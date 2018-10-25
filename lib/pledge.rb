require 'pledge_keys'
require 'net/http'
require 'openssl'

URI::Generic.class_eval do
  def request_uri
    return nil unless @path
    if @path.start_with?(?/.freeze)
      @query ? "#@path?#@query" : @path.dup
    else
      @query ? "/#@path?#@query" : "/#@path"
    end
  end
end

class Pledge
  attr_accessor :jrc, :jrc_uri

  def process_content_type(type, bodystr)
    ct = Mail::Parsers::ContentTypeParser.parse(type)

    return [false,nil] unless ct

    # XXX this is all wrong now.
    parameters = ct.parameters.first

    begin
      case [ct.main_type,ct.sub_type]
      when ['application','pkcs7-mime'], ['application','cms']
        @voucher_response_type = :pkcs7


        @smimetype = parameters['smime-type']
        if @smimetype == 'voucher'
          @responsetype = :pkcs7_voucher
          @pkcs7voucher = true
        end

        der = decode_pem(bodystr)
        voucher = ::CmsVoucher.from_voucher(@voucher_response_type, der)

      when ['application','voucher-cms+cbor']
        @voucher_response_type = :pkcs7
        voucher = ::CoseVoucher.from_voucher(@voucher_response_type, bodystr)

      when ['application','voucher-cose+cbor']
        @voucher_response_type = :cbor
        @cose = true
        voucher = ::CoseVoucher.from_voucher(@voucher_response_type, bodystr)

      when ['multipart','mixed']
        @voucher_response_type = :cbor
        @cose = true
        @boundary = parameters["boundary"]
        mailbody = Mail::Body.new(bodystr)
        mailbody.split!(@boundary)
        voucher = Voucher.from_parts(mailbody.parts)
      else
        byebug
      end

    rescue Chariwt::Voucher::MissingPublicKey => e
      self.status = { :failed       => e.message,
                      :voucher_type => ct.to_s,
                      :parameters   => parameters,
                      :encoded_voucher => Base64::urlsafe_encode64(bodystr),
                      :masa_url     => masa_uri.to_s }
      return nil
    end

    return voucher
  end

  def process_constrained_content_type(type, bodystr)
    begin
      case type
      when 65502
        @voucher_response_type = :cbor
        @cose = true
        voucher = Chariwt::Voucher.from_cbor_cose(bodystr, PledgeKeys.instance.masa_cert)
      end

    rescue Chariwt::Voucher::MissingPublicKey => e
      return { :failed       => e.message,
               :voucher_type => type,
               :parameters   => parameters,
               :encoded_voucher => Base64::urlsafe_encode64(bodystr)
      }
    end

    return voucher
  end

  def decode_pem(base64stuff)
    begin
      der = Base64.urlsafe_decode64(base64stuff)
    rescue ArgumentError
      der = Base64.decode64(base64stuff)
    end
  end

  def security_options
    { :verify_mode => OpenSSL::SSL::VERIFY_NONE,
      :use_ssl => jrc_uri.scheme == 'https',
      :cert    => PledgeKeys.instance.idevid_pubkey,
      :key     => PledgeKeys.instance.idevid_privkey
    }
  end

  def http_handler
    @http_handler ||=
      Net::HTTP.start(jrc_uri.host, jrc_uri.port,
                      security_options)
  end

  def coap_handler
    @http_handler ||=
      Net::HTTP.start(jrc_uri.host, jrc_uri.port,
                      security_options)
  end

  def jrc_uri
    @jrc_uri ||= URI::join(@jrc,"/.well-known/est/requestvoucher")
  end

  def get_voucher(saveto = nil)
    request = Net::HTTP::Post.new(jrc_uri)

    # this needs to set the SSL client certificate somewhere.

    vr = Chariwt::VoucherRequest.new
    vr.generate_nonce
    vr.assertion    = :proximity
    vr.signing_cert = PledgeKeys.instance.idevid_pubkey
    vr.serialNumber = vr.eui64_from_cert
    vr.createdOn    = Time.now
    vr.proximityRegistrarCert = http_handler.peer_cert
    smime = vr.pkcs_sign(PledgeKeys.instance.idevid_privkey)

    if saveto
      File.open("tmp/vr_#{vr.serialNumber}.pkcs", "w") do |f|
        f.write smime
      end
    end

    request.body = smime
    request.content_type = 'application/pkcs7-mime; smime-type=voucher-request'
    response = http_handler.request request # Net::HTTPResponse object

    voucher = nil
    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      raise VoucherRequest::BadMASA

    when Net::HTTPSuccess
      ct = response['Content-Type']
      logger.info "MASA provided voucher of type #{ct}"
      voucher = process_content_type(ct, response.body)
      if voucher
        if saveto
          File.open("tmp/voucher_#{vr.serialNumber}.pkcs", "w") do |f|
            f.puts response.body
          end
        end
      else
        nil
      end

    when Net::HTTPRedirection
      byebug
    end
    voucher
  end

  def get_constrained_voucher(saveto = nil)

    client = CoAP::Client.new(host: jrc_uri.hostname, scheme: jrc_uri.scheme)
    client.client_cert = PledgeKeys.instance.idevid_pubkey
    client.client_key  = PledgeKeys.instance.idevid_privkey
    client.logger.level = Logger::DEBUG
    client.logger.debug("STARTING")
    client.client_cert = PledgeKeys.instance.idevid_pubkey

    CoRE::CoAP::Transmission.client_debug=true

    result = client.get('/.well-known/core?rt=ace.est')

    links = CoRE::Link.parse(result.payload)

    print "Ready?  "
    ans = STDIN.gets
    puts "proceeding..."

    @rv_uri = jrc_uri.merge(links.uri)
    @rv_uri.path += "/rv"

    vr = Chariwt::VoucherRequest.new(:format => :cose_cbor)
    vr.generate_nonce
    vr.assertion    = :proximity
    vr.signing_cert = PledgeKeys.instance.idevid_pubkey
    vr.serialNumber = vr.eui64_from_cert
    vr.createdOn    = Time.now
    vr.proximityRegistrarCert = client.peer_cert
    cose = vr.cose_sign(PledgeKeys.instance.idevid_privkey)

    if saveto
      File.open("tmp/vr_#{vr.serialNumber}.vrq", "wb") do |f|
        f.write cose
      end
    end

    # host=nil, port=nil to get preset values above.
    # payload = cose
    # then options...
    response = client.post(@rv_uri, nil, nil, cose,
                           {:content_format => 'application/cose; cose-type="cose-sign"'})

    voucher = nil
    case
    when response.mcode[0] == 5
      raise VoucherRequest::BadMASA

    when response.mcode == [2,5]
      ct = response.options[:content_format]
      puts "MASA provided voucher of type #{ct}"
      voucher = process_constrained_content_type(ct, response.payload)
      if voucher
        if saveto
          File.open("tmp/voucher_#{voucher.serialNumber}.vch", "wb") do |f|
            f.puts response.payload
          end
        end
      else
        nil
      end

    when Net::HTTPRedirection
      byebug
    end
    voucher
  end
end
