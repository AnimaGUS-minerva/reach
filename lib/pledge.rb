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
    voucher = nil

    return [false,nil] unless ct

    # XXX this is all wrong now.
    parameters = ct.parameters.first

    begin
      case [ct.main_type,ct.sub_type]
      when ['application','pkcs7-mime'], ['application','voucher-cms+json']
        @voucher_response_type = :pkcs7


        @smimetype = parameters['smime-type']
        if @smimetype == 'voucher'
          @responsetype = :pkcs7_voucher
          @pkcs7voucher = true
        end

        voucher = Chariwt::Voucher.from_pkcs7(bodystr, PledgeKeys.instance.vendor_ca)

      when ['application','voucher-cms+cbor']
        @voucher_response_type = :pkcs7
        voucher = Chariwt::Voucher.from_cms_cbor(bodystr, PledgeKeys.instance.vendor_ca)

      when ['application','voucher-cose+cbor']
        @voucher_response_type = :cbor
        @cose = true
        voucher = Chariwt::Voucher.from_cose_cbor(bodystr, PledgeKeys.instance.vendor_ca)

      when ['multipart','mixed']
        @voucher_response_type = :cbor
        @cose = true
        @boundary = parameters["boundary"]
        mailbody = Mail::Body.new(bodystr)
        mailbody.split!(@boundary)
        voucher = Chariwt::Voucher.from_cose_cbor(mailbody.parts[0],
                                                  mailbody.parts[1])
      else
        puts "Not valid voucher type"
        byebug
        puts "voucher: #{ct.main_type} / #{ct.sub_type}"
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

  # for the IDevID enrollment, must verify the manufacturer's certificate
  def security_options
    { :verify_mode => OpenSSL::SSL::VERIFY_PEER,
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
    @coap_handler ||=
      Net::HTTP.start(jrc_uri.host, jrc_uri.port,
                      security_options)
  end

  def jrc_uri
    @jrc_uri ||= URI::join(@jrc,"/.well-known/est/requestvoucher")
  end
  def csrattr_uri
    @csrattr_uri ||= URI::join(@jrc,"/.well-known/est/csrattributes")
  end
  def simpleenroll_uri
    @simpleenroll_uri ||= URI::join(@jrc,"/.well-known/est/simpleenroll")
  end

  def voucher_validate!(voucher)
    voucherPinnedName = voucher.try(:pinnedDomainCert).try(:subject).try(:to_s)
    voucherPinnedName ||= "unknown"
    puts "Voucher connects to #{voucherPinnedName}"
    puts "vs:   #{http_handler.peer_cert.subject.to_s}"

    unless http_handler.try(:peer_cert).try(:to_der)
      puts "No peer certificate returned"
      return false
    end

    if voucher.try(:pinnedDomainCert).try(:to_der) == http_handler.try(:peer_cert).try(:to_der)
      puts "Voucher authenticates this connection!"
      return true
    else
      puts "Something went wrong, and voucher does not provide correct info"
      return false
    end
  end

  def enroll(saveto = nil)
    request = Net::HTTP::Get.new(csrattr_uri)
    response = http_handler.request request # Net::HTTPResponse object

    unless Net::HTTPSuccess === response
      case response
      when Net::HTTPBadRequest, Net::HTTPNotFound
        puts "EST Enroll from JRC is bad: #{response.to_s} #{response.code}"

      else
        puts "Other: #{response}"
      end
      return
    end

    ct = response['Content-Type']
    puts "Registrar returned CSR of type #{ct}"
    if saveto
      File.open("tmp/csrattr.der", "wb") do |f|
        f.puts response.body
      end
    end

    ca = CSRAttributes.from_der(response.body)
    san = ca.find_subjectAltName

    # correct name is in san[0].value[0].value[0].value
    unless san[0] and san[0].value[0] and san[0].value[0].value[0]
      puts "Can not find subjectAltName!"
      return
    end
    rfc822name = san[0].value[0].value[0].value
    puts "new device gets rfc822Name: #{rfc822name}"

    csr = build_csr(rfc822name)
    if saveto
      File.open("tmp/csr.der", "w") do |f|
        f.syswrite csr.to_der
      end
    end

    request = Net::HTTP::Post.new(simpleenroll_uri)
    request.body         = csr.to_der
    request.content_type = 'application/pkcs10'
    response = http_handler.request request # Net::HTTPResponse object

    unless Net::HTTPSuccess === response
      case response
      when Net::HTTPBadRequest, Net::HTTPNotFound
        puts "EST /simpleenroll from JRC is bad: #{response.to_s} #{response.code}"

      else
        puts "Other: #{response}"
      end
      return
    end
    ct = response['Content-Type']
    puts "Registrar returned certificate of type #{ct}"
    File.open("tmp/certificate.der", "w") do |f|
      f.syswrite response.body
    end
  end

  def rfc822NameChoice
    1
  end
  def rfc822NameAttr(rfc822name)
    v = OpenSSL::ASN1::UTF8String.new(rfc822name, rfc822NameChoice, :EXPLICIT, :CONTEXT_SPECIFIC)
    OpenSSL::X509::Attribute.new("subjectAltName", #OpenSSL::ASN1::ObjectId.new("subjectAltName"),
                                 OpenSSL::ASN1::Set.new([OpenSSL::ASN1::Sequence.new([v])]))
  end

  def build_csr(rfc822name)
    # form a Certificate Signing Request with the required rfc822name.
    csr = OpenSSL::X509::Request.new
    csr.version = 0
    csr.subject = OpenSSL::X509::Name.new([["serialNumber", PledgeKeys.instance.hunt_for_serial_number, 12]])
    csr.public_key = PledgeKeys.instance.idevid_cert.public_key
    csr.add_attribute rfc822NameAttr(rfc822name)
    csr.sign PledgeKeys.instance.idevid_privkey, OpenSSL::Digest::SHA256.new
    csr
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
    request.content_type = 'application/voucher-cms+json'
    response = http_handler.request request # Net::HTTPResponse object

    voucher = nil
    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      puts "Voucher JRC is bad: #{response.to_s} #{response.code}"

    when Net::HTTPSuccess
      ct = response['Content-Type']
      puts "MASA/JRC provided voucher of type #{ct}"
      if saveto
        File.open("tmp/voucher_#{vr.serialNumber}.pkcs", "w") do |f|
          f.syswrite response.body.b
        end
      end
      voucher = process_content_type(ct, response.body)

    when Net::HTTPRedirection
      byebug
    end
    voucher
  end

  def get_voucher_with_unsigned(saveto = nil)
    request = Net::HTTP::Post.new(jrc_uri)

    # this needs to set the SSL client certificate somewhere.

    vr = Chariwt::VoucherRequest.new
    vr.generate_nonce
    vr.assertion    = :proximity
    vr.signing_cert = PledgeKeys.instance.idevid_pubkey
    vr.serialNumber = vr.eui64_from_cert
    vr.createdOn    = Time.now
    vr.proximityRegistrarCert = http_handler.peer_cert
    smime = vr.unsigned!

    if saveto
      File.open("tmp/vr_#{vr.serialNumber}.json", "w") do |f|
        f.write smime
      end
    end

    request.body = smime
    request.content_type = 'application/json'
    response = http_handler.request request # Net::HTTPResponse object

    voucher = nil
    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      raise VoucherRequest::BadMASA

    when Net::HTTPSuccess
      ct = response['Content-Type']
      puts "MASA provided voucher of type #{ct}"
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

    # set block size bigger.
    client.max_payload = 1024

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
    end
    voucher
  end

  def get_constrained_enroll(saveto = nil)

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

    @cacerts_uri = jrc_uri.merge(links.uri)
    @cacerts_uri.path += "/crts"

    # set block size bigger.
    #client.max_payload = 1024

    result = client.get(@cacerts_uri)

    byebug

    @sen_uri = jrc_uri.merge(links.uri)
    @sen_uri.path += "/sen"

    # now build a CSR request.
    csr = OpenSSL::X509::Request.new
    #csr.

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
