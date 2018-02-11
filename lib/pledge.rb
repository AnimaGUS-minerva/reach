require 'pledge_keys'
require 'net/http'
require 'openssl'

class Pledge
  attr_accessor :jrc, :jrc_uri

  def process_smime_type
    case @smimetype.downcase
    when 'voucher'
      @pkcs7voucher = true
      @voucher_response_type = :pkcs7
    end
  end

  def process_content_type_arguments(args)
    args.each { |param|
      param.strip!
      (thing,value) = param.split(/=/)
      case thing.downcase
      when 'smime-type'
        @smimetype = value.downcase
        process_smime_type
        @responsetype = :pkcs7_voucher
      end
    }
  end

  def process_content_type(value)
    things = value.split(/;/)
    majortype = things.shift
    return false unless majortype

    @apptype = majortype.downcase
    case @apptype
    when 'application/pkcs7-mime'
      @pkcs7 = true
      process_content_type_arguments(things)
      return true
    end
  end

  def decode_pem(base64stuff)
    begin
      der = Base64.urlsafe_decode64(base64stuff)
    rescue ArgumentError
      der = Base64.decode64(base64stuff)
    end
  end

  def http_handler
    @http_handler ||=
      Net::HTTP.start(jrc_uri.host, jrc_uri.port,
                      { :verify_mode => OpenSSL::SSL::VERIFY_NONE,
                        :use_ssl => jrc_uri.scheme == 'https'})
  end

  def get_voucher(saveto = nil)
    self.jrc_uri = URI::join(@jrc,"/.well-known/est/requestvoucher")

    request = Net::HTTP::Post.new(jrc_uri)

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
        f.puts smime
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
      if process_content_type(@content_type = response['Content-Type'])
        if saveto
          File.open("tmp/voucher_#{vr.serialNumber}.pkcs", "w") do |f|
            f.puts response.body
          end
        end

        der = decode_pem(response.body)

        voucher = Chariwt::Voucher.from_pkcs7(der, PledgeKeys.instance.vendor_ca)
      else
        nil
      end

    when Net::HTTPRedirection
      byebug
    end
    voucher
  end

  def get_cwt_voucher(saveto = nil)
    self.jrc_uri = URI::join(@jrc,"/.well-known/est/requestvoucher")

    client = CoAP::Client.new(host: jrc_uri.hostname, scheme: jrc_uri.scheme)
    client.logger.level = Logger::DEBUG
    client.logger.debug("STARTING")
    result = client.get('/.well-known/core?rt=ace.est')

    return true

    request = Net::HTTP::Post.new(jrc_uri)

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
        f.puts smime
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
      if process_content_type(@content_type = response['Content-Type'])
        if saveto
          File.open("tmp/voucher_#{vr.serialNumber}.pkcs", "w") do |f|
            f.puts response.body
          end
        end

        der = decode_pem(response.body)

        voucher = Chariwt::Voucher.from_pkcs7(der, PledgeKeys.instance.vendor_ca)
      else
        nil
      end

    when Net::HTTPRedirection
      byebug
    end
    voucher
  end
end
