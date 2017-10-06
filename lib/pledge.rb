require 'pledge_keys'
require 'net/http'

class Pledge
  attr_accessor :jrc

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

  def get_voucher
    jrc_uri = URI::join(@jrc,"/.well-known/est/requestvoucher")

    http_handler =
      Net::HTTP.start(jrc_uri.host, jrc_uri.port,
                      { :verify_mode => OpenSSL::SSL::VERIFY_NONE,
                        :use_ssl => jrc_uri.scheme == 'https'})

    request = Net::HTTP::Post.new(jrc_uri)

    vr = Chariwt::VoucherRequest.new
    vr.nonce        = "Dss99sBr3pNMOACe-LYY7w"
    vr.assertion    = :proximity
    vr.signing_cert = PledgeKeys.instance.idevid_pubkey
    vr.serialNumber = vr.eui64_from_cert
    vr.createdOn    = '2017-09-01'.to_date
    smime = vr.pkcs_sign(PledgeKeys.instance.idevid_privkey)

    request.body = smime
    request.content_type = 'application/pkcs7-mime; smime-type=voucher-request'
    response = http_handler.request request # Net::HTTPResponse object

    voucher = nil
    case response
    when Net::HTTPBadRequest, Net::HTTPNotFound
      raise VoucherRequest::BadMASA

    when Net::HTTPSuccess
      if process_content_type(@content_type = response['Content-Type'])
        der = decode_pem(response.body)
        voucher = Chariwt::Voucher.from_pkcs7(der)


      else
        nil
      end

    when Net::HTTPRedirection
      byebug
    end
    voucher
  end
end
