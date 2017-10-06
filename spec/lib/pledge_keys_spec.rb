require 'pledge_keys'
require 'net/http'

RSpec.describe PledgeKeys do

  describe "IDevID certificate" do
    it "should be a public key" do
      b = PledgeKeys.instance.idevid_pubkey
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

  def cmp_pkcs_file(smime, base)
    ofile = File.join("tmp", base + ".pkcs")
    otfile = File.join("tmp", base+ ".txt")

    File.open(ofile, "w") do |f|     f.puts smime      end

    system("bin/pkcs2json #{ofile} #{otfile}")
    cmd = "diff #{otfile} spec/files/#{base}.txt"
    puts cmd
    system(cmd)
  end

  describe "IDevID private key" do
    it "should be a kind of private key" do
      b = PledgeKeys.instance.idevid_privkey
      expect(b).to be_kind_of(OpenSSL::PKey::PKey)
    end

    it "should pkcs sign a voucher request" do
      vr = Chariwt::VoucherRequest.new
      vr.nonce = "Dss99sBr3pNMOACe-LYY7w"
      vr.assertion = :proximity
      vr.signing_cert = PledgeKeys.instance.idevid_pubkey
      vr.serialNumber = vr.eui64_from_cert
      vr.createdOn    = '2017-09-01'.to_date
      #vr.proximityRegistrarCert = get_cert_from_tls
      smime = vr.pkcs_sign(PledgeKeys.instance.idevid_privkey)

      cmp_pkcs_file(smime, "pledge_request01")
    end
  end

  describe "pledge enrollment" do
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

    it "should open a TLS connection to fountain" do

      jrc_uri = URI::join("https://fountain-test.sandelman.ca",
                          "/.well-known/est/requestvoucher")

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

      expect(voucher).to_not be_nil

    end
  end

  describe "MASA public key" do
    it "should be a kind of public key" do
      b = PledgeKeys.instance.masa_cert
      expect(b).to be_kind_of(OpenSSL::X509::Certificate)
    end
  end

end
