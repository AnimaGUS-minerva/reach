require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe Smarkaklink do

  before(:all) do
    newdir = Rails.root.join("tmp").join("pledge1")
    FileUtils.remove_entry_secure(newdir, true) if Dir.exists?(newdir)
  end

  before(:each) do |x|
    #puts "B4: #{x.description}"
    #system("sha256sum spec/files/product/00-D0-E5-F2-00-01/device.crt")
    PledgeKeys.instance = nil
    PledgeKeys.instance.product_id = "spec/files/product/00-D0-E5-F2-00-01"
  end

  def mk_pledge_dir
    newdir = Rails.root.join("tmp").join("pledge1")
    FileUtils.remove_entry_secure(newdir, true) if Dir.exists?(newdir)
    FileUtils.mkdir_p(newdir)
    PledgeKeys.instance = nil
    PledgeKeys.instance.product_id = newdir
    newdir
  end

  def tmp_pledge_dir(srcdir)
    ndir = mk_pledge_dir
    system("cp -r #{srcdir}/. #{ndir}/.")
    ndir
  end

  describe "creating self-signed certificate" do
    it "should create a new cert if needed" do
      pdir = mk_pledge_dir

      Smarkaklink.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))
    end

    it "should reuse the private key if already created" do
      pdir=tmp_pledge_dir("spec/files/product/Smarkaklink-1502449999")

      expect(File.exists?(PledgeKeys.instance.priv_file)).to be true
      orig = OpenSSL::Digest.digest("SHA256", IO::read(PledgeKeys.instance.priv_file))
      Smarkaklink.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file)).to be true

      newd = OpenSSL::Digest.digest("SHA256", IO::read(PledgeKeys.instance.priv_file))
      expect(newd).to eq(orig)
    end
  end

  def pledge9999
    pdir = tmp_pledge_dir("spec/files/product/Smarkaklink-1502449999")
    yield PledgeKeys.instance
    FileUtils.remove_entry_secure(pdir, true)
  end

  describe "posting self-signed certificate to smarkaklink manufacturer" do
    it "should return an IDevID with the same public key" do
      # load files from this stored pledge
      pledge9999 { |pk|
        sp = Smarkaklink.new
        dpp = DPPCode.new(IO::read("spec/files/dpp1.txt"))

        # WebMock.allow_net_connect!

        pk.testing_capath = "spec/files/product/Smarkaklink-1502449999/vendor_secp384r1.crt"

        result = IO.binread("spec/files/dpp1_certificate.der")
        enroll_request = nil
        @time_now = Time.at(1507671037)  # Oct 10 17:30:44 EDT 2017

        allow(Time).to receive(:now).and_return(@time_now)
        stub_request(:post, "https://highway-test.example.com:9443/.well-known/brski/smarkaklink").
          with(headers:
                 {'Accept'=>'application/pkcs7',
                  'Accept-Encoding'=>'gzip;q=1.0,deflate;q=0.6,identity;q=0.3',
                  'Content-Type'=>'application/json',
                  'Host'=>'highway-test.example.com:9443',
                  'User-Agent'=>'Ruby'
                 }).
          to_return(status: 200, body: lambda { |request|
                      enroll_request = request
                      result},
                    headers: {
                      'Content-Type'=>'application/pkcs7'
                    })

        newcert = sp.enroll_with_smarkaklink_manufacturer(dpp)
        expect(newcert).to be_a(OpenSSL::X509::Certificate)
      }
    end

    it "should calculate a hash to post to enrollment" do
      pledge9999 { |pk|
        sp = Smarkaklink.new
        File.open("tmp/enroll1.json", "w") { |f|
          f.write sp.idevid_enroll_json
        }
        expect(sp.idevid_enroll_json).to match(/{\"cert\":.*}/)
      }
    end
  end

  describe "request voucher-request" do
    it "should generate a nonce, and encrypt it to AR DPP key" do
      # XXX nonce probably needs to be deterministic for testing
      nonce = SecureRandom.base64(16)
      dc = DPPCode.new(IO::read("spec/files/dpp1.txt"))
      ek = dc.ecdsa_key

      ec = OpenSSL::PKey::EC::IES.new(dc.key, "algorithm")
      encrypted = ec.public_encrypt(nonce)

      encoded = Base64::urlsafe_encode64(encrypted)
      File.open("tmp/smarkaklink_req-challenge-01.b64", "w") do |f|
        f.syswrite encoded
      end

      blob = { "voucher-request-challenge" => encoded }.to_json
      expect(blob).to_not be_nil

      # verify a voucher-requests produced by the AR which has this blob in it.
      #sk = Smarkaklink.new
      #sk.testing_capath = "spec/files/product/Smarkaklink-1502449999/vendor_secp384r1.crt"
    end
  end

  describe "SPnonce encryption" do
    it "should encrypt a nonce and then decrypt it" do
      nonce = "abcd1234"
      pub  = OpenSSL::X509::Certificate.new(IO::read("spec/files/jrc/router-01/jrc_prime256v1.crt"))
      priv = OpenSSL::PKey.read(IO::read("spec/files/jrc/router-01/jrc_prime256v1.key"))

      ec   = OpenSSL::PKey::EC::IES.new(pub.public_key, "algorithm")
      encrypted = ec.public_encrypt(nonce)
      expect(encrypted).to_not be_nil

      File.open("tmp/router01nonce.b64", "w") do |f|
        f.syswrite Base64.urlsafe_encode64(encrypted)
      end

      ec2   = OpenSSL::PKey::EC::IES.new(priv, "algorithm")
      nn    = ec2.private_decrypt(encrypted)
      expect(nn).to eq(nonce)
    end
  end

end
