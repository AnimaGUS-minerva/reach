require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe Smarkaklink do

  before(:all) do
    newdir = Rails.root.join("tmp").join("pledge1")
    FileUtils.remove_entry_secure(newdir, true) if Dir.exists?(newdir)
  end

  def mk_pledge_dir
    newdir = Rails.root.join("tmp").join("pledge1")
    FileUtils.remove_entry_secure(newdir, true) if Dir.exists?(newdir)
    FileUtils.mkdir_p(newdir)
    newdir
  end

  def tmp_pledge_dir(srcdir)
    ndir = mk_pledge_dir
    system("cp -r #{srcdir}/. #{ndir}/.")
    ndir
  end

  describe "creating self-signed certificate" do
    it "should create a new cert if needed" do
      sp = Smarkaklink.new
      pdir = mk_pledge_dir

      sp.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))
    end

    it "should reuse the private key if already created" do
      sp = Smarkaklink.new
      pdir = tmp_pledge_dir("spec/files/product/Smarkaklink-1502449999")

      expect(File.exists?(PledgeKeys.instance.priv_file))
      orig = OpenSSL::Digest.digest("SHA256", IO::read(PledgeKeys.instance.priv_file))
      sp.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))

      newd = OpenSSL::Digest.digest("SHA256", IO::read(PledgeKeys.instance.priv_file))
      expect(newd).to eq(orig)
    end
  end

  def pledge9999
    pdir = tmp_pledge_dir("spec/files/product/Smarkaklink-1502449999")
    PledgeKeys.instance.product_id = pdir
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

        result = IO.read("spec/files/dpp1_certificate.der")
        enroll_request = nil
        @time_now = Time.at(1507671037)  # Oct 10 17:30:44 EDT 2017

        allow(Time).to receive(:now).and_return(@time_now)
        stub_request(:post, "https://highway-test.example.com:9443/.well-known/est/smarkaklink").
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

end
