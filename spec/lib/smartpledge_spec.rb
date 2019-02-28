require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe SmartPledge do

  def mk_pledge_dir
    newdir = Rails.root.join("tmp").join("pledge1")
    FileUtils.remove_entry_secure(newdir) if Dir.exists?(newdir)
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
      sp = SmartPledge.new
      pdir = mk_pledge_dir

      sp.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))
    end

    it "should reuse the private key if already created" do
      sp = SmartPledge.new
      pdir = tmp_pledge_dir("spec/files/product/SmartPledge-1502449999")

      expect(File.exists?(PledgeKeys.instance.priv_file))
      orig = OpenSSL::Digest.digest("SHA256", IO::read(PledgeKeys.instance.priv_file))
      sp.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))

      newd = OpenSSL::Digest.digest("SHA256", IO::read(PledgeKeys.instance.priv_file))
      expect(newd).to eq(orig)
    end
  end

  def pledge9999
    pdir = tmp_pledge_dir("spec/files/product/SmartPledge-1502449999")
    PledgeKeys.instance.product_id = pdir
    PledgeKeys.instance
  end

  describe "posting self-signed certificate to smartpledge manufacturer" do
    it "should return an IDevID with the same public key" do
      pledge9999  # load files from this stored pledge
      sp = SmartPledge.new
      dpp = DPPCode.new(IO::read("spec/files/dpp1.txt"))
      newcert = sp.enroll_with_smartpledge_manufacturer(dpp)
      expect(newcert).to be_a(OpenSSL::X509::Certificate)
    end

    it "should calculate a hash to post to enrollment" do
      pledge9999
      sp = SmartPledge.new
      expect(sp.idevid_enroll_json).to match(/{\"cert\":.*}/)
    end
  end

end
