require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe SmartPledge do

  describe "creating self-signed certificate" do
    def mk_pledge_dir
      newdir = Rails.root.join("tmp").join("pledge1")
      FileUtils.remove_entry_secure(newdir) if Dir.exists?(newdir)
      FileUtils.mkdir_p(newdir)
      newdir
    end

    it "should create a new cert if needed" do
      sp = SmartPledge.new
      pdir = mk_pledge_dir

      sp.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))
    end

    def tmp_pledge_dir(srcdir)
      ndir = mk_pledge_dir
      system("cp -r #{srcdir}/. #{ndir}/.")
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

end
