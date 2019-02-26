require 'pledge_keys'
require 'pledge'
require 'net/http'

require 'rails_helper'

RSpec.describe SmartPledge do

  describe "creating self-signed certificate" do
    def tmp_pledge_dir
      newdir = Rails.root.join("tmp").join("pledge1")
      FileUtils.remove_entry_secure(newdir) if Dir.exists?(newdir)
      FileUtils.mkdir_p(newdir)
      newdir
    end

    it "should create a new cert if needed" do
      sp = SmartPledge.new
      pdir = tmp_pledge_dir

      sp.generate_selfidevid(pdir)
      expect(File.exists?(PledgeKeys.instance.pub_file))
    end
  end

end
