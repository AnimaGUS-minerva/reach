# -*- ruby -*-

require 'smarkaklink'

namespace :reach do

  def setup_env
    @idevid     = ENV['IDEVID']
    @productid  = ENV['PRODUCTID']

    if (!@idevid and !@productid)
      Smarkaklink.generate_selfidevid 
    end

    if @productid
      PledgeKeys.instance.product_id = @productid
    else
      PledgeKeys.instance.idevid = @idevid
    end
  end

  desc "parse DPPFILE=file and enroll"
  task :parse_dpp_enroll => :environment do
    dppfile = ENV['DPPFILE']
    dpp = DPPCode.new(IO::read(dppfile))

    sk = SmartPledge.new
    sk.smarkaklink_enroll(dpp)

    # Registrar is now authenticated!
  end



end
