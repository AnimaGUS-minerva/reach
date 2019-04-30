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

    sk = Smarkaklink.new
    sk.smarkaklink_enroll(dpp, ENV['SAVETO'])
  end

  desc "parse SMARKAKLINK/LLv6/QRKEYFILE and enroll"
  task :enroll => :environment do
    dpp = DPPCode.new()

    qrkeyfile = ENV['QRKEYFILE']
    dpp.key = OpenSSL::PKey::read(IO::read(qrkeyfile))

    dpp.llv6 = ENV['LLV6']
    dpp.smarkaklink = ENV['SMARKAKLINK']
    dpp.essid = 'ESSID'

    sk = Smarkaklink.new
    sk.smarkaklink_enroll(dpp, ENV['SAVETO'])
  end



end
