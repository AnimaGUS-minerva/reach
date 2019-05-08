# -*- ruby -*-

require 'smarkaklink'

namespace :reach do

  def setup_env
    @idevid     = ENV['IDEVID']
    @productid  = ENV['PRODUCTID']
    @saveto     = ENV['SAVETO']

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
    setup_env

    dppfile = ENV['DPPFILE']
    dpp = DPPCode.new(IO::read(dppfile))

    sk = Smarkaklink.new
    sk.smarkaklink_enroll(dpp, @saveto)
  end

  desc "Enroll an LDevID with the manufacturer, save it to PRODUCTID=directory"
  task :sk0_dpp_manu_enroll => :environment do
    setup_env

    dppfile = ENV['DPPFILE']
    dpp = DPPCode.new(IO::read(dppfile))

    PledgeKeys.instance.product_id = ENV['PRODUCTID']

    sk = Smarkaklink.new
    # Enroll with the manufacturer only.
    sk.enroll_with_smarkaklink_manufacturer(dpp, @saveto)
  end

  desc "Request a Voucher-Request from SHG unit, use PRODUCTID=directory"
  task :sk1_rvr => :environment do
    setup_env

    dppfile = ENV['DPPFILE']
    dpp = DPPCode.new(IO::read(dppfile))

    PledgeKeys.instance.product_id = ENV['PRODUCTID']

    sk = Smarkaklink.new
    # Enroll with the manufacturer only.
    puts "Ensure that IPv6 LL #{dpp.ulanodename_iauthority} is alive"
    sk.fetch_voucher_request(dpp, ENV['SAVETO'])
  end

  desc "parse SMARKAKLINK/LLv6/QRKEYFILE and enroll"
  task :enroll => :environment do
    setup_env

    dpp = DPPCode.new()

    qrkeyfile = ENV['QRKEYFILE']
    dpp.key = OpenSSL::PKey::read(IO::read(qrkeyfile))

    dpp.llv6 = ENV['LLV6']
    dpp.smarkaklink = ENV['SMARKAKLINK']
    dpp.essid = 'ESSID'

    sk = Smarkaklink.new
    sk.smarkaklink_enroll(dpp, @saveto)
  end



end
