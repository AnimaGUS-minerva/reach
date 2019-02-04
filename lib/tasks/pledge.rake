# -*- ruby -*-

require 'pledge'

namespace :reach do

  def setup_voucher_request
    @idevid     = ENV['IDEVID']
    @productid  = ENV['PRODUCTID']
    @jrcurl  = ENV['JRC']

    if (!@idevid and !@productid)
      puts "Must set IDEVID=xx or PRODUCTID=zz"
      exit
    end

    unless @jrcurl
      puts "Must Set JRC=url"
      exit
    end

    if @productid
      PledgeKeys.instance.product_id = @productid
    else
      PledgeKeys.instance.idevid = @idevid
    end
  end


  # generate an unsigned voucher request
  desc "construct a unsigned voucher request IDEVID=xx/PRODUCTID=zz, send to JRC=yy"
  task :send_unsigned_voucher_request => :environment do
    setup_voucher_request

    client = Pledge.new
    client.jrc = @jrcurl

    voucher = client.get_voucher_with_unsigned(true)

    unless voucher
      puts "no voucher returned"
      exit 10
    end

    client.voucher_validate!(voucher)

    # Registrar is now authenticated!
  end

  # generate a voucher request with the
  # proximity-registrar-cert filled in
  # and send it to the appropriate Registrar.
  desc "enroll using HTTP to with IDEVID=xx/PRODUCTID=zz, send to JRC=yy"
  task :enroll_http_pledge => :environment do
    setup_voucher_request

    client = Pledge.new
    client.jrc = @jrcurl

    voucher = client.get_voucher(true)
    # now enroll using /simpleenroll

    client.voucher_validate!(voucher)
    client.enroll(true)
  end

  # generate a voucher request with the
  # proximity-registrar-cert filled in
  # and send it to the appropriate Registrar.
  desc "construct a (signed) voucher request IDEVID=xx/PRODUCTID=zz, send to JRC=yy"
  task :send_voucher_request => :environment do
    setup_voucher_request

    client = Pledge.new
    client.jrc = @jrcurl

    voucher = client.get_voucher(true)

    unless voucher
      puts "no voucher returned"
      exit 10
    end

    client.voucher_validate!(voucher)
    # Registrar is now authenticated!
  end


  # generate a CWT voucher request with the
  # proximity-registrar-public-key filled in
  # and send it to the connected Registrar.
  desc "construct an (unsigned) CWT voucher request from PRODUCTID=xx, send to JRC=yy"
  task :send_constrained_request => :environment do
    productid  = ENV['PRODUCTID']
    idevid  = ENV['IDEVID']
    jrcurl  = ENV['JRC']

    if (!idevid and !productid)
      puts "Must set IDEVID=xx or PRODUCTID=zz"
      exit
    end

    unless jrcurl
      puts "Must Set JRC=url"
      exit
    end

    if productid
      PledgeKeys.instance.product_id = productid
    else
      PledgeKeys.instance.idevid = idevid
    end

    client = Pledge.new
    client.jrc = jrcurl

    voucher = client.get_constrained_voucher(true)

    unless voucher
      puts "no voucher returned"
      exit 10
    end

    client.voucher_validate!(voucher)
  end

end
