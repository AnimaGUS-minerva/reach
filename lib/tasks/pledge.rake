# -*- ruby -*-

require 'pledge'

namespace :reach do

  # generate a voucher request with the
  # proximity-registrar-cert filled in
  # and send it to the appropriate Registrar.
  desc "construct a (signed) voucher request IDEVID=xx/PRODUCTID=zz, send to JRC=yy"
  task :send_voucher_request => :environment do
    idevid     = ENV['IDEVID']
    productid  = ENV['PRODUCTID']
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

    voucher = client.get_voucher(true)

    unless voucher
      puts "no voucher returned"
      exit 10
    end

    puts "Voucher connects to #{voucher.pinnedDomainCert.subject.to_s}"
    puts "vs:   #{client.http_handler.peer_cert.subject.to_s}"
    if voucher.pinnedDomainCert.to_der == client.http_handler.peer_cert.to_der
      puts "Voucher authenticates this connection!"
    else
      puts "Something went wrong, and voucher does not provide correct info"
    end

    # Registrar is now authenticated!
  end


  # generate a CWT voucher request with the
  # proximity-registrar-public-key filled in
  # and send it to the connected Registrar.
  desc "construct an (unsigned) CWT voucher request from PRODUCTID=xx, send to JRC=yy"
  task :send_cwt_request => :environment do
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

    voucher = client.get_cwt_voucher(true)

    unless voucher
      puts "no voucher returned"
      exit 10
    end

    puts "Voucher connects to #{voucher.pinnedDomainCert.subject.to_s}"
    puts "vs:   #{client.http_handler.peer_cert.subject.to_s}"
    if voucher.pinnedDomainCert.to_der == client.http_handler.peer_cert.to_der
      puts "Voucher authenticates this connection!"
    else
      puts "Something went wrong, and voucher does not provide correct info"
    end

    # Registrar is now authenticated!

  end

end
