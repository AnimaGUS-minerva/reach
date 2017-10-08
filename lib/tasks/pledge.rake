# -*- ruby -*-

require 'pledge'

namespace :reach do

  # generate a voucher request with the pinned-domain-cert filled in
  # and send it to the appropriate Registrar.
  desc "construct a (signed) voucher request IDEVID=xx, send to JRC=yy"
  task :send_voucher_request => :environment do
    idevid  = ENV['IDEVID']
    jrcurl  = ENV['JRC']

    unless idevid
      puts "Must set IDEVID=xx"
      exit
    end

    unless jrcurl
      puts "Must Set JRC=url"
      exit
    end

    client = Pledge.new
    client.jrc = jrcurl

    voucher = client.get_voucher(true)

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
