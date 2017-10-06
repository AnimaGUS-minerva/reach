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

    voucher = client.get_voucher
  end

end
