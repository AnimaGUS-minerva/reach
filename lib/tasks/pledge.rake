# -*- ruby -*-

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



  end

end
