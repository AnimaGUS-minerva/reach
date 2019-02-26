require 'singleton'
require 'byebug'
require 'chariwt'

class SmartPledge < Pledge

  # this initializes the system with a self-signed IDevID.
  def generate_selfidevid(dir = "db/smartpledge")
    pi = PledgeKeys.instance
    pi.product_id = dir if dir

    curve = pi.curve

    if File.exists?(pi.priv_file)
      puts "CA using existing key at: #{pi.priv_file}" unless Rails.env.test?
      self_key = OpenSSL::PKey.read(File.open(pi.priv_file))
    else
      # the CA's public/private key - 3*1024 + 8
      self_key = OpenSSL::PKey::EC.new(curve)
      self_key.generate_key
      File.open(pi.priv_file, "w", 0600) do |f| f.write self_key.to_pem end
    end

    self_crt  = OpenSSL::X509::Certificate.new
    # cf. RFC 5280 - to make it a "v3" certificate
    self_crt.version = 2
    serialno=SystemVariable.randomseq(:serialnumber)
    self_crt.serial  = serialno
    dn = sprintf("/C=Canada/OU=SmartPledge-%d", serialno)
    self_crt.subject = OpenSSL::X509::Name.parse dn

    # this is self-signed certificate
    self_crt.issuer = self_crt.subject
    self_crt.public_key = self_key
    self_crt.not_before = Time.now

    # 2 years validity
    self_crt.not_after = self_crt.not_before + 2 * 365 * 24 * 60 * 60

    # Extension Factory -- no extensions needed
    self_crt.sign(self_key, OpenSSL::Digest::SHA256.new)

    File.open(pi.pub_file, 'w') do |f|
      f.write self_crt.to_pem
    end
    puts "Self-Signed Certificate writtten to: #{pi.pub_file}" unless Rails.env.test?

  end

end
