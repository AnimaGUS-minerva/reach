require 'singleton'
require 'byebug'
require 'chariwt'

#
# this class is a singleton class that provides access to the
# public and private keys of a pledge, along with the anchor
# to the MASA
#
class PledgeKeys
  include Singleton

  attr_accessor :productid, :product_dir, :idevid, :dbroot, :testing_capath

  def idevid_pubkey
    @idevid_pubkey  ||= load_idevid_pub_key
  end
  alias :idevid_cert :idevid_pubkey

  def idevid_privkey
    @idevid_privkey ||= load_idevid_priv_key
  end

  def ldevid_pubkey
    @ldevid_pubkey  ||= load_ldevid_pub_key
  end

  def ldevid_privkey
    @ldevid_privkey ||= load_ldevid_priv_key
  end

  def masa_cert
    @masa_cert ||= load_masa_pub_cert
  end

  def vendor_ca
    @vendor_ca ||= load_vendor_pub_cert
  end

  def curve
    # wish we could use X25519!
    'secp384r1'
  end
  def client_curve
    # wish we could use X25519!
    'prime256v1'
  end

  # when setting the productID, then set up an alternate directory for
  # public and private key files
  def product_id=(x)
    @product_id  = x
    @product_dir ||= dbroot.join(x)
    FileUtils::mkdir_p(product_dir.to_s)
    @priv_file = @product_dir.join('key.pem')
    @pub_file  = @product_dir.join('device.crt')
    @lpriv_file     = @product_dir.join('key.pem')  # same private key
    @lpub_file      = @product_dir.join('ldevice.crt')
    @masa_file      = @product_dir.join('masa.crt')
    @vendorca_file  = @product_dir.join('vendor.crt')
  end

  def priv_dir
    @privkey_dir ||= dbroot.join('db').join('private')
  end

  def pub_dir
    @pubkey_dir ||= dbroot.join('db').join('cert')
  end

  def priv_file
    @priv_file ||= priv_dir.join("#{idevid}_#{client_curve}.key")
  end
  def pub_file
    @pub_file  ||= pub_dir.join("#{idevid}_#{client_curve}.crt")
  end

  def lpriv_file
    @lpriv_file ||= priv_dir.join("#{ldevid}_#{client_curve}.key")
  end
  def lpub_file
    @lpub_file  ||= pub_dir.join("#{ldevid}_#{client_curve}.crt")
  end

  def masa_file
    @masa_file ||= pub_dir.join("masa_#{curve}.crt")
  end

  # the base of name of the certificate
  def idevid
    @idevid ||= "pledge"
  end

  def ldevid
    @ldevid ||= "lpledge"
  end

  # copied from fountain/app/models/voucher_request.rb
  def hunt_for_serial_number
    attrs = Hash.new
    serial_number = nil
    idevid_cert.subject.to_a.each {|attr|
      # might want to look at attr[2] for type info.
      attrs[attr[0]] = attr[1]
    }

    # look through in priority order
    return serial_number if serial_number=attrs['serialNumber']
    return serial_number if serial_number=attrs['CN']
    return nil
  end

  def dbroot
    @dbroot || Pathname.new("")
  end
  def masa_pub_file
    @masa_file ||= pub_dir.join("masa_#{curve}.crt")
  end
  def vendor_pub_file
    @vendorca_file ||= pub_dir.join("vendor.crt")
  end

  protected
  def load_idevid_pub_key
    pubkey_file = File.open(pub_file,'r')
    OpenSSL::X509::Certificate.new(pubkey_file)
  end

  def load_idevid_priv_key
    privkey_file=File.open(priv_file)
    OpenSSL::PKey.read(privkey_file)
  end

  def load_ldevid_pub_key
    lpubkey_file = File.open(lpub_file,'r')
    OpenSSL::X509::Certificate.new(lpubkey_file)
  end

  def load_ldevid_priv_key
    if File.exists?(lpriv_file)
      lprivkey_file = File.open(lpriv_file)
    else
      lprivkey_file = File.open(priv_file)
    end
    OpenSSL::PKey.read(lprivkey_file)
  end

  def load_masa_pub_cert
    File.open(masa_pub_file,'r') do |f|
      OpenSSL::X509::Certificate.new(f)
    end
  end

  def load_vendor_pub_cert
    File.open(vendor_pub_file,'r') do |f|
      OpenSSL::X509::Certificate.new(f)
    end
  end


end
