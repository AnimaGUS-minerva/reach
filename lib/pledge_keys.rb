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

  attr_accessor :productid, :idevid, :dbroot

  def idevid_pubkey
    @idevid_pubkey  ||= load_idevid_pub_key
  end

  def idevid_privkey
    @idevid_privkey ||= load_idevid_priv_key
  end

  def masa_cert
    @masa_cert ||= load_masa_pub_cert
  end

  def jrc_key
    @jrc_key  ||= load_jrc_pub_key
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
    @product_dir ||= dbroot.join(x)
    @priv_file = @product_dir.join('key.pem')
    @pub_file  = @product_dir.join('device.crt')
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

  def idevid
    @idevid ||= "pledge"
  end

  def dbroot
    @dbroot || Pathname.new("")
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

  def load_masa_pub_cert
    File.open(pub_dir.join("masa_#{curve}.crt"),'r') do |f|
      OpenSSL::X509::Certificate.new(f)
    end
  end


end
