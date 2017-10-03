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

  attr_accessor :idevid, :dbroot

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

  def priv_dir
    @privkey_dir ||= dbroot.join('db').join('private')
  end

  def pub_dir
    @pubkey_dir ||= dbroot.join('db').join('cert')
  end

  def idevid
    @idevid ||= "pledge"
  end

  def dbroot
    @dbroot || Pathname.new("")
  end

  protected
  def load_idevid_pub_key
    pubkey_file = File.open(pub_dir.join("#{idevid}_#{client_curve}.crt"),'r')
    OpenSSL::X509::Certificate.new(pubkey_file)
  end

  def load_idevid_priv_key
    privkey_file=File.open(priv_dir.join("#{idevid}_#{client_curve}.key"))
    OpenSSL::PKey.read(privkey_file)
  end

  def load_masa_pub_cert
    File.open(pub_dir.join("masa_#{curve}.crt"),'r') do |f|
      OpenSSL::X509::Certificate.new(f)
    end
  end


end
