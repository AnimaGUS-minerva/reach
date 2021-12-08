class DPPCode
  attr_accessor :key, :keybinary, :mac, :smarkaklink, :llv6, :essid
  attr_accessor :dpphash
  attr_accessor :dppcode

  class DPPKeyError < Exception; end

  def initialize(str = nil)
    if str
      self.dppcode = str
      parse_dpp
    end
  end

  def dpphash
    @dpphash ||= Hash.new
  end

  def parse_one_item(item)
    letter,rest = item.split(/:/, 2)

    dpphash[letter] = rest
    case letter
    when 'S'
      self.smarkaklink = rest
    when 'M'
      self.mac = rest
    when 'K'
      begin
        self.keybinary = Base64.strict_decode64(rest)
        self.key = OpenSSL::PKey.read(keybinary)
      rescue OpenSSL::PKey::PKeyError
        raise DPPKeyError
      rescue ArgumentError  # invalid base 64
        raise DPPKeyError
      end
    when 'L'
      self.llv6= rest
    when 'E'
      self.essid= rest
    end
  end

  def ecdsa_key
    @ecdsa ||= ECDSA::Format::PubKey.decode(key)
  end

  def parse_dpp
    return if dppcode.blank?

    return unless dppcode[0..3].upcase == 'DPP:'
    dppcodes = dppcode[4..-1]

    colons = dppcodes.split(/;/)

    item = colons.shift
    while item
      parse_one_item(item)
      item = colons.shift
    end
  end

  # turn compressed hex IPv6 address into something useable for HTTPS
  # use IPAddress module
  def llv6_as_iauthority
    iid=ACPAddress::parse_hex llv6
    ll = iid.set_ll_prefix
    "[" + ll.to_s + "%wlan0]"
  end

  # this routine looks for ULA addresses, and then it picks out the
  # appropriate name, and turns into an appropriate name.
  # this should REALLY work by sending an mDNS unicast query to
  # the LL-v6 address asking for resolution of the name "mud"
  #
  # for testing purposes, this is right now hard coded to [::2]
  def ulanodename_iauthority
    ENV['NODENAME'] || "n3CE618.router.securehomegateway.ca"
  end

  def mudport
    ENV['NODEPORT'] || 8081
  end

  # decode the iauthority or URL found in the S field, and turn it into a full
  # URL
  def self.canonicalize_masa_url(url)
    if !url.blank? and !url.include?("/")
      url = "https://" + url + "/.well-known/brski/"
    else
      # make sure that there is a trailing /
      unless url[-1] == "/"
        url ||= "/"
      end
    end
    url
  end

  def smarkaklink_enroll_url
    URI.join(self.class.canonicalize_masa_url(smarkaklink), "smarkaklink")
  end

end
