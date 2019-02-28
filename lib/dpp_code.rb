class DPPCode
  attr_accessor :key, :keybinary, :mac, :smartpledge, :llv6, :essid
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
      self.smartpledge = rest
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

  # decode the iauthority or URL found in the S field, and turn it into a full
  # URL
  def self.canonicalize_masa_url(url)
    if !url.blank? and !url.include?("/")
      url = "https://" + url + "/.well-known/est/"
    else
      # make sure that there is a trailing /
      unless url[-1] == "/"
        url ||= "/"
      end
    end
    url
  end

  def smartpledge_enroll
    URI.join(self.class.canonicalize_masa_url(smartpledge), "smartpledge")
  end

end
