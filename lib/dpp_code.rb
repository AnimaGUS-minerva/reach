class DPPCode
  attr_accessor :key, :keybinary, :mac, :smartpledge, :llv6, :essid
  attr_accessor :dpphash
  attr_accessor :dppcode

  def initialize(str = nil)

  end

  def parse_one_item(item)
    letter,rest = item.split(/:/, 2)

    dpphash[item] = rest
    case item
    when 'S'
      self.smartpledge = rest
    when 'M'
      self.mac = rest
    when 'K'
      begin
        self.keybinary = Base64.decode64(rest)
        self.key = OpenSSL::PKey.read(keybinary)
      rescue
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
    dppcodes = dppcode[3..-1]

    colons = dppcodes.split(/;/)
    return unless colons[0].upcase == 'DPP'
    colons.shift  # eat DPP

    item = colons.shift
    while item
      parse_one_item(item)
      item = colons.shift
    end

  end


end
