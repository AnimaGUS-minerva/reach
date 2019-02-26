class SystemVariable < ActiveRecord::Base
  include FixtureSave

  @@cache = Hash.new

  def self.dump_vars
    all.each { |thing|
      valshort = thing.value || ""
      if valshort && valshort.size > 128
        valshort = valshort[0..7]+"..."+valshort[-7..-1]
      end
     puts "#{thing.variable}: #{thing.number} #{valshort}"
    }
    true
  end

  def self.lookup(thing)
    self.find_by_variable(thing.to_s)
  end

  def self.findormake(thing)
    v = self.lookup(thing)
    if v.nil?
      v = self.new
      v.variable = thing.to_s
    end
    v
  end

  def self.boolvalue?(thing)
    v = self.lookup(thing)
    return false if v.nil?
    return (v.number != 0)
  end

  def self.string(thing)
    v = self.lookup(thing)
    return nil if v.nil?
    return v.value
  end

  def self.boolcache?(thing)
    @@cache[thing] ||= boolvalue?(thing)
  end

  def self.number(thing)
    v = self.lookup(thing)
    return 0 if v.nil?
    return v.number
  end

  def self.setnumber(thing, value)
    v = self.findormake(thing)
    v.number = value
    v.save
  end

  def self.setvalue(thing, value)
    v = self.findormake(thing)
    v.value = value
    v.save
  end

  def self.nextval(thing)
    v = self.findormake(thing)
    if v.number.nil?
      v.number = 1
    end
    v.nextval
  end

  # this generates a new pseudo-random number from the things stored into
  # the given item.  Both the number and value are used.   The value is used
  # to store the cryptographic state, and the number gives which iteration
  # this is.  This object needs to initialize itself from a nextval().
  def self.randomseq(thing)

    # first find the thing.
    v = self.findormake(thing)

    # next, see if the thing has never been initialized and initialize it with
    # a random value.
    if v.value.nil?
      prng = Random.new
      v.number = 1 unless v.number
      [1..(v.number)].each {|n|
        prng.rand(2147483648)
      }
      v.value = Base64.encode64(Marshal.dump(prng))
      v.save!
    end

    prng = Marshal.load(Base64.decode64(v.value))
    v.number = prng.rand(2147483648)
    v.value = Base64.encode64(Marshal.dump(prng))
    v.save!
    v.number
  end

  def self.get_uid
    return self.nextval(:unix_id)
  end

  def after_save
    @@cache.delete(self.variable)
  end

  def nextval
    n = nil
    begin
      transaction do
        n = self.number
        m = n + 1
        self.number = m
        self.save
      end
    #rescue ActiveRecord::Rollback
    #  logger.err "failed to get nextval for #{variable}"
    end
    n
  end

  def elidedvalue
    if value.blank?
      ""
    elsif value.length > 15
      value[0..7] + ".." + value[-7..-1]
    else
      value
    end
  end

  def self.masa_iauthority
    SystemVariable.string("masa_iauthority")
  end

  def self.routerfqdn
    SystemVariable.string("routerfqdn")
  end

end
