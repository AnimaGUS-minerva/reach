class FixtureWriter
  attr_accessor :dir
  attr_accessor :savefiles

  def initialize(dir)
    @dir = dir
  end

  def savefile(thing)
    return files[thing] if files[thing]

    basename = thing.base_class.name.to_s.demodulize.underscore.pluralize

    outfile = File.join(@dir, "#{basename.to_s}.yml")
    set_file(thing, File.open(outfile, "w"))
  end

  def set_file(thing, file)
    files[thing] = file
  end

  def object_saved?(object)
    @objecthash ||= Hash.new
    val = @objecthash[object]
    @objecthash[object] = 1
    return val
  end

  def closefiles
    @savefiles.values.each { |f|
      f.close
    }
    @savefiles = nil
  end

  private
  def files
    @savefiles ||= Hash.new
  end
end
