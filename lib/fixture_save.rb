# module that helps save things to files.
require 'fixture_writer'

module FixtureSave
  # for saving the records for later use.
  def simplename
    if respond_to? :name and name
      name.gsub(/ /,'')
    else
      sprintf("%s%u", self.class.name, id)
    end
  end

  def to_namedyaml
    h = {}
    h[self.simplename] = self.attributes
    h.to_yaml(:SortKeys => true)
  end

  def save_self_tofixture(fw)
    savedbefore=fw.object_saved?(self)
    if !savedbefore
      fw.savefile(self.class) << self.to_namedyaml
    end
    return savedbefore
  end

  def savefixture(dir)
    fw ||= FixtureWriter.new(dir)
    self.savefixturefw(fw)
  end

  # this will get overridden.
  def savefixturefw(fw)
    save_self_tofixture(fw)
  end

  def self.included(klass)
    klass.extend(ClassMethods)
  end

  module ClassMethods
    def append_from_file(path=nil)
      path ||= "db/#{table_name}.yml"

      # this is not safe against SQL-injection attacks.
      begin
	records = YAML::load( File.open( File.expand_path(path, RAILS_ROOT) ) )
	records.each do |key, record|

	  cols   = ""
	  values = ""
	  sep    = ""
	  record.each do |column, value|
	    if !value.blank?
	      cols   += sep + column
	      if value.class == DateTime ||
		  value.class == Time
		values += sep + '"' + value.to_s(:db) + '"'
	      elsif value.class == Fixnum
		values += sep + value.to_s
	      else
		values += sep + quote_bound_value(value.to_s)
	      end
	      sep = ','
	    end
	  end

	  #puts "REPLACE INTO #{table_name} (#{cols}) VALUES (#{values})\n"
	  connection.execute("REPLACE INTO #{table_name} (#{cols}) VALUES (#{values});")

	  fid = record["id"]
	  unless RAILS_ENV == 'test'
	    puts "Loaded #{table_name} fixture with id=#{fid}\n"
	  end
	end
      rescue Errno::ENOENT
	unless RAILS_ENV == 'test'
	  puts "No such file: #{path}"
	end
      end
    end
  end
end

