#GPLv3+
# TODO: use a gem instead of copying this here

class MemStruct
  attr_accessor :raw_data
  @@enc = {}
  @@pos = {}
  def self.inherited(mod)
    @@enc[mod] = "V" # default to little endian, or V (vax)
    @@pos[mod] = 0
  end
  def self.int(name, *args)
    data(name, 4, *args)
  end
  def self.default_encoding(endian)
    @@enc[self] = endian
  end
  def self.data(name, size, *args)
    loc = @@pos[self]
    extractor = if (if args.include?(:big_endian)
      :big_endian
    elsif args.include?(:little_endian)
      :little_endian
    else
      @@enc[self]
    end) == :big_endian
      "N"
    else
      "V"
    end

    define_method name do
      @raw_data[loc, size].unpack(extractor)[0]
    end
    define_method "#{name}=" do |v|
      if v.is_a?(Fixnum)
        v = [v].pack(extractor)
      end
      @raw_data[loc, size] = v
    end
    @@pos[self] += size
  end

  def initialize(hash)
    if hash.is_a? Hash and hash[:hex]
      d = ""
      (hash[:hex].length / 2).times do |i|
        d << [hash[:hex][i*2, 2].to_i(16)].pack("C")
      end
    else
      d = hash
    end
    @raw_data = d
  end
end