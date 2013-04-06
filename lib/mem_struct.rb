#  GDB2WDB - Debug VxWorks targets via WDB
#  Copyright (C) 2013 Patrick Plenefisch
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

# TODO: use a gem instead of copying this here

class MemStruct
  attr_accessor :raw_data
  @@enc = {}
  @@pos = {}
  @@fields = {}
  @@structs = {}
  @@save_it = {}
  def self.inherited(mod)
    @@enc[mod] = :little_endian # default to little endian, or V (vax)
    @@pos[mod] = 0
    @@fields[mod] = []
    @@structs[mod] = nil
    @@save_it[mod] = true
  end
  def self.int(name, *args)
    data(name, 4, *args)
  end
  def self.default_encoding(endian)
    @@enc[self] = endian
  end
  def self.read_only_data(ro=true)
    @@save_it[self] = !ro
  end
  def self.data(name, size, *args)
    @@fields[self] << name
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
    if @@save_it[self]
      define_method "#{name}=" do |v|
        if v.is_a?(Fixnum)
          v = [v].pack(extractor)
        end
        @raw_data[loc, size] = v
      end
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

  def unallocated_data
    @raw_data[@@pos[self.class], @raw_data.length]
  end

  def to_struct
    unless @@structs[self.class]
      sargs = [self.class.name + "Struct"] + @@fields[self.class]
      @@structs[self.class] = Struct.new(*sargs)
    end
    str = @@structs[self.class].new
    @@fields[self.class].each do |name|
      str[name] = send(name)
    end
    str
  end
end