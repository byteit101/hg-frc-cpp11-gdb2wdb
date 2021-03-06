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


class Xdr
  def self.flatten(obj)
    if obj.is_a? String
      return self.flatten_str obj
    end
  end
  def self.flatten_str(str)
    if (str.length % 4) != 0
      str << ("\0" * (4 - (str.length % 4 )))
    end
    [str.length].pack("N") + str
  end
end