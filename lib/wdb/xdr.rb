# GPLv3+

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