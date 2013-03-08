# GPLv3+

# gdb
# file frc.out
# target remote :2345
# info symbol hex => function
# info address function => hex


require 'socket'
require_relative 'start-wdb'

GDB_PACKET = /^\$(.*)\#(..)$/

def gdb_checksum(str)
  cs = 0
  str.each_char{|c| cs += c.ord}
  (cs & 0xFF).to_s(16).rjust(2, "0")
end

def validate_gdb_packet(str)
  str = str.match GDB_PACKET
  if gdb_checksum(str[1]) != str[2]
    puts "Checksum mismatch: expected '#{gdb_checksum(str[1])}' but found '#{str[2]}"
    return false
  end
  str[1]
end

class TCPSocket
  def get_gdb_str
    str = ""
    loop do
      str += self.getc
      if str.match GDB_PACKET
        STDOUT.puts "<- #{validate_gdb_packet(str)}"
        return str
      elsif str == "+"
        return str
      end
    end
  end
  def put_gdb_str(cmd)
    STDOUT.puts "-> #{cmd}"
    #TODO: encode
    self.send "$#{cmd}##{gdb_checksum(cmd)}", 0
  end
  def put_ok
    self.put_gdb_str("OK")
  end
end

server = TCPServer.new 2345

wdb_mush = WdbGdbMusher.new
puts "Listening for GDB..."
#puts "Gopher:"
#puts wdb_mush.wdb.exec_gopher("0x2feaac * +64 * { <-28 ! <+0 +48 @> <+44 *{$ 0}> <+152 @> <+112 @> <+148 @> <+448+140 @> > *}").unpack("H*")
puts "Searching for thead"
thread_id = wdb_mush.get_thread_id

puts "enabling debug mode..."
wdb_mush.debug_mode = true
puts "IP HEX: "
puts "sigh, now I need to find the task ID...."
p wdb_mush.get_ip_hex
client = server.accept
loop do
  str = client.get_gdb_str
  if str == "-"
    puts "FAIL FAIL FAIL!!!!"
    exit -1
  end
  str = validate_gdb_packet(str) unless str == "+"
  client.send "+", 0 if str
  if str == "+"

  elsif str.start_with? "q"
    str = str[1..-1]
    if str.start_with? "Supported"
      client.put_gdb_str("PacketSize=1000")
    elsif str.start_with? "C" #current thread
      client.put_gdb_str("QC1451")
    elsif str.start_with? "Attached"
      client.put_gdb_str("0")
    elsif str.start_with? "Symbol::"
      #client.put_gdb_str("qSymbol:5f5a3379617969") # 4652435f5573657250726f6772616d5f537461727475704c696272617279496e6974")
      #client.put_gdb_str("qSymbol:FRC_UserProgram_StartupLibraryInit")
      client.put_ok
    elsif str.start_with? "Symbol:"
      puts str
      client.put_ok
    elsif str.start_with? "Offsets"
      client.put_gdb_str(sprintf "TextSeg=%x;DataSeg=%x", wdb_mush.mod_offsets.text, wdb_mush.mod_offsets.data)
    elsif str == "TStatus" #tracing status
      client.put_gdb_str("T0")
    elsif str == "TfV"
      client.put_gdb_str("")
    elsif str == "TfP"
      client.put_gdb_str("")
    else
      puts "Unknown Query!"
      puts "q" + str
    end
  elsif str.start_with? "H" # set the current thread, G is general, C is continue, i think
    client.put_gdb_str("OK")
  elsif str == "?" # what is the status?
    client.put_gdb_str("S05") #signal 5 (TRAP)
  elsif str == "!"
    client.put_ok
  elsif str == "g" # registers! oh yea, no ow
    client.put_gdb_str(wdb_mush.get_r_hex(0,0x80))
  elsif str.start_with? "p" #individual register. ex p40 = register 0x40. register 40 = Instruction pointer
    client.put_gdb_str(wdb_mush.get_ip_hex)
  elsif str.start_with? "vKill"
    client.put_ok
  else
    puts "Unknown packet!"
    puts str
  end
end
client.close
 