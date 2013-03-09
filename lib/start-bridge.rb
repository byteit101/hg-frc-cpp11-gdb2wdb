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
p wdb_mush.get_ip_hex(thread_id)
client = server.accept
begin
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
      client.put_gdb_str("TextSeg=#{wdb_mush.mod_offsets.text.to_s 16};DataSeg=#{wdb_mush.mod_offsets.data.to_s 16}")
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
  elsif str == "vCont?"
    client.put_gdb_str("vCont;c;s;t")
  elsif str.start_with? "vCont" # step, continue, etc
    str = str[6..-1]
    if str.star_with? "s" #step
      wdb_mush.step(0)
      client.put_gdb_str("S05") #signal 5 (TRAP)
    else
      puts "Unknown vCont!"
      puts "vCont;" + str
    end
  elsif str == "g" # registers! oh yea, no ow
    client.put_gdb_str(wdb_mush.get_r_hex(thread_id, 0,4))
  elsif str.start_with? "p" #individual register. ex p40 = register 0x40. register 40 = Instruction pointer
    r = str[1..-1].to_i(16)
    # name  mem gdb
    # msr    32 41 
    # lr     33 43
    # ctr    34 44
    # pc/eip 35 40
    # cr     36 42
    # xer    37 45
    gdb_to_wdb = {
      0x41=>32,
      0x43 => 33,
      0x44 => 34,
      0x40 => 35,
      0x42 => 36,
      0x45 => 37
    }
    if r >= 0x40
      r = gdb_to_wdb[r]
    end
    res = (wdb_mush.get_r_hex(thread_id, r))
    if r == 35
      #TODO: why does GDB not relocate this?
      res = (res.to_i(16) - wdb_mush.mod_offsets.text).to_s(16).rjust(8, '0')
    end
    client.put_gdb_str(res)
  elsif str.start_with? "m" # memory. read. mADDR_TO_READ,SIZE
    bits = str.match(/m([a-fA-F0-9]{1,8}),([a-fA-F0-9]{1,8})/)
    client.put_gdb_str(wdb_mush.read_memory(bits[1].to_i(16), bits[2].to_i(16)).unpack("H*")[0])
  elsif str.start_with? "vKill"
    client.put_ok
  else
    puts "Unknown packet!"
    puts str
  end
end
client.close
ensure
  wdb_mush.close
end
 