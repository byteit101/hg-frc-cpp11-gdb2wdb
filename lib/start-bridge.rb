# GPLv3+

# gdb
# file frc.out
# target remote :2345
# info symbol hex => function
# info address function => hex
# ifno file => symbol tables


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
      elsif str == "\x03" or str == "+"
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
puts "Searching for thead"
thread_id = wdb_mush.get_thread_id
puts "enabling debug mode..."
wdb_mush.debug_mode = true
puts "Listening for GDB..."

offset_desc = "Text=#{wdb_mush.mod_offsets.text.to_s 16};Data=#{wdb_mush.mod_offsets.data.to_s 16};Bss=#{wdb_mush.mod_offsets.data.to_s 16}"

brkmap = {}

client = server.accept

begin
  wdb_mush.async_get_events() do |data|
    client.put_gdb_str("S05") # Breakpoint default!
  end
  wdb_mush.break(thread_id)
  loop do
    str = client.get_gdb_str
    if str == "-"
      puts "FAIL FAIL FAIL!!!!"
      exit -1
    end
    str = validate_gdb_packet(str) unless str == "+" or str == "\x03"
    client.send "+", 0 if str
    if str == "+"
    elsif str == "\x03"
      wdb_mush.break(thread_id)
      client.put_gdb_str("S05") #signal 05 (TRAP)
    elsif str.start_with? "q"
      str = str[1..-1]
      if str.start_with? "Supported"
        client.put_gdb_str("PacketSize=1000")
      elsif str.start_with? "C" #current thread
        client.put_gdb_str("QC#{thread_id.to_s 16}")
      elsif str.start_with? "Attached"
        client.put_gdb_str("1")
      elsif str.start_with? "Symbol::"
        #client.put_gdb_str("qSymbol:5f5a3379617969") # 4652435f5573657250726f6772616d5f537461727475704c696272617279496e6974")
        #client.put_gdb_str("qSymbol:FRC_UserProgram_StartupLibraryInit")
        client.put_ok
      elsif str.start_with? "Symbol:"
        puts str
        client.put_ok
      elsif str.start_with? "Offsets"
        # BSS = baloney. why must I do this? is this a Gdb bug?
        client.put_gdb_str(offset_desc)
      elsif str == "TStatus" #tracing status
        client.put_gdb_str("T0")
      elsif str == "TfV"
        client.put_gdb_str("")
      elsif str == "TfP"
        client.put_gdb_str("")
      elsif str == "fThreadInfo" # first thread info
        client.put_gdb_str("m #{thread_id.to_s 16}") # one thread. separate multiple with commas
      elsif str == "sThreadInfo" # more thread info
        client.put_gdb_str("l") # l = last
      elsif str.start_with? "ThreadExtraInfo"
        client.put_gdb_str("Kernel Task") # TODO: get more exciting thread info
      else
        puts "Unknown Query!"
        puts "q" + str
      end
    elsif str.start_with? "H" # set the current thread, G is general, C is continue, i think
      client.put_gdb_str("OK")
    elsif str == "?" # what is the status?
      client.put_gdb_str("S05") #signal 05 (TRAP
    elsif str == "!"
      client.put_ok
    elsif str == "vCont?"
      client.put_gdb_str("vCont;s;S;C;c;t")
    elsif str.start_with? "vCont" # step, continue, etc
      str = str[5..-1]
      mod_threads = []
      # match ALL the requests!
      str.scan(/;([sScCt])(:([a-fA-F0-9]+)){0,1}/) do |cmd, ignore_me, thread|
        if thread == nil and mod_threads.include? thread_id
          next
        elsif thread == nil
          thread = thread_id
        else
          thread = thread.to_i(16)
        end
        mod_threads << thread
        if cmd == "s" #step
          wdb_mush.step(thread)
          client.put_gdb_str("S05") #signal 5 (TRAP)
        elsif cmd == "c" #continue
          wdb_mush.continue(thread)
        else
          puts "Unknown vCont!"
          puts "vCont;" + str
        end
      end
    elsif str == "s" #step
      wdb_mush.step(thread_id)
      client.put_gdb_str("S05") #signal 5 (TRAP)
    elsif str == "c" #continue
      wdb_mush.continue(thread_id)
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
      client.put_gdb_str(wdb_mush.get_r_hex(thread_id, r))
    elsif str.start_with? "m" # memory. read. mADDR_TO_READ,SIZE
      bits = str.match(/m([a-fA-F0-9]{1,8}),([a-fA-F0-9]{1,8})/)
      if bits[1].to_i(16) < 0x40 # silly eclipse
        client.put_gdb_str(wdb_mush.get_r_hex(thread_id, bits[1].to_i(16)/4, bits[2].to_i(16)/4))
      else
        client.put_gdb_str(wdb_mush.read_memory(bits[1].to_i(16), bits[2].to_i(16)).unpack("H*")[0])
      end
    elsif str.start_with? "Z0"
      addr = str.match(/Z0,([a-fA-F0-9]+),/)[1].to_i(16)
      brkmap[addr] = wdb_mush.add_breakpoint(addr)
      client.put_ok
    elsif str.start_with? "z0"
      wdb_mush.delete_breakpoint(brkmap[str.match(/z0,([a-fA-F0-9]+),/)[1].to_i(16)])
      client.put_ok
    elsif str.start_with? "T"  #is thread alive
      # CHEAT CHEAT!!!! TODO: fix
      client.put_ok
    elsif str == "D"
      client.put_ok
    elsif str.start_with? "vKill"
      client.put_ok
    else
      puts "Unknown packet!"
      puts str
    end
  end
ensure
  client.close
  wdb_mush.continue(thread_id)
  wdb_mush.debug_mode = false
  wdb_mush.close
end
