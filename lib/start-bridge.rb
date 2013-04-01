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
core_dir = ARGV.length > 0 ? ARGV[0] : ENV['FRC_COREFILES']

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
  def put_gdb_str(cmd, quiet=false)
    if quiet && cmd.length > 90
      STDOUT.puts "-> #{cmd[0..42]}..#{cmd[-42..-1]}"
    else
      STDOUT.puts "-> #{cmd}"
    end
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
puts "Building offset map..."

offset_desc = "Text=#{wdb_mush.mod_offsets.text.to_s 16};Data=#{wdb_mush.mod_offsets.data.to_s 16};Bss=#{wdb_mush.mod_offsets.data.to_s 16}"
#puts "Got a map of this: "
# build the xml doc now
# <library-list>
# <library name="sharedlib.o">
# <segment address="0x10000000"/>
#</library>
#</library-list>
puts " Using #{core_dir}/cRIOFRC_vxWorks as cRIO corefile..."
xml_segs = "<library-list><library name=\"cRIOFRC_vxWorks\">"
`powerpc-wrs-vxworks-readelf -S #{core_dir}/cRIOFRC_vxWorks`.scan(/\[[ 0-9]{2}\] \.[\w\._\$]* *[A-Z]* *[0-9a-fA-F]{8} ([0-9a-fA-F]{1,9}) [0-9a-fA-F]{1,9} [0-9]{2} *[WZMSILGTExOop]*A[WZMSILGTExOop]* *[0-9]*/) do |offset|
  xml_segs << "<section address=\"0x00000000\"/>"
end
xml_segs << "</library><library name=\"FRC_UserProgram.out\">"
wdb_mush.mod_offsets.sections.each do |sec|
  xml_segs << "<section address=\"0x#{sec.offset.to_s(16)}\"/>"
end
xml_segs << "</library></library-list>"
brkmap = {}
puts "Listening for GDB..."
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
        client.put_gdb_str("PacketSize=2000;qXfer:libraries:read+")
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
        client.put_gdb_str("")#T0;tnotrun:0")
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
      elsif str.start_with? "Xfer:libraries:read:"
        bits = str.match(/:read::([a-fA-F0-9]{1,8}),([a-fA-F0-9]{1,8})/)
        offset = bits[1].to_i(16)
        size = bits[2].to_i(16)
        if offset >= xml_segs.length
          client.put_gdb_str("l")
        else
          client.put_gdb_str("m" + xml_segs[offset, size], true)
        end
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
    elsif str.start_with? "p" #individual register. ex p40 = register 0x40. register 40 = Instruction pointer, 40 = 8c
      r = str[1..-1].to_i(16)
      # GDB:  0 int 31 32 float 63 64 ctrl (int) 69 70 fpu 70 71 OEA ???
      # WDB0: 0 int 31 32 ctrl (different order) 37
      # WDB1: 0 float 31 32 fpu 32
      intRange = (0..31)
      ctrlRange = (64..69)
      intr = (intRange.include? r) || (ctrlRange.include? r)

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
        0x45 => 37,
        0x46 => 32, #FPU: fpscr
      }
      if r >= 0x40
        r = gdb_to_wdb[r]
      end
      client.put_gdb_str(wdb_mush.get_r_hex(thread_id, r, 1, intr))
    elsif str.start_with? "m" # memory. read. mADDR_TO_READ,SIZE
      bits = str.match(/m([a-fA-F0-9]{1,8}),([a-fA-F0-9]{1,8})/)
      client.put_gdb_str(wdb_mush.read_memory(bits[1].to_i(16), bits[2].to_i(16)).unpack("H*")[0])
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
