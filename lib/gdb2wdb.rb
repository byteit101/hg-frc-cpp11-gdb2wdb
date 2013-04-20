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

# gdb
# file frc.out
# target remote :2345
# info symbol hex => function
# info address function => hex
# ifno file => symbol tables


require 'trollop'

# Parse the args
GDB_PACKET_END = /^\#(..)$/

opts = Trollop::Parser.new do
  version "gdb2wdb 1.0 (c) 2013 Patrick Plenefisch"
  banner <<-EOS
GDB2WDB acts as a RSP client for GDB to enable debugging the cRIO (or any VxWorks target)

Usage:
       gdb2wdb options
where options are:
  EOS

  opt :attach, "Attach to thread of given name [default is to upload]", :type => :string
  opt :vxcorefile, "cRIO corefile (normally called cRIOFRC(II)_vxWorks)", :type => :io, :required => true
  opt :code, "Robot code to debug (normally called FRC_UserProgram.out)", :type => :io
  opt :no_gdb, "Don't run GDB on connect"
  opt :extended, "Use extended-remote GDB command (only valid without --no-gdb)"
  opt :port, "What port to listen for GDB on [default: 2345]", :type => :int, :default => 2345
  opt :link_only, "Link at address 0 and exit"
  opt :output_link, "Where to save the final linked elf file", :type => :string
  opt :entry_point, "Entry point [default: FRC_UserProgram_StartupLibraryInit]", :type => :string, :default => "FRC_UserProgram_StartupLibraryInit"
  opt :quiet, "Don't spew entire conversations", :default => false
  opt :log, "Redirect output to logfile", :type => :string
end
$opts = Trollop::with_standard_exception_handling opts do
  raise Trollop::HelpNeeded if ARGV.empty?
  res = opts.parse ARGV
  # check for invalid config
  if !res[:attach] && !res[:code]
    puts "Must provide robot code or a thread to attach to."
    raise Trollop::HelpNeeded
  end
  # fix stuff
  res[:code] = res[:code].path if res[:code]
  res[:vxcorefile] = res[:vxcorefile].path if res[:vxcorefile]
  if !res[:output_link] && res[:code]
    res[:output_link] = res[:code] + ".exec.elf"
  end
  res
end

core_file = $opts[:vxcorefile]
outfile = $opts[:code]

if $opts[:link_only]
  require_relative 'wdb_proxy'
  WdbProxy.link_it(outfile, core_file, $opts[:output_link], $opts[:entry_point], 0)
  exit 0
end

# have a forking good time :-D
christmas_pipes = IO.pipe
unless $opts[:no_gdb]
  serverpid = fork
  if serverpid # must be parent
    msg = christmas_pipes[0].gets.strip
    if msg == "die"
      Process.kill("TERM", serverpid)
      sleep 0.1
      Process.kill("KILL", serverpid)
      exit -1
    elsif msg == "gdb"
      Process.detach(serverpid)
      exec("powerpc-wrs-vxworks-gdb -nx -ex \"target remote localhost:#{$opts[:port]}\" #{$opts[:output_link]}")
    else
      puts "umm...?"
      p msg
      Process.kill("TERM", serverpid)
      sleep 0.1
      Process.kill("KILL", serverpid)
      exit -2
    end
  end
end
begin
  require 'socket'
  require_relative 'wdb_proxy'
  # exceptoin: "\x00\x00\x00\x06\x00\x00\x00\n\x00\x00\x00\x02\x00\x00\x00\x03\x00\xCB\xC5(\x0058 \x00\x00\x00\x03\x00\xCB\xC5(\x0058 \x00\x00\a\x00\x00\xECW\xF8\x00\x00\x00\x00"
  # go into the background
  Process.daemon(true, true) unless $opts[:no_gdb]

  def gdb_checksum(str)
    cs = 0
    str.each_char{|c| cs += c.ord}
    (cs & 0xFF).to_s(16).rjust(2, "0")
  end

  def validate_gdb_packet(str)
    str = [str, str[1..-4], str[-2..-1]]
    if gdb_checksum(str[1]) != str[2]
      puts "Checksum mismatch: expected '#{gdb_checksum(str[1])}' but found '#{str[2]}"
      return false
    end
    str[1]
  end

  def decode_gdb_data(str)
    str.gsub("}\x03", "#").gsub("}\x04", "$").gsub("}\x5d", "}")
  end

  def split_x_packet(str)
    #                             X    numbers hex    ,    num    hex     :  data
    r = str.unpack("H*")[0].match(/58((3[0-9]|6[1-6])+)2c((3[0-9]|6[1-6])+)3a(.*)$/)
    return [[r[1]].pack("H*").to_i(16), [r[3]].pack("H*").to_i(16), decode_gdb_data([r[5]].pack("H*"))]
  end

  class TCPSocket
    def get_gdb_str
      str = ""
      loop do
        str += self.getc
        if str.length > 3 && str[0] == "$" && str[-3..-1].match(GDB_PACKET_END)
          unless $opts[:quiet]
            px = validate_gdb_packet(str)
            if str[1] == "X"
              xp = split_x_packet(px)
              px = "X#{xp[0].to_s(16)},#{xp[1].to_s(16)}:#{xp[2].unpack("H*")[0]}"
            end
            STDOUT.puts "<- #{px}"
          end
          return str
        elsif str == "\x03" or str == "+"
          return str
        end
      end
    end
    def put_gdb_str(cmd, quiet=false)
      unless $opts[:quiet]
        if quiet && cmd.length > 90
          STDOUT.puts "-> #{cmd[0..42]}..#{cmd[-42..-1]}"
        else
          STDOUT.puts "-> #{cmd}"
        end
      end
      #TODO: encode
      self.send "$#{cmd}##{gdb_checksum(cmd)}", 0
    end
    def put_ok
      self.put_gdb_str("OK")
    end
  end

  server = TCPServer.new $opts[:port]
  wdb_mush = WdbProxy.new($opts[:attach] != nil)

  puts " Using #{core_file} as cRIO corefile..."
  xml_segs = "<library-list><library name=\"#{core_file}\">"
  `powerpc-wrs-vxworks-readelf -S #{core_file}`.scan(/\[[ 0-9]{2}\] \.[\w\._\$]* *[A-Z]* *[0-9a-fA-F]{8} ([0-9a-fA-F]{1,9}) [0-9a-fA-F]{1,9} [0-9]{2} *[WZMSILGTExOop]*A[WZMSILGTExOop]* *[0-9]*/) do |offset|
    xml_segs << "<section address=\"0x00000000\"/>"
  end
  xml_segs << "</library></library-list>"

  puts "enabling debug mode..."
  wdb_mush.debug_mode = true
  wdb_mush.break_on_new_thread = true

  thread_id = 0
  on_quit = :detach
  if $opts[:attach]
    puts "Searching for thead..."
    thread_id = wdb_mush.get_thread_id($opts[:attach])
    puts "Breaking thread..."
    wdb_mush.break(thread_id)
  else
    puts "Loading code into target memory..."
    thread_id = wdb_mush.upload_elf(outfile, core_file, $opts[:output_link], $opts[:quiet], $opts[:entry_point])
    on_quit = :kill
  end

  puts "Building offset map..."
  offset_desc = "Text=#{wdb_mush.mod_offsets.text.to_s 16};Data=#{wdb_mush.mod_offsets.data.to_s 16};Bss=#{wdb_mush.mod_offsets.data.to_s 16}"

  brkmap = {}
  all_threads = [thread_id]
  puts "Listening for GDB... #{$opts[:no_gdb] ?"connect with:\npowerpc-wrs-vxworks-gdb -nx -ex \"target remote localhost:#{$opts[:port]}\" #{$opts[:output_link]}":""}"
  unless $opts[:no_gdb]
    if $opts[:log]
      STDOUT.reopen($opts[:log], "a")
      STDERR.reopen($opts[:log], "a")
    else
      STDOUT.reopen("/dev/null", "w")
      STDERR.reopen("/dev/null", "w")
    end
    # tell the mothership we want gdb
    christmas_pipes[1].puts "gdb"
  end

  client = server.accept

  begin
    # listen for events (aka breakpoints)
    wdb_mush.async_get_events() do |data|
      type = data[0].type
      if type == 3 || type == 1 # breakpoint, ctx create
        client.put_gdb_str("T05thread:#{data[1].context_id.to_s 16};") # Breakpoint default!
        thread_id = data[1].context_id
        unless all_threads.include?(thread_id)
          all_threads << thread_id
        end
      elsif type == 2 # ctx destroy
        # remove it from our pool
        if all_threads.include?(data[1].context_id)
          all_threads -= [data[1].context_id]
        end
        if thread_id == data[1].context_id
          thread_id = all_threads[0] # if there are no more threads we might want to gracefully fail
        end
      else
        puts "Unknown event happened!"
        p data
      end
    end
    # GDB/RSP loop
    loop do
      str = client.get_gdb_str
      if str == "-"
        puts "FAIL FAIL FAIL!!!!"
        raise "GDB send a minus sign. All is not ok..."
      end
      str = validate_gdb_packet(str) unless str == "+" or str == "\x03"
      client.send "+", 0 if str
      if str == "+"
      elsif str == "\x03"
        wdb_mush.break(thread_id)
        client.put_gdb_str("T05thread:#{thread_id.to_s 16};") #signal 05 (TRAP)
      elsif str.start_with? "q"
        str = str[1..-1]
        if str.start_with? "Supported"
          client.put_gdb_str("PacketSize=2000;qXfer:libraries:read+")
        elsif str.start_with? "C" #current thread
          client.put_gdb_str("QC#{thread_id.to_s 16}")
        elsif str.start_with? "Attached"
          client.put_gdb_str("1")
        elsif str.start_with? "Symbol::"
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
        new_thread =  str[2..-1].to_i(16)
        if new_thread > 0
          thread_id = new_thread
        end
        client.put_gdb_str("OK")
      elsif str == "?" # what is the status?
        client.put_gdb_str("T05thread:#{thread_id.to_s 16};") #signal 05 (TRAP
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
            #client.put_gdb_str("S05") # signal 5 (TRAP)
          elsif cmd == "c" #continue
            wdb_mush.continue(thread)
          else
            puts "Unknown vCont!"
            puts "vCont;" + str
          end
        end
      elsif str == "s" #step
        wdb_mush.step(thread_id)
        #client.put_gdb_str("S05") # signal 5 (TRAP)
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
      elsif str.start_with? "X" # memory write. USES BINARY!
        pkt = split_x_packet(str)
        if pkt[1] > 0 # length
          if pkt[1] != pkt[2].length
            puts "Whoa! size written and data are not the same size! #{pkt[1]} != #{pkt[2].length}"
          end
          wdb_mush.write_memory(pkt[2], pkt[0])
        end
        client.put_ok
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
      elsif str == "D" # detach
        client.put_ok
        on_quit = :detach if on_quit != :kill
        raise nil
      elsif str == "k" # kill
        client.put_ok
        on_quit = :kill
        raise nil
      elsif str.start_with? "vKill"
        client.put_ok
      else
        puts "Unknown packet!"
        puts str
      end
      STDOUT.flush
      STDERR.flush
    end
  ensure
    puts "exiting"
    p $?
    STDOUT.flush
    STDERR.flush
    client.close
    if on_quit == :detach
      wdb_mush.continue(thread_id)
    else
      # TODO: kill
    end
    wdb_mush.debug_mode = false
    wdb_mush.close
  end
ensure
  christmas_pipes[1].puts "die"
end
