# GPLv3+

require_relative 'wdb/wdb'

class WdbGdbMusher
  attr_reader :mod_offsets
  attr_reader :wdb
  def initialize(seek_out=true)
    @wdb = Wdb.new "10.4.51.2"
    @breakpts = []
    @wdb.connect
    unless seek_out
      puts "Connected to vxWorks."
      return
    end
    puts "Connected to vxWorks. Loading Symbols..."
    # load the important stuff: get the symbols
    syms = []
    loop do
      symtab = @wdb.get_symbols
      # only look for ours
      symtab.entries.each do |entry|
        if entry.name.include? "FRC_UserProgram_StartupLibraryInit"
          syms << entry
          break
        end
      end
      break if syms.length > 0 or !symtab.more_coming
    end
    if syms.length < 1 #fail
      puts "ERR, captain... we can't seem to find the FRC_UserProgram_StartupLibraryInit symbol... is it loaded?"
      @wdb.disconnect
      exit -1
    end
    syms = syms[0]
    puts "Found 'FRC_UserProgram_StartupLibraryInit' in the module with id 0x%x" % syms.ref
    @mod_offsets = @wdb.get_module(syms.ref)

    while @mod_offsets.has_more
      nr = @wdb.get_module(syms.ref)

      # some names are spread out in multiple responses.
      if nr.sections.first && nr.sections.first.offset == @mod_offsets.sections.last.offset
        @mod_offsets.sections.last.name += nr.sections.first.name
        nr.sections.delete_at(0)
      end

      # append to the master list
      nr.sections.each do |x|
        @mod_offsets.sections << x
      end
      @mod_offsets.has_more = nr.has_more
    end
  end

  def debug_mode=(value)
    # yea, magic numbers. you can find this in the symbol table. its edrSystemDebugModeSet(1)
    @wdb.direct_call(0x001a32d0, [value ? 1 : 0])
    value
  end

  def get_thread_id(name="FRC_RobotTask")
    res = @wdb.exec_gopher(WdbGopherStrings::GET_THREADS_SHORT) # format \x01string\0\x00threadid
    # this is so cheating. TODO: make it better
    chop = res[res.index(name)+name.length+1, 5]
    unless chop[0] == "\0"
      puts "Gopher thread not found!"
      p res
      puts "--------"
      p chop
      raise "Thread #{name} was not found"
    end
    chop[1,4].unpack("N")[0].tap{|i| puts "Found Thread ID of '#{name}': 0x#{i.to_s(16)}"}
  end

  def get_r_hex(thread_id, r=4, count=1, is_int=true)
    @wdb.get_regs(thread_id, r, count, (is_int ? :int : :fpu))
  end

  def get_ip_hex(thread_id)
    @wdb.get_regs(thread_id, 35, 1)
  end

  def read_memory(addr, size)
    @wdb.get_mem(addr, size)
  end

  def break(thread_id)
    @wdb.thread_break(thread_id)
  end

  def step(thread_id, lower=0, upper=0)
    @wdb.step(thread_id, lower, upper)
  end

  def continue(thread_id)
    @wdb.continue(thread_id)
  end

  def add_breakpoint(addr)
    @wdb.create_breakpoint(addr).tap{|id| @breakpts << id}
  end

  def delete_breakpoint(id)
    @breakpts -= [id]
    @wdb.delete_breakpoint(id)
  end

  def async_get_events(&block)
    Thread.new do
      loop {
        @wdb.get_event_call
        block.call(@wdb.get_event)
      }
    end
  end

  def close
    @breakpts.each do |id|
      @wdb.delete_breakpoint(id)
    end
    wdb.disconnect
  end
end