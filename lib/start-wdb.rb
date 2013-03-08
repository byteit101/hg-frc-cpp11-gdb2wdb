# GPLv3+

require_relative 'wdb/wdb'

class WdbGdbMusher
  attr_accessor :mod_offsets
  def initialize
    @wdb = Wdb.new "10.4.51.2"
    @wdb.connect
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
  end
  
  def get_r_hex(r=4, count=1)
    @wdb.get_regs(r, count)
  end
  
  def get_ip_hex()
    @wdb.get_regs(35, 1)
  end
  
  def close
    wdb.disconnect
  end
end