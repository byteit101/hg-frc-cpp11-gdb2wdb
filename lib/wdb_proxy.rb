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


require_relative 'wdb/wdb'
require_relative './elf_utils'
require 'tmpdir'

class WdbProxy
  attr_reader :mod_offsets
  attr_reader :wdb
  def initialize(seek_out=true)
    @wdb = Wdb.new "10.4.51.2"
    @breakpts = []
    @thread_breakpoints = nil
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

  def write_memory(data, addr)
    opt = Wdb::MEMORY_OPTIONS[:force_write]
    if (data.length % 2) != 0
      opt |= Wdb::MEMORY_OPTIONS[:copy_by_uint8]
    elsif (data.length % 4) != 0
      opt |= Wdb::MEMORY_OPTIONS[:copy_by_uint16]
    end
    # 32 bit is default
    @wdb.set_mem(addr, data, opt)
  end

  def break_on_new_thread=(val)
    if val and not @thread_breakpoints
      @thread_breakpoints = [
        # 1 = thread create, 2 = thread quit
        # no args
        # 3 = task/tread
        # magic number
        # notify us when it happens and break it
        @wdb.create_custom_breakpoint(1, [], 3, 0xffff_ffff, 6),
        @wdb.create_custom_breakpoint(2, [], 3, 0xffff_ffff, 6)
      ]
    elsif !val and @thread_breakpoints
      @wdb.delete_breakpoint(@thread_breakpoints[0], 1)
      @wdb.delete_breakpoint(@thread_breakpoints[1], 2)
      @thread_breakpoints = nil
    end
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

  def self.link_it(filename, os_image, olink0, entry_name, base_addr)
    elk = ElfLinker.new(filename)
    elk.link_at(base_addr, os_image, entry_name, olink0)
    olink0
  end

  def upload_elf(filename, os_image, olink0, quiet = false,  entry_name = "FRC_UserProgram_StartupLibraryInit")
    WdbProxy.link_it(filename, os_image, olink0 + ".tmp", entry_name, 0)

    # link0 should exist now
    elk = ElfLinker.new(filename)
    elf = ElfParser.new(olink0 + ".tmp")
    thread_id = nil

    # compute the required size
    allocated_size = elf.section(:text).size + elf.section(:data).size + elf.section(:bss).size + 42 # unicorns
    # remove tmp file
    File.unlink(olink0 + ".tmp")
    # request space
    addr = @wdb.memalign(8, allocated_size)

    puts "Allocated on 0x#{addr.to_s 16}. Relocating elf file..." unless quiet
    elf = ElfParser.new(elk.link_at(addr, os_image, entry_name, olink0))

    puts "Zeroing entire allocated region..." unless quiet
    @wdb.fill_mem(addr, allocated_size)

    puts "Begining upload in chunks of 384 (0x180) bytes at a time..."
    [:text, :data].each do |seg_name|
      puts "Uploading .#{seg_name}..." unless quiet
      seg = elf.section(seg_name)
      seg_raw = seg.raw
      seg_address = seg.address
      (seg.size / 384.0).ceil.times do |idx|
        @wdb.set_mem(seg_address + (idx * 384), seg_raw[idx * 384, 384])
      end
      puts "Done" unless quiet
    end

    puts "Refreshing cache..." unless quiet
    @wdb.force_cache_refresh(addr, allocated_size)

    puts "Calling constructors..." unless quiet
    @wdb.call_ctors(elf.address_of("_ctors"))

    puts "Creating new thread..."
    thread_id = @wdb.thread_new("t#{entry_name}", elf.address_of(entry_name))
    puts "Success! Thread is 0x#{thread_id.to_s 16}"

    puts "Stopping at entry..." unless quiet
    @wdb.thread_resume(thread_id) # resumes creation, then instantly hits implicit stop

    puts "Saving offsets..." unless quiet
    @mod_offsets = Moduletab.new(false, 0,0,0, [])

    thread_id
  end

  def close
    @breakpts.each do |id|
      @wdb.delete_breakpoint(id)
    end
    self.break_on_new_thread = false
    wdb.disconnect
  end
end
