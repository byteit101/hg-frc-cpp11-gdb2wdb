#GPLv3+

require 'fileutils'
require 'tmpdir'

class ElfLinker
  LD = "powerpc-wrs-vxworks-ld"
  def initialize(file_name)
    @file_name = file_name
    raise "No such file - #{file_name}" unless File.exist?(file_name)
  end

  def link_at(base_addr, os_image, entry_point)
    Dir.mktmpdir("gdb2wdb") do |tmpdir|
      # step 1: generate linker script
      File.open(File.join(tmpdir, "fkm.ld"), "wb") {|ld|
        ElfLinker.create_link_script(ld, @file_name, os_image, base_addr, entry_point)
      }
      # step 2: link it
      res = `#{LD} -z now -o #{File.join(tmpdir, File.basename(@file_name)) + ".elf"} #{@file_name} -X -T #{File.join(tmpdir, "fkm.ld")}`
      unless res == ""
        puts res
        raise "Error running LD!"
      end
      # step 3: copy it back
      FileUtils.cp(File.join(tmpdir, File.basename(@file_name)) + ".elf", @file_name + ".elf")
    end
    return @file_name + ".elf"
  end

  def self.create_link_script(output, input, os_image, base_addr, entry_point = "FRC_UserProgram_StartupLibraryInit")
    unk_syms = `powerpc-wrs-vxworks-nm -C -u #{input} |awk '{print $2}'`
    unk_syms.each_line do |line|
      line.strip!
      output.print "#{line} = 0x"
      output.puts `powerpc-wrs-vxworks-readelf -W -s #{os_image} | grep ' #{line}$' |awk '{print $2}'`.strip + ";"
    end
    output.puts <<STUFF
ENTRY(#{entry_point});
SECTIONS {
    .text 0x#{base_addr.to_s(16)}: {
        _VX_START_TEXT = .;
        *(.text*) *(.text.fast) *(.text.init)
        *(.text) *(.stub) *(.gnu.warning) *(.gnu.linkonce.t*)
        KEEP(*(.init)) KEEP(*(.fini))
        *(.rodata) *(.rodata.*) *(.gnu.linkonce.r*) *(.rodata1)
        *(.sdata2) *(.sbss2)
        . = ALIGN(4);
        *(.gcc_except_table*) /* cheat way to avoid copying this section later*/
    }
    .data ALIGN(16): { /* only really needs to be 8 it appears */
        _VX_START_DATA = .;
        *(.data*) *(.data.fast) *(.data.init)
        *(.gnu.linkonce.d*) SORT(CONSTRUCTORS) *(.data1)
        *(.eh_frame) *(.gcc_except_table)
        KEEP (*crtbegin.o(.ctors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .ctors))
        KEEP (*(SORT(.ctors.*)))
        KEEP (*(.ctors))
        KEEP (*crtbegin.o(.dtors))
        KEEP (*(EXCLUDE_FILE (*crtend.o) .dtors))
        KEEP (*(SORT(.dtors.*)))
        KEEP (*(.dtors))
        *(.got.plt) *(.got) *(.dynamic) *(.got2) *(.sdata) *(.sdata.*) *(.lit8) *(.lit4)
    }
    .bss ALIGN(16): {*(.bss*) *(.dynbss) *(.sbss) *(.scommon) *(COMMON)}
    /DISCARD/ : {*(.note) *(.comment) *(.pdr)}

    /* Debugging stuff */
    /* Stabs debugging sections.  */
    .stab 0 : { *(.stab) }
    .stabstr 0 : { *(.stabstr) }
    .stab.excl 0 : { *(.stab.excl) }
    .stab.exclstr 0 : { *(.stab.exclstr) }
    .stab.index 0 : { *(.stab.index) }
    .stab.indexstr 0 : { *(.stab.indexstr) }
    .comment 0 : { *(.comment) }
    /* DWARF debug sections.
       Symbols in the DWARF debugging sections are relative to the beginning
       of the section so we begin them at 0.  */
    /* DWARF 1 */
    .debug          0 : { *(.debug) }
    .line           0 : { *(.line) }
    /* GNU DWARF 1 extensions */
    .debug_srcinfo  0 : { *(.debug_srcinfo) }
    .debug_sfnames  0 : { *(.debug_sfnames) }
    /* DWARF 1.1 and DWARF 2 */
    .debug_aranges  0 : { *(.debug_aranges) }
    .debug_pubnames 0 : { *(.debug_pubnames) }
    /* DWARF 2 */
    .debug_info     0 : { *(.debug_info) }
    .debug_abbrev   0 : { *(.debug_abbrev) }
    .debug_line     0 : { *(.debug_line) }
    .debug_frame    0 : { *(.debug_frame) }
    .debug_str      0 : { *(.debug_str) }
    .debug_loc      0 : { *(.debug_loc) }
    .debug_macinfo  0 : { *(.debug_macinfo) }
    /* SGI/MIPS DWARF 2 extensions */
    .debug_weaknames 0 : { *(.debug_weaknames) }
    .debug_funcnames 0 : { *(.debug_funcnames) }
    .debug_typenames 0 : { *(.debug_typenames) }
    .debug_varnames  0 : { *(.debug_varnames) }
}
STUFF
  end
end


class ElfParser
  READELF = "powerpc-wrs-vxworks-readelf"
  OBJDUMP = "powerpc-wrs-vxworks-objdump"
  def initialize(file_name)
    @file_name = file_name
    raise "No such file - #{file_name}" unless File.exist?(file_name)
  end

  def entry_point
    `#{READELF} -h #{@file_name}`.match(/Entry point address: *0x([a-fA-F0-9]{1,8}) *$/)[1].to_i(16)
  end

  def section(sec)
    ElfParserSection.new(@file_name, sec)
  end

  def address_of(symbol)
    `#{READELF} -W -s #{@file_name} | grep ' #{symbol.to_s}$' |awk '{print $2}'`.strip.to_i(16)
  end
end

class ElfParserSection
  def initialize(file_name, section)
    @file_name = file_name
    @section = section
    raise "No such file - #{file_name}" unless File.exist?(file_name)
    @relf_regex = /^  \[[ 0-9]{2}\] .#{@section} +(NOBITS|PROGBITS) +([a-fA-F0-9]{1,8}) [a-fA-F0-9]{1,8} ([a-fA-F0-9]{1,8}) \d{2} +[WAXMSILGTExOoP]* +\d+ +\d+ +\d+$/
  end
  def raw
    dat = ""
    `#{ElfParser::OBJDUMP} -s -j .#{@section} #{@file_name}`.scan(/^ [a-fA-F0-9]{1,8}(( [a-fA-F0-9]{1,8})+)   *................$/) do |every_thing, last_thing|
      dat << [every_thing.gsub(" ", "")].pack("H*")
    end
    dat
  end
  def address
    `#{ElfParser::READELF} -S #{@file_name}`.match(@relf_regex)[2].to_i(16)
  end
  def size
    `#{ElfParser::READELF} -S #{@file_name}`.match(@relf_regex)[3].to_i(16)
  end
end