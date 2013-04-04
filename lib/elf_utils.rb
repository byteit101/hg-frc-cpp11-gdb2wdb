#GPLv3+

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