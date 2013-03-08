# GPLv3+
require 'socket'
require_relative 'xdr'
require_relative '../blocking_udp'
require_relative '../mem_struct.rb'

class OncRpc
  RPC_CALL = 0
  RPC_RESPONSE = 1
  def self.wrap(seqn, func_number, data_str)

    hdr = [
      RPC_CALL,
      2, #version number of RPC
      0x55555555, # program "id"
      1, #program version
      func_number,
      0,0,0,0, # credentials and verifiers
      0, #checksum goes here
      48 + data_str.length, # 48 is the length of this header
      0x5140_0000|seqn
    ]
    pkt = hdr.pack("N*")
    pkt << data_str

    res = [seqn].pack("V")
    hdr[9] = checksum(pkt)
    res << hdr.pack("N*")
    res << data_str
    return res
  end
  def self.checksum(data_str)
    css = 0
    data_str.scan(/.{2}/m).each{|x| css += x.unpack("n")[0]}
    (0xFFFF_FFFF & ~((css & 0xFFFF) + (css >> 16)))
  end
end

class Wdb
  FUNC_NUMBERS = {
    "TARGET_PING" => 0,
    "TARGET_CONNECT" => 1,
    "TARGET_DISCONNECT" => 2,
    "TARGET_MODE_SET" => 3,
    "TARGET_MODE_GET" => 4,
    "MEM_READ" => 10,
    "MEM_WRITE" => 11,
    "MEM_FILL" => 12,
    "MEM_MOVE" => 13,
    "MEM_CHECKSUM" => 14,
    "MEM_PROTECT" => 15,
    "MEM_CACHE_TEXT_UPDATE" => 16,
    "MEM_SCAN" => 17,
    "MEM_MANY_WRITE" => 18,
    "MEM_WRITE_MANY_INT" => 19,
    "CONTEXT_CREATE" => 30,
    "CONTEXT_KILL" => 31,
    "CONTEXT_SUSPEND" => 32,
    "CONTEXT_RESUME" => 33,
    "CONTEXT_STATUS_GET" => 34,
    "CONTEXT_ATTACH" => 35,
    "CONTEXT_DETACH" => 36,
    "REGS_GET" => 40,
    "REGS_SET" => 41,
    "VIO_WRITE" => 51,
    "EVENTPOINT_ADD" => 60,
    "EVENTPOINT_DELETE" => 61,
    "EVENT_GET" => 70,
    "CONTEXT_CONT" => 80,
    "CONTEXT_STEP" => 81,
    "CONTEXT_STOP" => 82,
    "FUNC_CALL" => 90,
    "EVALUATE_GOPHER" => 91,
    "DIRECT_CALL" => 92,
    "SYM_LIST_ADD" => 100,
    "SYM_GET" => 101,
    "MOD_INFO_GET" => 102,
    "MOD_ADD" => 103,
    "MOD_REMOVE" => 104,
    "USR_SVC_CTRL" => 110,
    "USR_SVC_CALL" => 111,
    "THREAD_INFO_SET" => 120,
    "THREAD_INFO_GET" => 121
  }
  def initialize(host)
    @core = WdbCore.new
    @sock = BlockingUDPSocket.new
    @sock.bind("", 149501)
    @sock.filter do |inpkt|
      [:input, :response][inpkt[4..7].unpack("N")[0]]
    end
    @sock.connect host, 0x4321
    @seqn = 0 # start sequence number
  end
  def send(data)
    #puts "sending data"
    resp = @sock.send_blocking data, 0 #, "10.4.51.2", 0x4321
    #p resp
  end
  def set_name(str)
    send OncRpc.wrap(@seqn += 1, 122,
      @core.get_mem + [1].pack("N") +  Xdr.flatten(str))
  end
  def connect()
    send OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['TARGET_CONNECT'], @core.get_mem)
  end
  def disconnect()
    send OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['TARGET_DISCONNECT'], @core.get_mem)
  end
  def get_symbols(mod=0, sym=0, flags=0)
    decode_symtab(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['SYM_GET'], @core.get_mem + [
            mod.to_i, sym.to_i, flags.to_i
          ].pack("N*")))) # hope that the args are all ints...
  end
  def get_module(mod, sym=0, flags=0)
    decode_mod_info(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['MOD_INFO_GET'], @core.get_mem + [
            mod.to_i, sym.to_i, flags.to_i
          ].pack("N*")))) # hope that the args are all ints...
  end
  def decode_symtab(raw)
    # check the header
    rpc = RpcHeader.new(raw[0,36])
    if (rpc.type != 1) || rpc.event_type != 0 # reply, no event
      puts "whoa! unknown SYMTAB packet!"
      puts raw.unpack("H*")[0] # hexdump it
      puts "END OF ERROR PACKET"
      raise "unknown SYMTAB"
    end
    raw = raw[36..-1]
    symtab = Symtab.new
    symtab.index = raw[0,4].unpack("N")[0]
    symtab.more_coming = (raw[4,4].unpack("N")[0] != 0)
    symtab.entries = []
    offset = 8
    while raw[offset, 4].unpack("N")[0] != 0
      sym = SymbolInfo.new
      sym.next = raw[offset += 4, 4].unpack("N")[0]
      sym.id = raw[offset += 4, 4].unpack("N")[0]
      sym.value = raw[offset += 4, 4].unpack("N")[0]
      sym.ref = raw[offset += 4, 4].unpack("N")[0]
      sym.type = raw[offset += 4, 4].unpack("N")[0]
      sym.group = raw[offset += 4, 4].unpack("N")[0]
      sym.small_unk = raw[offset += 4, 4].unpack("N")[0]
      sym.addr_unk = raw[offset += 4, 4].unpack("N")[0]
      sym.name = raw[offset += 4, 4].unpack("N")[0]
      #puts "sym.name (length) = #{sym.name}; offset = #{offset}"
      if sym.name == 0
        sym.name = ""
      else
        sym.name = raw[offset += 4, sym.name-1] #ignore the trailing \0. 
        # puts "sym.name (data) = #{sym.name}"
        offset += sym.name.length
      end
      if (offset % 4) != 0
        offset += 4 - (offset % 4)
      end
      symtab.entries << sym
    end
    symtab
  end
  def decode_mod_info(raw)
    rpc = RpcHeader.new(raw[0,36])
    if (rpc.type != 1) || rpc.event_type != 0 # reply, no event
      puts "whoa! unknown MODTAB packet!"
      puts raw.unpack("H*")[0] # hexdump it
      puts "END OF ERROR PACKET"
      raise "unknown MODTAB"
    end
    raw = raw[36..-1]
    #cheat! cheat! this will fail!!!
    #TODO: get all the infos
    Struct::CheapModuleOffsets.new(raw[0x30, 4].unpack("N")[0], raw[0x40, 4].unpack("N")[0], raw[0x50, 4].unpack("N")[0])
  end
  def get_mem(addr, length)
    unwrap_xfer(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['MEM_READ'], [
            2, 0, 0, # WDB_CORE
            0, # options
            addr, length, 
            0 # param. this is never zero in WindRiver stuff. No iea what it could be
          ].pack("N*"))))
  end
  def get_regs(thread_id, rx=35, count=1, type=:int)
    # must we use tool 0x01c161c0 ?
    decode_regs(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['REGS_GET'], [
            2, 0, 0, # WDB_CORE
            (type == :int ? 0 : 1),
            3, # ctx type = task
            1, 1, thread_id, # task to get, of length 1, 1 (silly duplication)
            0, #options
            rx * 4, # register base
            count * 4, # size
            0 # param
          ].pack("N*"))))
  end
  def thread_break(thread_id)
    send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['CONTEXT_STOP'], [
            2, 0, 0, # WDB_CORE
            3, # context = task
            1, 1, thread_id # num of arguments, num of arguments, argument
          ].pack("N*")))
  end
  def decode_regs(raw)
    # ugh, must make this a funciton soon
    rpc = RpcHeader.new(raw[0,36])
    if (rpc.type != 1) || rpc.event_type != 0 || rpc.error_code != 0 # reply, no event
      puts "whoa! unknown REGS packet!"
      puts raw.unpack("H*")[0] # hexdump it
      puts "END OF ERROR PACKET"
      raise "unknown REGS"
    end
    raw = raw[36..-1]
    # options, source, dest, length = 4, skip them
    raw = raw[16..-1]
    raw =  raw.unpack("H*")
    # naw...
    #raw.unpack("N*")
    if raw.length == 1
      raw[0]
    else
      raw
    end
  end
  def unwrap_xfer(raw)
    # ugh, must make this a funciton soon
    rpc = RpcHeader.new(raw[0,36])
    if (rpc.type != 1) || rpc.event_type != 0 || rpc.error_code != 0 # reply, no event
      puts "whoa! unknown XFER packet!"
      puts raw.unpack("H*")[0] # hexdump it
      puts "END OF ERROR PACKET"
      raise "unknown XFER"
    end
    raw[52..-1]
  end
  def memalign(bound, size)
    #FIXME: this should not be hard coded
    direct_call(0x001b86d4, [bound, size])
  end
  def direct_call(entry_point, args)
    send OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['DIRECT_CALL'], @core.get_mem + [
        0, # System context
        0, # string length
        0, 0, 0, # redirect stdin, out, err
        0, #base addr
        entry_point,
        args.length,
        args.length #don't ask me why its twice, it just is!
      ].pack("N*") + args.pack("N*")) # hope that the args are all ints...
    #001b86d4
  end
  def exec_gopher(str)
    data = "".force_encoding("binary")
    res = raw_exec_gopher(str)
    data << res.data
    while res.has_more
      res = raw_exec_gopher("")
      data << res.data
    end
    data
  end
  def raw_exec_gopher(str)
    # tool number is 01c161c0
    # must we use tool 0x01c161c0 ?
    raw = send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['EVALUATE_GOPHER'], [
          2, 0, 0 # WDB_CORE
        ].pack("N*") + 
          Xdr.flatten(str)))
      
    # ugh, must make this a funciton soon
    rpc = RpcHeader.new(raw[0,36])
    if (rpc.type != 1) || rpc.event_type != 0 || (rpc.error_code != 0 && rpc.error_code != 0x4000) # reply, no event
      puts "whoa! unknown GOPHER packet!"
      puts raw.unpack("H*")[0] # hexdump it
      puts "END OF ERROR PACKET"
      raise "unknown GOPHER"
    end
    raw = raw[36..-1]
    # just shove in all the data
    WdbGopherResults.new(rpc.error_code == 0x4000, raw[16..-1])
  end
end

class WdbGopherStrings
  GET_THREADS="0x2feaac * +64 * { <-28 ! <+0 +48 @> <+44 *{$ 0}> <+152 @> <+112 @> <+148 @> <+448+140 @> > *}"
  GET_THREADS_SHORT="0x2feaac * +64 * { <-28 <+44 *{$ 0}> !> *}"
end

class WdbCore
  def get_mem
    [2,0,0].pack "N*"
  end
end

Struct.new("CheapModuleOffsets", :text, :data, :bss)
WdbGopherResults = Struct.new("WdbGopherResults", :has_more, :data)

class Symtab
  attr_accessor  :index, :more_coming, :entries
  def initialize(index=0, more=false, entries=[])
    @index = index
    @more_coming = more
    @entries = entries
  end
end

class SymbolInfo
  attr_accessor :next, :id, :value, :ref, :type, :group, :small_unk, :addr_unk, :name
  def next?
    self.next < 0x352d00
  end
end

class RpcHeader < MemStruct
  default_encoding :big_endian
  int :sequence, :little_endian
  int :type
  int :reply_to
  int :status
  int :verifier
  int :event_type
  int :checksum
  int :packet_size
  int :error_code
end