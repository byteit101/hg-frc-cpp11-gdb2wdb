# GPLv3+
require 'socket'
require_relative 'xdr'
require_relative '../blocking_udp'
require_relative '../mem_struct.rb'

# TODO: if the error code is 0x8000, that means call get_event NOW!

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
  CTX_TYPES = {
    0 => :system,
    1 => :group,
    2 => :any,
    3 => :task,
    4 => :any_task,
    5 => :interrupt,
    6 => :any_interrupt,
    7 => :protect_domain,
    8 => :process,
    9 => :rtp,
    10 => :type_num
  }
  MEMORY_OPTIONS = {
    :force_write => 0x1, # aka remove write protections
    :copy_by_uint8 => 0x10000000,
    :copy_by_uint16 => 0x20000000,
    :copy_by_uint32 => 0x40000000,
  }
  def initialize(host)
    @core = WdbCore.new
    @sock = BlockingUDPSocket.new
    @sock.bind("", 149501)
    @expecting_event=false
    @sock.filter do |inpkt|
      if @expecting_event
        :response
      else
        [:input, :response][inpkt[4..7].unpack("N")[0]]
      end
    end
    @sock.connect host, 0x4321
    @seqn = 0 # start sequence number
  end
  def send(data)
    #puts "sending data"
    resp = @sock.send_blocking data, 0 #, "10.4.51.2", 0x4321
    #p resp
  end
  def send_with_event(data)
    @expecting_event = true
    resp = strip_header(send(data))
    evt_ping = @sock.recv_type :response
    @expecting_event = false
    event_resp = strip_header(get_event)
    WdbEventCollection.new(resp, evt_ping[20..23].unpack("N")[0], event_resp)
  end
  def get_event_call
    @sock.recv_type :input
  end
  def get_event
    send OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['EVENT_GET'], @core.get_mem)
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
    raw = strip_header(raw)
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
      if sym.name == 0
        sym.name = ""
      else
        sym.name = raw[offset += 4, sym.name-1] #ignore the trailing \0.
        offset += sym.name.length + 1  #don't forget the null terminator
      end
      if (offset % 4) != 0
        offset += 4 - (offset % 4)
      end
      symtab.entries << sym
    end
    symtab
  end
  def strip_header(raw)
    rpc = RpcHeader.new(raw[0,36])
    if (rpc.type != 1) || rpc.event_type != 0 || (rpc.error_code != 0 && rpc.error_code != 0x4000) # reply, no event
      puts "whoa! unknown response packet!"
      puts raw.unpack("H*")[0] # hexdump it
      puts "END OF ERROR PACKET"
      puts "type: #{rpc.type.to_s 16}"
      puts "event type: #{rpc.event_type.to_s 16}"
      puts "error code: #{rpc.error_code.to_s 16}"
      raise "Error in packet!"
    end
    raw[36..-1]
  end
  def decode_mod_info(raw)
    raw = strip_header(raw)
    more = !raw[0x28, 4].unpack("N")[0].zero?
    text = raw[0x30, 4].unpack("N")[0]
    data = raw[0x40, 4].unpack("N")[0]
    bss = raw[0x50, 4].unpack("N")[0]
    mod_name_len = raw[96, 4].unpack("N")[0]
    if (mod_name_len % 4) != 0
      mod_name_len += (4 - (mod_name_len % 4))
    end
    # skip over all the fixed length info + string length
    raw = raw[(100 + mod_name_len)..-1]
    offset = 0
    res  = []
    until raw[offset, 4].unpack("N")[0].zero?
      offset += 4
      sec_off = raw[offset += 16, 4].unpack("N")[0]
      namelen = raw[offset += 16, 4].unpack("N")[0]
      name = ""
      unless namelen == 0
        name = raw[offset += 4, namelen-1] #ignore the trailing \0.
        offset += name.length + 1  #don't forget the null terminator
      end
      if (offset % 4) != 0
        offset += 4 - (offset % 4)
      end
      res << Struct::SectionOffsets.new(name, sec_off)
    end
    Moduletab.new(more, text, data, bss, res)
  end
  def set_mem(addr, data, options=MEMORY_OPTIONS[:force_write])
    strip_header(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['MEM_WRITE'], [
            2, 0, 0, # WDB_CORE
            options,
            data.length,
            addr,
            data.length
          ].pack("N*") + data)))
  end
  def force_cache_refresh(addr, size)
    strip_header(_send_mem_region(FUNC_NUMBERS['MEM_CACHE_TEXT_UPDATE'], addr, size, 0, 0))
  end
  def fill_mem(addr, size, pattern=0)
    strip_header(_send_mem_region(FUNC_NUMBERS['MEM_FILL'], addr, size, pattern))
  end
  def get_mem(addr, length)
    unwrap_xfer(_send_mem_region(FUNC_NUMBERS['MEM_READ'], addr, length))
  end
  def _send_mem_region(func_number, addr, size, param=0, mem_option=MEMORY_OPTIONS[:force_write])
    send(OncRpc.wrap(@seqn += 1, func_number, [
          2, 0, 0, # WDB_CORE
          mem_option,
          addr,
          size,
          param
        ].pack("N*")))
  end
  def get_regs(thread_id, rx=35, count=1, type=:int)
    rsize = (type == :int ? 4 : 8)
    # must we use tool 0x01c161c0 ?
    decode_regs(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['REGS_GET'], [
            2, 0, 0, # WDB_CORE
            (type == :int ? 0 : 1),
            3, # ctx type = task
            1, 1, thread_id, # task to get, of length 1, 1 (silly duplication)
            0, #options
            rx * rsize, # register base
            count * rsize, # size
            0 # param
          ].pack("N*"))))
  end
  def thread_new(name, entry_point, priority=100, stack_size=0x20000, options=0x10)
    strip_header(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['CONTEXT_CREATE'], @core.get_mem + [
            3, # context = task
          ].pack("N*") + Xdr.flatten(name) + [
            0, 0, 0, # redir stdin, out, err
            0, # base = 0, its the kernel
            entry_point,
            0, 0, # 0 args
            0, # not in a protected domain
            priority, stack_size, options
          ].pack("N*"))))
  end
  def thread_break(thread_id)
    strip_header send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['CONTEXT_STOP'], [
          2, 0, 0, # WDB_CORE
          3, # context = task
          1, 1, thread_id # num of arguments, num of arguments, argument
        ].pack("N*")))
  end
  def decode_regs(raw)
    raw = strip_header(raw)
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
    strip_header(raw)[16..-1]
  end
  def memalign(bound, size)
    #FIXME: this should not be hard coded
    strip_header(direct_call(0x001b86d4, [bound, size])).tap{|x| puts "Got memalign()=> #{x.inspect}"}.unpack("N")[0]
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
  def call_ctors(_ctors)
    call_task_func(0xd3274, [_ctors])
  end
  def call_task_func(entry_point, args, priority=100, stack_size=0, options=0)
    func_call(3, #3 for task
      [
        entry_point,
        args.length,
        args.length
      ] + args + [
        0, # protected domain id (none = 0)
        priority,
        stack_size,
        options
      ]
    )
  end
  def func_call(type, args)
    send OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['FUNC_CALL'], @core.get_mem + [
        type, # System context
        0, # string length
        0, 0, 0, # redirect stdin, out, err
        0, #base addr
      ].pack("N*") + args.pack("N*")) # hope that the args are all ints...
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

    rpc = RpcHeader.new(raw[0,36])
    raw = strip_header(raw)
    # just shove in all the data
    WdbGopherResults.new(rpc.error_code == 0x4000, raw[16..-1])
  end
  def step(thread, lower, upper)
    res = send_with_event(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['CONTEXT_STEP'], [
          2, 0, 0, # WDB_CORE
          3, # its a task!
          1, 1, thread, # argument array
          lower, upper # and now our bounds
        ].pack("N*")))

  end
  def continue(thread)
    strip_header send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['CONTEXT_CONT'], [
          2, 0, 0, # WDB_CORE
          3, # its a task!
          1, 1, thread, # argument array
        ].pack("N*")))
  end
  def decode_event(raw)
    bed = BasicEventData.new(*raw[0,16].unpack("N*"))
    bed.ctx_type = CTX_TYPES[bed.ctx_type] || bed.ctx_type
  end
  def create_breakpoint(addr)
    strip_header(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['EVENTPOINT_ADD'], @core.get_mem + [
            3, #its a breakpoint
            3, 3, addr, 0, 0, # list of 3 arguments
            3, 1, 1, 0, # its a task, with 1 argument
            6, # Stop and phone home
            0, 0, 0 # magic arguments
          ].pack("N*")))).unpack("N")[0]
  end
  def delete_breakpoint(id)
    strip_header(send(OncRpc.wrap(@seqn += 1, FUNC_NUMBERS['EVENTPOINT_DELETE'], @core.get_mem + [
            3, #its a thread breakpoint
            id
          ].pack("N*")))).unpack("N")[0]
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

Struct.new("SectionOffsets", :name, :offset)
Moduletab = Struct.new("Moduletab", :has_more, :text, :data, :bss, :sections)
WdbGopherResults = Struct.new("WdbGopherResults", :has_more, :data)
WdbEventCollection = Struct.new("WdbEventCollection", :response, :event_type, :event_data)

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

BasicEventData = Struct.new("BasicEventData", :unknown, :ctx_type, :ctx_id, :parent_id)
