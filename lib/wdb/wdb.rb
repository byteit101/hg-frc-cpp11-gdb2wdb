# GPLv3+
require 'socket'
require_relative 'xdr'
require_relative '../blocking_udp'

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
    puts "sending data"
    resp = @sock.send_blocking data, 0 #, "10.4.51.2", 0x4321
    p resp
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
end

class WdbCore
  def get_mem
    [2,0,0].pack "N*"
  end
end