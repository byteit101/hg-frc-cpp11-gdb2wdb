# GPLv3+
require 'socket'
require 'thread'


class BlockingUDPSocket < UDPSocket
  def filter(&block)
    @filter = block
    @eventQs = {}
    @lockedEvents = {}
    cputs "yea"
    Thread.new do
      loop do
        cputs "revcing..."
        pkt = self.recv (65 * 1024)
        cputs "Recvd"
        category = @filter.call(pkt)
        cputs "Filtered to #{category}"
        (@eventQs[category] ||= Queue.new) << pkt
        lock = @lockedEvents[category]
        if lock
          lock[0].signal
        end

      end
    end.run
  end
  def send_blocking(*args)
    self.send *args
    cputs "recvign"
    recv_type :response
  end
  def recv_type(cat)
    if !@eventQs[cat] or @eventQs[cat].empty?
      @lockedEvents[cat] = [ConditionVariable.new, Mutex.new]
      @lockedEvents[cat][1].lock
      cputs "About to cat it"
      @lockedEvents[cat][0].wait(@lockedEvents[cat][1])
      cputs "done!"
      @lockedEvents[cat] = nil
    end
    @eventQs[cat].pop
  end
  def cputs(str)
    STDOUT.puts str
  end
end