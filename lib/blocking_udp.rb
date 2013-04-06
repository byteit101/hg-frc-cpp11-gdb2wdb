# GPLv3+
require 'socket'
require 'thread'


class BlockingUDPSocket < UDPSocket
  def filter(&block)
    @filter = block
    @eventQs = {}
    @lockedEvents = {}
    #cputs "yea"
    Thread.new do
      loop do
        pkt = self.recv (65 * 1024)
        category = @filter.call(pkt)
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
    recv_type :response
  end
  def recv_type(cat)
    if !@eventQs[cat] or @eventQs[cat].empty?
      @lockedEvents[cat] = [ConditionVariable.new, Mutex.new]
      @lockedEvents[cat][1].lock
      @lockedEvents[cat][0].wait(@lockedEvents[cat][1])
      @lockedEvents[cat] = nil
    end
    @eventQs[cat].pop
  end
  def cputs(str)
    STDOUT.puts str
  end
end