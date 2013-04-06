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