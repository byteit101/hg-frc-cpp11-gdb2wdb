# GPLv3+

require_relative 'wdb/wdb'

wdb = Wdb.new "10.4.51.2"

#wdb.set_name "VxWorks6x_10.4.51.2"
sleep(0.05)
wdb.connect
sleep(5)
wdb.disconnect