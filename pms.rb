# Mac OS X processus memory search tool
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
# This script search through a process memory space and dump the memory block
# when it finds a matching expression
#
# =======
#  Usage
# =======
# % sudo ruby pms.rb <pid> <regexp>
# wherein <pid> is the pid of the process you want to analyze
# and regexp is a regular expression
#
# Example: % sudo ruby pms.rb <pid> "password[\000]+([^\000]+)[\000]+shell"
#

require 'rubygems'
require 'ragweed'

include Ragweed
include Wraposx

def hexdump(buffer, addr = 0)
  i = 0
  last_line = ""
  dup = false
  buffer.scan(/.{0,16}/m) { |match|
    line = match.unpack('H2'*16).join(' ') + " "
    line += match.unpack("C*").map { |b| 0x20 > b || 0x7f < b  ? "." : b.chr }.join
    if (!dup && last_line == line)
      dup = true
      puts "*"
    elsif last_line != line
      dup = false
      puts ("%08x " % (addr + i)) + line
    end
    last_line = line
    i += 16
  }  
end

def search_regexp(buffer, regexp, addr = 0)
  hexdump(buffer, addr) if regexp.match(buffer)
end

def search_region(dbg, regexp, addr, debug = false)
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
      search_regexp(buffer, regexp, basic_region_info.address)
    end
    addr = basic_region_info.address + basic_region_info.size
  end
  puts "done!"  
end

if ARGV.size != 2 then
  puts "Mac OS X processus memory search tool"
  puts "Copyright (c) 2009 iZsh - izsh at iphone-dev.com"
  puts "================================================"
  puts "Usage: sudo ruby #{$0} <pid> <regexp>"
  exit(1)
end
  
pid = Integer(ARGV[0])
search_str = ARGV[1]
regexp = Regexp.new(search_str)
dbg = Debuggerosx.new(pid)
search_region(dbg, regexp, 0x0, true)

