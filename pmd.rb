# Mac OS X processus memory dump tool
# Copyright (c) 2011 iZsh - izsh at fail0verflow.com
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
# This script dumps a process memory space
#
# =======
#  Usage
# =======
# % sudo ruby pmd.rb <pid> <outfile>
# wherein <pid> is the pid of the process you want to analyze
# and <outfile> a filename to write to
#

require 'rubygems'
require 'ragweed'

include Ragweed
include Wraposx

# left for debugging purposes
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

def dump_regions(dbg, file, addr, debug = false)
  while true do
    print "Looking for the next region starting from addr 0x%08x\n" % addr if debug
    basic_region_info = dbg.region_info(addr) rescue break
    printf basic_region_info.dump if debug
    extended_region_info = dbg.region_info(addr, :extended) rescue break
    printf extended_region_info.dump if debug
    if ((basic_region_info.protection & Vm::Pflags::READ) != 0 &&
      (basic_region_info.max_protection & Vm::Pflags::READ) != 0 &&
      extended_region_info.share_mode != Vm::Sm::EMPTY)
    then
      begin
        buffer = Wraposx::vm_read(dbg.task, basic_region_info.base_address, basic_region_info.region_size)
      rescue
        buffer = ""
        puts "WARNING: something went wrong while reading @0x%x" % basic_region_info.base_address
      end
      file.write(buffer)
    end
    addr = basic_region_info.base_address + basic_region_info.region_size
  end
  puts "done!"  
end

if ARGV.size != 2 then
  puts "Mac OS X processus memory dump tool"
  puts "Copyright (c) 2011 iZsh - izsh at fail0verflow.com"
  puts "================================================"
  puts "Usage: sudo ruby #{$0} <pid> <outfile>"
  exit(1)
end
  
pid = Integer(ARGV[0])
File.open(ARGV[1], "w") do |f|
  dbg = Debuggerosx.new(pid)
  dump_regions(dbg, f, 0x0, true)
end
