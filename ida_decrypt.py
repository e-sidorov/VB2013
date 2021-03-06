# IDAPython script ( need IDA Pro > 6.0 )
# Authors:
# Andrey Rassokhin ( gizmo@yandex-team.ru )
# Evgeniy Sidorov ( e-sidorov@yandex-team.ru )

from operator import itemgetter
from idautils import *

addr = 0
size = 0
xor_stat_pos = 0
xor_end_pos = 0
prev_key = ''
xor_key = []
strDict = {}


def decrypt(addr, size):
    global xor_key
    dec_buff = ''
    for i in xrange(size):
        dec_buff += chr(Byte(addr + i) ^ xor_key[i % len(xor_key)])
    return dec_buff

print "Script for strings decryption in DarkLeech modules"
print "Authors: "
print "\t Andrey Rassokhin ( gizmo@yandex-team.ru )"
print "\t Evgeniy Sidorov ( e-sidorov@yandex-team.ru )"
print "****************************************************"

for index, ordinal, ea, name in Entries():
    if name == "KEY_XOR":
        xor_start_pos = ea                
    if name == "C_MODULE_VERSION":
        xor_end_pos = ea
    if name.startswith('C_'):
        strDict[name] = ea

xor_size = xor_end_pos - xor_start_pos

for i in xrange(xor_size):
    xor_key.append(Byte(xor_start_pos + i))

#for key, value in sorted(strDict.iteritems(), key=lambda (k, v): (v, k)):
for key, value in sorted(strDict.iteritems(), key=itemgetter(1,0)):
    dec_buff = ''
    if not addr:
        addr = value
        prev_key = key
    else:
        size = value - addr
        dec_buff = decrypt(addr, size)
        print "[~] %s: %s" % (prev_key, dec_buff)
        MakeComm(addr, dec_buff)
        addr = value
        prev_key = key

size = 1
addr += 1

while Byte(addr + size):
    size += 1

addr -= 1

dec_buff = decrypt(addr, size)
print "[~] %s: %s" % (prev_key, dec_buff)
MakeComm(addr, dec_buff)
