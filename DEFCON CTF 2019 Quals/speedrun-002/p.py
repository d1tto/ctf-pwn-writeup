sh="/bin/sh"
sh=sh[::-1]
a=""

for i in sh:
    a+=hex(ord(i))[2:]

print hex(int(a,16))