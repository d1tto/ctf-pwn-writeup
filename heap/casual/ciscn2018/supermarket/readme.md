漏洞出现在realloc.关于realloc，可以参考 https://www.cnblogs.com/ren54/archive/2008/11/20/1337545.html 

>   1.如果 当前连续内存块足够 realloc 的话，只是将p所指向的空间扩大，并返回p的指针地址。 这个时候 q 和 p 指向的地址是一样的。
>   2.如果 当前连续内存块不够长度，再找一个足够长的地方，分配一块新的内存，q，并将 p指向的内容 copy到 q，返回 q。并将p所指向的内存空间删除。

题目中用这个函数的地方很奇怪：

```
 if ( *((_DWORD *)(&s2)[index] + 5) != size )
    realloc(*((void **)(&s2)[index] + 6), size);
  printf("description:");
  return _read__(*((_DWORD *)(&s2)[index] + 6), *((_DWORD *)(&s2)[index] + 5));
```
调用了realloc，但是没有接收返回值，读入还是在原description chunk中读入。

commodity的结构如下:
```
chunk_info      struc ; (sizeof=0x1C, mappedto_5)
00000000 name            db 16 dup(?)
00000010 price           dd ?
00000014 desc_size       dd ?
00000018 desc_ptr        dd ?
0000001C chunk_info      ends
```
其中desc_ptr指向description_chunk.

**利用：**
1. 可以输入比原来description_size更大的size，那么realloc就会将原本的description free掉，再申请一个大的chunk来存放description。虽然free掉了，但是指针没清除，相当于构成了UAF。
2. 再申请一个commodity，那么他的chunk_info就会得到原先free掉的description_chunk,这时chunk_info的内容是可控的，可以修改chunk_info里的desc_ptr为free_got。
3. 使用list函数，泄露free的地址，即可计算出system地址
4. 再使用change_desc函数修改free_got表项为system函数，申请一个chunk，其description的内容为/bin/sh，然后free他即可getshell。
