好久没用过unlink，就没往这边想，开始一直想用两次unsortedbin attack，看了wp才知道用unlink。

只用使用一次edit
```
  if ( edit_flag == 1 )
    exit(0);
  puts("index:");
  v2 = read_2_int();
  if ( v2 < 0 || v2 > 31 || !chunk_ptr[v2] )
    exit(0);
  puts("content:");
  v0 = chunk_ptr[v2];
  read(0, chunk_ptr[v2], 0x28uLL);
  ++edit_flag;
```
开始时不能使用show:
```
  if ( show_flag )
  {
    puts("index:");
    v1 = read_2_int();
    if ( v1 < 0 || v1 > 31 || !chunk_ptr[v1] )
      exit(0);
    puts((const char *)chunk_ptr[v1]);
  }
  else
  {
    puts("only admin can use");
  }
```
add函数有offbyone漏洞，且溢出字节可控。
```
unsigned __int64 add()
{
  int v1; // [rsp+Ch] [rbp-14h]
  void *v2; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("index:");
  v1 = read_2_int();
  if ( v1 < 0 || v1 > 31 || chunk_ptr[v1] )
    exit(0);
  v2 = malloc(0x28uLL);
  if ( (signed __int64)v2 < ptr || (signed __int64)v2 > ptr + 2048 )
    exit(0);
  chunk_ptr[v1] = v2;
  printf("gift: %llx\n", chunk_ptr[v1]);
  puts("content:");
  read(0, chunk_ptr[v1], 0x29uLL);
  ```
  由于有ptr的限制，不能直接把chunk malloc到bss段。
  利用思路是 先利用 tcache poison，将chunk申请到ptr指向的chunk，然后在该chunk上使用unlink，将ptr的内容修改为 &ptr-24 . 这样就可以把 chunk 申请到bss段了。
  
  tcache poison时，有个trcik是：
  ```
delete(13)
delete(19)
delete(11)
delete(5)
add(5,p64(fuck_chunk_addr))
  ```
  这里的 11和5 是相同的chunk，这样修改fd后，申请到chunk后，tcache_count是0，而不是 -1 ,这样就可以继续使用tcache poison.
  
