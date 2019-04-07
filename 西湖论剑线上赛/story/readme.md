**利用：格式化串，栈溢出**

先利用格式化串泄露canary，再rop，getshell。

程序开启了以下保护：
```
[*] '/mnt/hgfs/Desktop/story/story'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

这里有格式化串漏洞
```
char *sub_400915()
{
  char *v0; // ST08_8
  char s; // [rsp+10h] [rbp-40h]
  unsigned __int64 v3; // [rsp+48h] [rbp-8h]
  v3 = __readfsqword(0x28u);
  printf("Please Tell Your ID:");
  read__((__int64)&s, 50uLL);
  v0 = strdup(&s);
  printf("Hello ", 50LL);
  printf(&s);                                   // 格式化串
  putchar('\n');
  return v0;
}
```
这里有栈溢出：
```
char *sub_4009A0()
{
  __int64 size; // [rsp+0h] [rbp-A0h]
  char s; // [rsp+10h] [rbp-90h]
  unsigned __int64 v3; // [rsp+98h] [rbp-8h]
  v3 = __readfsqword(0x28u);
  puts("Tell me the size of your story:");
  size = read_str2i();
  if ( size < 0 )
    size = -size;
  if ( size > 128 )
    size = 1024LL;
  puts("You can speak your story:");
  read__((__int64)&s, size);                    // 栈溢出
  return strdup(&s);
}
```
由于开启了canary保护，则需要先利用格式化串泄露canary：
```
pwndbg> stack 25
00:0000│ rsp  0x7fffffffdd90 —▸ 0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2887
01:0008│      0x7fffffffdd98 —▸ 0x603010 ◂— 'AAAAAAAA' //我输入的AAAAAAAA
02:0010│ rdi  0x7fffffffdda0 ◂— 'AAAAAAAA'
03:0018│      0x7fffffffdda8 ◂— 0x0
... ↓
05:0028│      0x7fffffffddb8 —▸ 0x7ffff7a85439 (_IO_file_setbuf+9) ◂— test   rax, rax
06:0030│      0x7fffffffddc0 —▸ 0x7ffff7dd2620 (_IO_2_1_stdout_) ◂— 0xfbad2887
07:0038│      0x7fffffffddc8 —▸ 0x7ffff7a7cdbd (setbuffer+189) ◂— test   dword ptr [rbx], 0x8000
08:0040│      0x7fffffffddd0 ◂— 0x0
09:0048│      0x7fffffffddd8 ◂— 0x47fcabdd43fa2100  //canary
0a:0050│ rbp  0x7fffffffdde0 —▸ 0x7fffffffde20 —▸ 0x400b70 ◂— push   r15
0b:0058│      0x7fffffffdde8 —▸ 0x4008c6 ◂— mov    qword ptr [rbp - 0x18], rax
```
此时寄存器rdi 的值为
```
RDI  0x7fffffffdda0 ◂— 'AAAAAAAA'
```
则偏移为6时才是栈中第一项，计算下canary的偏移是15。
利用`%15$p`即可泄露canary。
然后利用栈溢出写rop即可

[https://github.com/Dittozzz/CTF-pwn-writeup/blob/master/西湖论剑线上赛/story/exp.py](https://github.com/Dittozzz/CTF-pwn-writeup/blob/master/西湖论剑线上赛/story/exp.py "exp.py")
