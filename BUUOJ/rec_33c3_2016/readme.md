#### 问题出现在Sign函数中:
```c
unsigned int sub_CDB()
{
  unsigned int result; // eax
  unsigned int v1; // et1
  void (*v2)(void); // [esp+8h] [ebp-20h]
  int v3; // [esp+Ch] [ebp-1Ch]
  char nptr; // [esp+10h] [ebp-18h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  my_read((int)&nptr, 0xCu);
  v3 = atoi(&nptr);
  if ( v3 <= 0 )
  {
    if ( v3 < 0 )                               // == 0 的时候没有对v2进行赋值
      v2 = (void (*)(void))Negative;
  }
  else
  {
    v2 = (void (*)(void))Positive;
  }
  v2();
  v1 = __readgsdword(0x14u);
  result = v1 ^ v5;
  if ( v1 != v5 )
    sub_1030();
  return result;
}
```
当v3等于0的时候没有对v2进行赋值，由于v2并没有进行初始化，那么v2的值将会是栈中的垃圾数据.后续调用v2的时候就会出现问题.

#### 泄露信息:
```
int __cdecl take_or_read_note(int a1)
{
  int result; // eax
  unsigned int v2; // et1
  char s; // [esp+8h] [ebp-20h]
  unsigned int v4; // [esp+1Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  if ( a1 )
  {
    printf("Your note: ");
    my_read((int)&s, 0x14u);
  }
  else
  {
    printf("Your note: ");
    puts(&s); //打印了栈中的数据
  }
  v2 = __readgsdword(0x14u);
  result = v2 ^ v4;
  if ( v2 != v4 )
    sub_1030();
  return result;
}
```
这里可以直接泄露栈中的数据，可以得到libc的基地址.

#### 下面就是劫持执行流:

向Sign的栈帧的v2的位置写入system的地址，并布置好参数即可getshell.
问题是Sign函数的栈帧很低:
![]()
其他函数的栈帧和他的距离太远了.

发现在polish函数中求和操作可以降低ESP:
![]()
每次调用一次该函数，ESP会降低 8 


求和操作时的ESP指向：
![]()
在sign中栈帧如下，则可以计算出大致的偏移:
![]()

