title: _IO_FILE部分源码分析及利用
date: 2019-04-24 11:13:36
tags:
---
<!--more-->
### 前言：

最近的题目(最近两年的国赛，HCTF2018)中出现了很多关于_IO_FILE的利用，不是house of orange中的伪造vtable，而是修改_IO_FILE结构体中的一些指针，达到任意读写的能力。
鉴于修改指针这方面的资料很少，只好自己读源码分析了。

### 部分源码分析:

在linux系统中，打开文件的系统调用是open，当使用open函数打开一个文件后，会返回一个整数，这个整数就是文件描述符。
每个进程都有一个叫做task_struct的结构体（即PCB，process control block），用来保存进程的一些信息，这个结构体保存了**文件描述符表**指针，来记录该进程打开的文件。而文件描述符就是这个表的索引。
当程序启动后，会默认打开三个文件，stdin,stdout,stderr.分别为标准输入，标准输出，标准错误。对应的文件描述符是0,1,2.
linux下一切都当做文件对待，显示器，键盘等都当做文件，这里的标准输入对应的就是键盘，标准输出就是对应的显示器。

而c语言用一个指向_IO_FILE结构体的指针来操作其对应的文件，其中**封装了文件描述符**，这个FILE结构体中保存的有文件描述符，操作文件权限，**_IO_缓冲区信息**等。后面的任意读写漏洞就是出在了IO缓冲区这里。
当使用fopen函数打开一个文件后，会返回一个指向FILE结构体的指针。
如:
```
FILE *fp;
fp=fopen("xxx","r")
```

#### _IO_FILE结构体：
```
truct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```

FILE结构体中有很多指针，**这里重点关注一下这些指针**:
```
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
```

这些指针记录了IO缓冲区的位置，和当前的读写位置。
c语言为了提高效率，为IO提供了缓冲区（这些缓冲区是默认分配在堆中的，也可以使用setbuf，setvbuf函数将输入输出与特定的缓存区相联系），**当第一次对文件读的时候，会以页为单位，将文件中的内容读取到缓冲区中，以供程序后来的使用，避免了多次系统调用，降低了效率(用户态和内核态的切换的消耗很大)。同理，对文件进行写操作的时候，其实是先在缓冲区中写**。如果修改这些指针，则可以达到任意读写的能力，但是需要搞清楚glibc是如何使用这些指针的。

**注意使用缓冲区的情况是使用c标准库的文件操作函数，如果你使用系统调用write，read等函数，是不使用缓冲区的，他直接将内容写入到对应的文件中（或直接从对应的文件中读取），因为write，read函数是直接使用文件描述符的，并不使用FILE结构。**

pwn的题目通常都会setbuf，setvbuf，取消缓冲区，防止缓冲区没有满，没有输出的情况。

```
 struct _IO_FILE *_chain;
```
这个指针指向下个FILE结构，所有的FILE结构体是使用单向链表串起来的，链表头是_IO_list_all.
如图所示：
![](https://github.com/Dittozzz/CTF-pwn-writeup/blob/master/_IO_FILE%E9%83%A8%E5%88%86%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/1.png?raw=true)

#### _IO_FILE_plus结构体：
```
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```
_IO_FILE_plus结构体只是对_IO_FILE结构体进行了封装，增加了一个新成员：vtable，这个和c++里的vtable很像。其实fopen返回的是_IO_FILE_plus类型的指针。
vtable是指向_IO_jump_t结构体类型的指针，_IO_jumpt_t结构体的定义如下：
```
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
};
```
其中`JUMP_FIELD`是一个宏：`#define JUMP_FIELD(TYPE, NAME) TYPE NAME`

可以看出 _IO_jump_t 是一个函数指针表，里面存的是函数指针，用来以后的跳转。libc中的函数指针非常多，可以劫持libc中的函数指针来劫持程序的执行流。
house of orange 就是构造 fake vtable 来getshell的，这里只是提下这个技术，本篇重点不在这里，而是修改指向缓冲区的指针。
这个函数表中有两个很重要的函数：__overflow，__underflow，在后面分析实例函数的时候会提到。

#### fopen函数:
```
_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL) //分配失败
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  _IO_no_init (&new_f->fp.file, 1, 0, NULL, NULL);
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_new_file_init_internal (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```
_IO_no_init函数是用来初始化的，他调用了`_IO_old_init`
其定义如下：
```
void
_IO_old_init (_IO_FILE *fp, int flags)
{
  fp->_flags = _IO_MAGIC|flags;
  fp->_flags2 = 0;
  fp->_IO_buf_base = NULL;
  fp->_IO_buf_end = NULL;
  fp->_IO_read_base = NULL;
  fp->_IO_read_ptr = NULL;
  fp->_IO_read_end = NULL;
  fp->_IO_write_base = NULL;
  fp->_IO_write_ptr = NULL;
  fp->_IO_write_end = NULL;
  fp->_chain = NULL; /* Not necessary. */
  fp->_IO_save_base = NULL;
  fp->_IO_backup_base = NULL;
  fp->_IO_save_end = NULL;
  fp->_markers = NULL;
  fp->_cur_column = 0;
#if _IO_JUMPS_OFFSET
  fp->_vtable_offset = 0;
#endif
#ifdef _IO_MTSAFE_IO
  if (fp->_lock != NULL)
    _IO_lock_init (*fp->_lock);
#endif
}
```
将缓冲区指针初始化为NULL，还有一些其他初始化的操作。
` _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;` 
`#define _IO_JUMPS(THIS) (THIS)->vtable` 
`extern const struct _IO_jump_t _IO_file_jumps;`
这里将vtable指向`_IO_file_jumps`。这步很重要，后面的输入输出函数都会用到。

真正完成打开文件操作的函数是_IO_file_fopen.
`# define _IO_new_file_fopen _IO_file_fopen`
该函数就是根据传入的modes，例如"r","r+"等来设置flag位，最终调用open系统调用完成打开文件操作。


#### getchar函数：

这里以getchar函数为例，其他输入函数最终调用的函数是相同的。

```
int
getchar (void)
{
  int result;
  _IO_acquire_lock (_IO_stdin); //获得锁
  result = _IO_getc_unlocked (_IO_stdin);
  _IO_release_lock (_IO_stdin); //释放锁
  return result;
}
```
在进行真正的读入操作前，先获得锁，这是因为在多线程的情况下，多个线程公用一个输入缓冲区，如果不加锁，当前线程正在读入的时候，由于调度，切换至另一个线程，如果他也在进行读入，则可能会读到相同的东西或者覆盖掉前一个线程读入的东西。

getchar 函数调用了函数`_IO_getc_unlocked`进行输入。
其定义如下：
```
#define _IO_getc_unlocked(_fp) \
       (_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) \
	? __uflow (_fp) : *(unsigned char *) (_fp)->_IO_read_ptr++)
```
```
# define _IO_BE(expr, res) __builtin_expect ((expr), res)
```
__builtin_expect在标准库中使用的地方很多，他并不改变比较的结果，只是表明这个比较结果很有可能是 true还是false，以便来优化汇编代码。详情可以百度下。

`_IO_BE ((_fp)->_IO_read_ptr >= (_fp)->_IO_read_end, 0) ` 这段代码只是表明`(_fp)->_IO_read_ptr >= (_fp)->_IO_read_end`很可能是false。
如果`(_fp)->_IO_read_ptr >= (_fp)->_IO_read_end`为true则执行`__uflow (_fp) `，否者执行`*(unsigned char *) (_fp)->_IO_read_ptr++)`

看一下_IO_FILE结构中定义的_IO_read_ptr的注释:`Current read pointer`，**他指的是当前的读入位置，即在输入缓冲区中的位置**。
_IO_read_ptr的注释为`char* _IO_read_end;	/* End of get area. */` 读取缓冲区结束的位置。
之前已经说过，我们输入的东西其实是先保存在输入缓冲区中，如果_IO_read_ptr小于_IO_read_end则说明，并没有到输入缓冲区的尽头，则只需返回_IO_read_ptr所指向的一字节的内容，然后_IO_read_ptr的大小增加1，指向下一个字节。
如果_IO_read_ptr大于等于_IO_read_end，则说明已经读取到尽头，则需要重新从设备中读取数据到缓冲区，从这里可以看出，最初的时候，_IO_read_ptr是和_IO_read_end相等的，因为这样才会从键盘中进行读取，否者缓冲区中是没有内容的。

看一下__uflow的定义:
```
int
__uflow (_IO_FILE *fp)
{
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  if (_IO_vtable_offset (fp) == 0 && _IO_fwide (fp, -1) != -1)
    return EOF;
#endif

  if (fp->_mode == 0)
    _IO_fwide (fp, -1);
  if (_IO_in_put_mode (fp))
    if (_IO_switch_to_get_mode (fp) == EOF)
      return EOF;
  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr++;
  if (_IO_in_backup (fp))
    {
      _IO_switch_to_main_get_area (fp);
      if (fp->_IO_read_ptr < fp->_IO_read_end)
	return *(unsigned char *) fp->_IO_read_ptr++;
    }
  if (_IO_have_markers (fp))
    {
      if (save_for_backup (fp, fp->_IO_read_end))
	return EOF;
    }
  else if (_IO_have_backup (fp))
    _IO_free_backup_area (fp);
  return _IO_UFLOW (fp);
}
```
前面的操作在干啥我也不太清楚，但是最终调用了`return _IO_UFLOW (fp);`
`#define _IO_UFLOW(FP) JUMP0 (__uflow, FP)`
`#define JUMP0(FUNC, THIS) (_IO_JUMPS_FUNC(THIS)->FUNC) (THIS)`
宏特别多，这些宏都是一套套一套，只说下最后的功能是：在其对应的vtable中调用了 __uflow。不太清楚这个 __uflow是啥，于是动态调试一波:
以stdin为例：
```
pwndbg> p _IO_2_1_stdin_ 
$7 = {
  file = {
    _flags = -72540024, 
    _IO_read_ptr = 0x0, 
    _IO_read_end = 0x0, 
    _IO_read_base = 0x0, 
    _IO_write_base = 0x0, 
    _IO_write_ptr = 0x0, 
    _IO_write_end = 0x0, 
    _IO_buf_base = 0x0, 
    _IO_buf_end = 0x0, 
    _IO_save_base = 0x0, 
    _IO_backup_base = 0x0, 
    _IO_save_end = 0x0, 
    _markers = 0x0, 
    _chain = 0x0, 
    _fileno = 0, 
    _flags2 = 0, 
    _old_offset = -1, 
    _cur_column = 0, 
    _vtable_offset = 0 '\000', 
    _shortbuf = "", 
    _lock = 0x7ffff7dd3790 <_IO_stdfile_0_lock>, 
    _offset = -1, 
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dd19c0 <_IO_wide_data_0>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0, 
    _mode = 0, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
```
vtable是_IO_file_jumps,

他里面的内容是
```
pwndbg> p _IO_file_jumps
$6 = {
  __dummy = 0, 
  __dummy2 = 0, 
  __finish = 0x7ffff7a869c0 <_IO_new_file_finish>, 
  __overflow = 0x7ffff7a87730 <_IO_new_file_overflow>, 
  __underflow = 0x7ffff7a874a0 <_IO_new_file_underflow>, 
  __uflow = 0x7ffff7a88600 <__GI__IO_default_uflow>, 
  __pbackfail = 0x7ffff7a89980 <__GI__IO_default_pbackfail>, 
  __xsputn = 0x7ffff7a861e0 <_IO_new_file_xsputn>, 
  __xsgetn = 0x7ffff7a85ec0 <__GI__IO_file_xsgetn>, 
  __seekoff = 0x7ffff7a854c0 <_IO_new_file_seekoff>, 
  __seekpos = 0x7ffff7a88a00 <_IO_default_seekpos>, 
  __setbuf = 0x7ffff7a85430 <_IO_new_file_setbuf>, 
  __sync = 0x7ffff7a85370 <_IO_new_file_sync>, 
  __doallocate = 0x7ffff7a7a180 <__GI__IO_file_doallocate>, 
  __read = 0x7ffff7a861a0 <__GI__IO_file_read>, 
  __write = 0x7ffff7a85b70 <_IO_new_file_write>, 
  __seek = 0x7ffff7a85970 <__GI__IO_file_seek>, 
  __close = 0x7ffff7a85340 <__GI__IO_file_close>, 
  __stat = 0x7ffff7a85b60 <__GI__IO_file_stat>, 
  __showmanyc = 0x7ffff7a89af0 <_IO_default_showmanyc>, 
  __imbue = 0x7ffff7a89b00 <_IO_default_imbue>
}
```
所以最终调用的函数其实是:`__GI__IO_default_uflow.`

看下他的定义:
```
int
_IO_default_uflow (_IO_FILE *fp)
{
  int ch = _IO_UNDERFLOW (fp);
  if (ch == EOF)
    return EOF;
  return *(unsigned char *) fp->_IO_read_ptr++;
}
```
他又调用了`_IO_UNDERFLOW (fp)`

`#define _IO_UNDERFLOW(FP) JUMP0 (__underflow, FP)`

同理，这个是调用了`_IO_new_file_underflow`
追了这么久，这个函数就是最底层的操作了，用来读取你的键盘输入.
看下他的定义：
```
int
_IO_new_file_underflow (_IO_FILE *fp) //最底层的输入操作
{
  _IO_ssize_t count;
#if 0
  /* SysV does not make this test; take it out for compatibility */
  if (fp->_flags & _IO_EOF_SEEN)
    return (EOF);
#endif

  if (fp->_flags & _IO_NO_READS)
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }

  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_IO_save_base != NULL)
	{
	  free (fp->_IO_save_base);
	  fp->_flags &= ~_IO_IN_BACKUP;
	}
      _IO_doallocbuf (fp);
    }

  /* Flush all line buffered files before reading. */
  /* FIXME This can/should be moved to genops ?? */
  if (fp->_flags & (_IO_LINE_BUF|_IO_UNBUFFERED))
    {
#if 0
      _IO_flush_all_linebuffered ();
#else
      /* We used to flush all line-buffered stream.  This really isn't
	 required by any standard.  My recollection is that
	 traditional Unix systems did this for stdout.  stderr better
	 not be line buffered.  So we do just that here
	 explicitly.  --drepper */
      _IO_acquire_lock (_IO_stdout);

      if ((_IO_stdout->_flags & (_IO_LINKED | _IO_NO_WRITES | _IO_LINE_BUF))
	  == (_IO_LINKED | _IO_LINE_BUF))
	_IO_OVERFLOW (_IO_stdout, EOF);

      _IO_release_lock (_IO_stdout);
#endif
    }

  _IO_switch_to_get_mode (fp);

  /* This is very tricky. We have to adjust those
     pointers before we call _IO_SYSREAD () since
     we may longjump () out while waiting for
     input. Those pointers may be screwed up. H.J. */
  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end //都等于了_IO_buf_base
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base); //从这里知道 _IO_buf_base是读入起始位置，_IO_buf_end是结束位置。
  if (count <= 0) //读入时出错
    {
      if (count == 0)
	fp->_flags |= _IO_EOF_SEEN;
      else
	fp->_flags |= _IO_ERR_SEEN, count = 0;
  }
  fp->_IO_read_end += count;
  if (count == 0)
    {
      /* If a stream is read to EOF, the calling application may switch active
	 handles.  As a result, our offset cache would no longer be valid, so
	 unset it.  */
      fp->_offset = _IO_pos_BAD;
      return EOF;
    }
  if (fp->_offset != _IO_pos_BAD)
    _IO_pos_adjust (fp->_offset, count);
  return *(unsigned char *) fp->_IO_read_ptr;
}
```
关键看这些
```
   ....

  if (fp->_IO_read_ptr < fp->_IO_read_end)//需要绕过
    return *(unsigned char *) fp->_IO_read_ptr;

   ....
	fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
    fp->_IO_read_end = fp->_IO_buf_base;
    fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end //都等于了_IO_buf_base
    = fp->_IO_buf_base;
  	count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base); //从这里知道 _IO_buf_base是读入起始位置，_IO_buf_end是结束位置。
	fp->_IO_read_end += count;
   
```
这里的_IO_SYSREAD最终会调用read，从你的键盘读入数据。且_IO_read_ptr等于了_IO_buf_base,_IO_read_end等于了_IO_buf_base+count.再次调用getchar时又可以读取正常读取缓冲区了。从这里可以知道，如果控制了_IO_buf_base，就可以造成任意写的能力。

总结一下：getchar函数会先判断是否已经读完了输入缓冲区（_IO_read_ptr>=_IO_read_end？？？),如果输入缓冲区还没有读完，则返回_IO_read_ptr指向的一字节内容，并自增1，如果输入缓冲区已经读完了，则最终调用_IO_new_file_underflow 重新进行读取，填充缓冲区，并调整_IO_read_ptr和_IO_read_end指针的位置。

##### 利用手法：
修改stdin结构体：
覆盖 stdin 里的_IO_read_ptr和_IO_read_end，使_IO_read_ptr>= _IO_read_end，以绕过:
``` 
if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;
```
修改_IO_buf_base为你想写入的位置，_IO_buf_end为你想写入的位置的末尾即可。

#### putchar：
```
int
putchar (int c)
{
  int result;
  _IO_acquire_lock (_IO_stdout);
  result = _IO_putc_unlocked (c, _IO_stdout);
  _IO_release_lock (_IO_stdout);
  return result;
}
```
和getchar很像，调用了_IO_putc_unlocked，
其定义如下:
```
#define _IO_putc_unlocked(_ch, _fp) \
   (_IO_BE ((_fp)->_IO_write_ptr >= (_fp)->_IO_write_end, 0) \
    ? __overflow (_fp, (unsigned char) (_ch)) \
    : (unsigned char) (*(_fp)->_IO_write_ptr++ = (_ch)))
```
如果_IO_write_ptr>=_IO_write_end说明缓冲区已满，需要调用__overflow来刷新缓冲区，将缓冲区的内容写入文件中，否者_IO_write_ptr指向的内容=ch，然后_IO_write_ptr自增1.
__oveflow函数最终调用了_IO_new_file_overflow，其定义如下:
```
int
_IO_new_file_overflow (_IO_FILE *f, int ch) //底层输出操作，这里的输出指的是向fd指向的文件写入，如果是stdout，即是向终端输出。
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */ //绕过
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)//可能影响_IO_write_base,ptr的值，绕过一下
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
      	{
	         _IO_doallocbuf (f);
	         _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
      	}
      if (__glibc_unlikely (_IO_in_backup (f)))
	    {
	      size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	      _IO_free_backup_area (f);
	      f->_IO_read_base -= MIN (nbackup,f->_IO_read_base - f->_IO_buf_base);
	      f->_IO_read_ptr = f->_IO_read_base;
	    }

      if (f->_IO_read_ptr == f->_IO_buf_end)
	        f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;

          f->_IO_write_ptr = f->_IO_read_ptr;
          f->_IO_write_base = f->_IO_write_ptr;
          f->_IO_write_end = f->_IO_buf_end;
          f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	        f->_IO_write_end = f->_IO_write_ptr;
    }
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base , f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full 缓冲区满了，需要刷新缓冲区，将缓冲区内容真正写入文件中*/
    if (_IO_do_flush (f) == EOF) 
      return EOF;
  *f->_IO_write_ptr++ = ch; 
  if ((f->_flags & _IO_UNBUFFERED) || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base , f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
```
如果ch==EOF会调用_IO_do_write函数，如果_IO_write_ptr == _IO_buf_end ，则说明缓冲区已满，调用_IO_do_flush来刷新缓冲区.
其实_IO_do_flush也是调用了_IO_do_write:
```
# define _IO_do_flush(_f) \
  _IO_do_write(_f, (_f)->_IO_write_base,				      \
	       (_f)->_IO_write_ptr-(_f)->_IO_write_base)
```
_IO_do_write调用了new_do_write,其定义如下:
```
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    /*在没有正确实现O_APPEND的系统上，
    你需要在此处使用sys_seek（0，SEEK_END），
    但对于类Unix或Posix类系统而言，这不是必需的，也不需要。*/
    fp->_offset = _IO_pos_BAD;// -1
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);//???不清楚原因
      //define SEEK_CUR 1,以目前的读写位置往后增加offset个位移量.
      if (new_pos == _IO_pos_BAD)
	        return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);//将缓冲区的内容真正写入设备中
  //最终调用了write()，它完成的操作是将用户缓冲区的文件内容写入到文件中
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
		       && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
		       ? fp->_IO_buf_base : fp->_O_buf_end);
  return count;
}
```
该函数最后调用了write函数，将缓冲区的内容输出到文件中。
最初时write_ptr = write_base , 向缓冲区写入东西时，write_ptr指针的值增大，当将缓冲区的内容写入文件中时，是从_IO_write_base指向的内容开始写入到文件，到_IO_write_ptr结束。

##### 利用手法：

修改stdout结构体：
绕过一下检查:
```
if (f->_flags & _IO_NO_WRITES) /* SET ERROR */ //绕过他
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
 if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)//绕过他
   ........
```
，设置flags位绕过检查:
```
flags=flags&~_IO_NO_WRITES
flags=flags|_IO_CURRENTLY_PUTTING
```
```
#define _IO_NO_WRITES 8，
#define _IO_CURRENTLY_PUTTING 0x800
```
设置_IO_write_base为想要泄露的起始地址，_IO_write_ptr为想要泄露的结束地址即可，这样就可以达到任意读。

#### puts函数：

```
int
_IO_puts (const char *str)
{
  int result = EOF;
  _IO_size_t len = strlen (str);
  _IO_acquire_lock (_IO_stdout);

  if ((_IO_vtable_offset (_IO_stdout) != 0
       || _IO_fwide (_IO_stdout, -1) == -1)
      && _IO_sputn (_IO_stdout, str, len) == len
      && _IO_putc_unlocked ('\n', _IO_stdout) != EOF)
    result = MIN (INT_MAX, len + 1);

  _IO_release_lock (_IO_stdout);
  return result;
}
```
puts函数是打印str里的内容，顺面在末尾加个\n,_IO_putc_unlocked之前已经分析过了，这里分析下_IO_sputn , _IO_sputn其实是调用了_IO_new_file_xsputn:

```
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))//绕过
    {
      count = f->_IO_buf_end - f->_IO_write_ptr;
      if (count >= n)
	    {
	      const char *p;
	      for (p = s + n; p > s; ) //s是data首地址
	        {
	            if (*--p == '\n')
		            {
		                count = p - s + 1;
		                must_flush = 1;
		                break;
		            }
	        }
	    }
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /*缓冲区没有满，计算还剩多少空间*/

  /*将即将输出的内容复制到缓冲区里*/
  if (count > 0)
    {
      if (count > to_do)
	      count = to_do;
#ifdef _LIBC
      f->_IO_write_ptr = __mempcpy (f->_IO_write_ptr, s, count);
#else
      memcpy (f->_IO_write_ptr, s, count);//从_IO_write_ptr开始复制
      f->_IO_write_ptr += count;//此时_IO_write_ptr 等于 _IO_write_end
#endif
      s += count; //s指向还没有复制的位置
      to_do -= count;//剩下需要输出的字符的个数
    }
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)//调用了_IO_new_file_overflow刷新输出缓冲区
	/* If nothing else has to be written we must not signal the
	   caller that everything has been written.  */
	        return to_do == 0 ? EOF : n - to_do;

      /* Try to maintain alignment: write a whole number of blocks.  */
      block_size = f->_IO_buf_end - f->_IO_buf_base;
      do_write = to_do - (block_size >= 128 ? to_do % block_size : 0);

      if (do_write)
	    {
	      count = new_do_write (f, s, do_write);
	      to_do -= count;
	      if (count < do_write)
	        return n - to_do;
	    }

      /* Now write out the remainder.  Normally, this will fit in the
	 buffer, but it's somewhat messier for line-buffered files,
	 so we let _IO_default_xsputn handle the general case. */
      if (to_do)
	        to_do -= _IO_default_xsputn (f, s+do_write, to_do);
    }
  return n - to_do;
}
```

如果输出缓冲区没有满，_IO_new_file_xsputn函数会先把将要输出的字符串复制到输出缓冲区中：
```
 ....
 else if (f->_IO_write_end > f->_IO_write_ptr)
    count = f->_IO_write_end - f->_IO_write_ptr; /*缓冲区没有满，计算还剩多少空间*/
 ....
memcpy (f->_IO_write_ptr, s, count);//从_IO_write_ptr开始复制
      f->_IO_write_ptr += count;//此时_IO_write_ptr 等于 _IO_write_end
```
然后再调用`_IO_OVERFLOW (f, EOF)`来刷新输出缓冲区。_IO_OVERFLOW就是_IO_new_file_overflow，在前面已经分析过了。
由于ch == EOF，会直接执行以下语句:
```
 if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base , f->_IO_write_ptr - f->_IO_write_base);
```

可以看出，_IO_new_file_xsputn函数完成了两个功能，当输出缓冲区还没有满时，会将即将打印的字符串复制到输出缓冲区中，填满输出缓冲区。然后调用_IO_new_file_overflow刷新输出缓冲区。所以_IO_new_file_xsputn函数即能达到任意写的功能，还可以达到任意读的功能。

##### 利用手法：

**任意写：**

提前准备好想要覆写的字符串，
修改stdout结构体：
设置flags绕过:
```
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))//绕过
```
```
#define _IO_LINE_BUF 0x200
#define _IO_CURRENTLY_PUTTING 0x800
```
然后设置_IO_write_ptr为想要写的起始地址，_IO_write_end为想要写的末尾地址即可。

**任意读:**

任意读需要先绕过前面的复制字符串操作(因为会覆盖想要泄露的内容)：
```
    count = f->_IO_write_end - f->_IO_write_ptr; /*缓冲区没有满，计算还剩多少空间*/

  /*将即将输出的内容复制到缓冲区里*/
  if (count > 0)
    {
        ....
      memcpy (f->_IO_write_ptr, s, count);//从_IO_write_ptr开始复制
      f->_IO_write_ptr += count;//此时_IO_write_ptr 等于 _IO_write_end
        ....
    }
```
只需要`f->_IO_write_end - f->_IO_write_ptr = 0` 即可绕过，
然后设置_IO_write_base为想要泄露的地址，_IO_write_ptr为想要泄露的末尾地址即可。

### 总结：

c语言_IO_缓冲区的思想是：
如果是从文件读，就先从文件读入数据填充输入缓冲区，让程序慢慢用，用完了再读入。
如果是向文件写，就先把想要写的内容写入输出缓冲区，等输出缓冲区满了，再一次性的写入文件中。
通过跟输入有关的函数(scanf等)只能达到任意写的目的，需要修改stdin结构体里的_IO_buf_base为想要修改的位置的起始地址，_IO_buf_end为想要修改的位置的末地址即可。
通过跟输出有关的函数(puts等)可以达到任意读写的目标，需要修改stdout结构体里的_IO_write_base,_IO_write_end指针。










