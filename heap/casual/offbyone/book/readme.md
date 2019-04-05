offbyone的溢出。
my_read函数中有NULL溢出：
![](https://github.com/Dittozzz/CTF-pwn-writeup/blob/master/%E5%9B%BE%E7%89%87/1.png?raw=true)

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
