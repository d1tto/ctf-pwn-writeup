创建的结构体如下：
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
