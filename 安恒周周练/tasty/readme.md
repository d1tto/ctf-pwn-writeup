堆的题目需要不断的调试，写一点就要调试调试，比如将堆分配到__malloc_hook附近，需要利用错位，就需要gdb挂上去查看内存数据。
记录下思路和调试过程。

UAF , fastbin double free，修改double free chunk 的fd指针，将fastbin分配到__malloc_hook附近，修改__mallo_chook为one_gadget。
由于栈中数据的问题，换了几个one_gadget才成功。
因为malloc的参数限制为128byte以下，不能使用small bin double free 然后unlink。因为合并后的chunk大小远大于0x90 byte.

首先利用UAF，泄露free chunk中保存的fd,bk指针，然后计算出libc base。


