**学习过程中，参考了以下博文:**

https://blog.csdn.net/qq_33528164/article/details/79951156   这篇我觉得泄露地址的方法最简便，但是最后无法getshell，我的exp是在他的基础下写的。

https://www.jianshu.com/p/959d4b7b5af1

https://www.jianshu.com/p/95b30d754577

**利用过程：**

利用了offbyone，修改处于inuse状态的chunk的size，造成chunk overlap来泄露地址，注意free的时候会检查下一个chunk的size的prev_inuse位是否为1.然后通过fastbin attack完成攻击。
由于__malloc_hook附近没有可用的fake_size。上述的博文的利用思路是利用fastbin attack先将chunk分配到main_arena里.
方法是利用chunk overlap，将处于fastbin的chunk的fd修改为0x61,再malloc一个size为0x60的chunk，这时fastbin里的内容就会变成0x61，
这样就可以使用fastbin attack，将堆分配到main_arena.
然后修改top_chunk到__malloc_hook附近。再次申请chunk即可得到malloc_hook附近的chunk。但是利用过程出现了很多上述博文没有出现的问题。下面记录下调试过程。

**详细调试过程：**

