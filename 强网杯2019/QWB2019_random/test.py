from ctypes import *

libc=CDLL("/lib/x86_64-linux-gnu/libc.so.6")
libc.srand(0)

for i in range(50):
    choice=libc.rand()%4
    if choice == 0:
        print str(i+1)+": add"
    elif choice == 1:
        print str(i+1)+": edit"
    elif choice == 2:
        print str(i+1)+": delete"
    else :
        print str(i+1)+": show"
