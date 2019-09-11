
A = sys_number
A == 0x101 ? next : allow
A = args[1] 
A == 0x40207e ? dead : allow
allow:
return ALLOW
dead:
return ERRNO(10)