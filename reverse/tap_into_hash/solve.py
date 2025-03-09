# made by Mel

#the encrypted data we're provided
key = b"\x1br\t;\x0f\xb5\x9f\xaa\xd1'\xaf\x86[\xf0\xe6\xd9'D\xf9\x8d\x17g\xeb>_gG.\xd4\xc3\xdc\x83"
blockchain = b'o\x14>\xda\x16\xc7\xce\xd784,.\x8f2\x80@cD?\xd3L\x90\x9f\x87l0yy\xdam\x85J1\x139\x88\x10\x95\x9f\x82ke*.\xda>\xd3\x195O?\xd3\x10\xc4\x94\x83kd| \x882\x86IzFk\xd2@\x95\xcd\x83:by{\x8c3\x81\x1e6E8\xdaC\xc2\xcf\xd087||\x8em\xd0\x1c3Cj\xde\x10\xc0\x99\x89;4+{\x8fn\x84\x1abN9\xdc\x16\xc5\xc8\xd0mc}+\x81o\xd7J1[k\xda\x12\x94\xce\x89m3}(\xdbh\x84KeDh\x8fF\x9e\xc9\x84i1.*\x8f2\x87\x1d4\x15+\x83\x17\xc9\xef\xe5Iz*t\xd7h\xd9\'d%\t\x82"\xcf\xfe\xd3[09{\xe0T\xea-=;k\x98@\x9f\xcf\xf9Pp\x0bb\xd5A\xe8\x02\x15=\x04\x8eL\x96\x9f\x86n0ze\x89m\x81A6Bi\x88B\x91\xce\x8279q~\x8d:\x84OfAn\x8fA\x95\xc9\xd76d|}\x95;\x82@oFb\xddE\x93\x98\xd2jdz/\x88h\xd7\x1a6@o\xdd\x12\x94\x94\xd2m`}y\x8c>\x82LaCm\x8f\x10\x9f\x9f\xd3>0py\xde2\x87AoGh\x88\x11\x91\x9a\x84=3z*\xde&\x82Hb@n\xddM\xc3\xce\x89me.(\x808\xd0KaGo\x8bG\x91\x9b\x81?`.|\xde=\xd6@b\x17m\x8e\x11\x9f\x95\x80>d+.\x88>\x80\x1d4\x14m\xdd\x12\x96\xcf\x85m1q-\x8ao\xb0z'

#the token is the flag

from hashlib import sha256
key_hash = sha256(key).digest()

xor = lambda x,y: bytes([a^b for a,b in zip(x,y)])

#it's kinda easy, we know the key, and can figure out the XOR key
#so we just unXOR it
#im surprised how insanely easy this was given the point value :P
for i in range(0,len(blockchain),16):
	print(xor(blockchain[i:i+16], key_hash).decode("ascii"), end="")