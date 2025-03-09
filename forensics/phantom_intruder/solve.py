# made by mel

#using wireshark, i sorted the packets by time
#i then exported this into json, and just printed out the payloads

import json
from base64 import b64decode

data = [
	b64decode(bytes.fromhex(i["_source"]["layers"]["tcp"]["tcp.payload"].replace(":",""))) 
for i in json.loads(open("packets.json","r").read())]

for d in data:
	try:
		print(d.decode("ascii"))
	except:
		pass

#picoCTF{1t_w4snt_th4t_34sy_tbh_4r_966d0bfb}