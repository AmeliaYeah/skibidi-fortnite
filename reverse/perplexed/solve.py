#clever as fuck oracle ngl ltrace is such a chad

#bascially, as seen in the check.c file,
#	whenever an iteration in the loop is successful, it does a strlen library call
#	if it's not, it returns prematurely
#	using ltrace, i used the strlen calls as an oracle

#	the main function makes sure that the input is exactly 0x1b long (including newline)
#	so, i bruteforced character by character and tallied up the strlen library calls
#	the highest calls mean the character belongs at that position in the flag
#	and then, we just bruteforce the next character
#	eventually, we get the flag

from string import ascii_letters,digits
from subprocess import run, CalledProcessError, PIPE

charset = ascii_letters+digits+"_{}"

pwd = ""
pwd_len = 0x1b-1 #for newline

def send_payload(payl):
	d = run(f"echo '{payl}' | ltrace ./perplexed | grep strlen", capture_output=True, shell=True)
	return len([s for s in d.stderr.splitlines() if b"strlen" in s])

#the higher strlen calls means the less "return 1" things we get in the loop
while len(pwd) < pwd_len:
	max_calls = (0,None)
	for c in charset:
		#send the data and check the amount of successes
		#(calls to strlen)

		#our payload
		data = pwd+c+"a"*(pwd_len-len(pwd)-1)

		#send it off
		calls = send_payload(data)
		if calls > max_calls[0]:
			max_calls = (calls, c)

	#add the highest call to the flag
	pwd += max_calls[1]
	print(pwd)

print(pwd)