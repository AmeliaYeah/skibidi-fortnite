import hashlib
import sys

cheese_hash = "fc0d71ed59417cff291a2db082dc831c389fc9130ea1e6d3977170193f21290c"

with open("cheese_list.txt", "r") as f:
    cheeses = [line.rstrip("\n") for line in f.readlines()] # get each cheese, remove extra newline in case

for cheese in cheeses:
    for cheesestr in [cheese, cheese.lower(), cheese.upper()]: # just try all lowercase and all uppercase in case
        cheesebytes = cheesestr.encode()
        for salt in range(256): # try all possible salt values
            salt_bites = bytes([salt]) # guessin its this cuz other ways didnt work also hint says its two nibbles or a byte
            cheese_salt_possibilities= []

            # to the end
            cheese_salt_possibilities.append(cheesebytes + salt_bites)
            # to the beginning
            cheese_salt_possibilities.append(salt_bites + cheesebytes)
            # every position
            for pos in range(1, len(cheesebytes)):
                cheese_salt_possibilities.append(cheesebytes[:pos] + salt_bites + cheesebytes[pos:])
            for candidate in cheese_salt_possibilities:
                h1 = hashlib.sha256(candidate).hexdigest()
                if h1 == cheese_hash:
                    print("we found a match omg!")
                    print("the cheese!:", cheesestr)
                    print("le salt hex:", format(salt, "02x"))
                    print("data bytes:", candidate)
                    sys.exit(0)
            
    

print("meow :(")