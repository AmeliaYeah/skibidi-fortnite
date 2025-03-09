import sys

def exit():
  sys.exit(0)

def scramble(L):
  A = L
  i = 2
  while (i < len(A)):
    A[i-2] += A.pop(i-1)
    A[i-1].append(A[:i-2])
    i += 1
    
  return L

def hex_enc(flag):
  hex_flag = []
  for c in flag:
    hex_flag.append([str(hex(ord(c)))])

  return hex_flag

j = hex_enc("picoCTF{")
print(scramble(j))
