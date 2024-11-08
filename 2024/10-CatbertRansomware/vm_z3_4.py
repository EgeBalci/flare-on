from z3 import *


# Initialize Z3 solver
solver = Solver()

# 0x00811D69050C5D1F = 0x811C9DC5 * 0x01000193
# 0x050C5D1F = 0x00811D69050C5D1F % 0x1000000000

# 0x050C5D49 = 0x050C5D1F ^ 0x46 (V)
# 0x050C653B76D9EB = 0x050C5D49 * 0x01000193
# 0x3B76D9EB = 0x050C653B76D9EB % 0x1000000000

# 0x3B76D98C = 0x67 (g) ^ 0x3B76D9EB
# 0x3B773728187764 = 0x3B76D98C * 0x1000193
# 0x28187764 = 0x3B773728187764 % 0x1000000000

# 0x28187754 = 0x30 (0) ^ 0x28187764
# 0x2818B67283D93C = 0x28187754 * 0x1000193
# 0x7283D93C = 0x2818B67283D93C % 0x1000000000

# 0x7283D965 = 0x7283D93C ^ 0x59 (Y)
# 0x72848DAA8F39FF = 0x7283D965 * 0x1000193
# 0xAA8F39FF = 0x72848DAA8F39FF 0x1000000000

# 0xAA8F39BB = 0x44 (D) ^ 0xAA8F39FF
# 0xAA90463A77E161 = 0xAA8F39BB * 0x1000193
# 0x3A77E161 = 0xAA90463A77E161 % 0x1000000000

# 0x3A77E114 = 0x75 (u) ^ 0x3A77E161
# 0x3A783D1EB7527C = 0x3A77E114 * 0x1000193
# 0x1EB7527C = 0x3A783D1EB7527C % 0x1000000000

# 0x1EB75211 = 0x1EB7527C ^ 0x6D (m)
# 0x1EB7826B9630C3 = 0x1EB75211 * 0x1000193
# 0x6B9630C3 = 0x1EB7826B9630C3 % 0x1000000000

# 0x6B963081 = 0x42 (B) ^ 0x6B9630C3
# 0x6B96D9DE6E5B13 = 0x6B963081 * 0x1000193
# 0xDE6E5B13 = 0x6B96D9DE6E5B13 % 0x1000000000

# 0xDE6E5B67 = 0x74 (t) ^ 0xDE6E5B13
# 0xDE6FB98EB9E325 = 0xDE6E5B67 * 0x1000193
# 0x8EB9E325 = 0xDE6FB98EB9E325 % 0x1000000000

# 0x8EB9E370 = 0x55 (U) ^ 0x8EB9E325
# 0x8EBAC41EA10950 = 0x8EB9E370 * 0x1000193
# 0x1EA10950 = 0x8EBAC41EA10950 % 0x1000000000

# 0x1EA10927 = 0x77 (w) ^ 0x1EA10950
# 0x1EA1395E816865 = 0x1EA10927 * 0x1000193
# 0x5E816865 = 0x1EA1395E816865 % 0x1000000000

# 0x5E816815 = 0x70 (p) ^ 0x5E816865
# 0x5E81FCDAB6D90F = 0x5E816815 * 0x1000193
# 0xDAB6D90F = 0x5E81FCDAB6D90F % 0x1000000000

# 0xDAB6D976 = 0x79 (y) ^ 0xDAB6D90F
# 0xDAB831C3D854C2 = 0xDAB6D976 * 0x1000193
# 0xC3D854C2 = 0xDAB831C3D854C2 % 0x1000000000

# 0xC3D854B8 = 0x7A (z) ^ 0xC3D854C2
# 0xC3D989058D5DA8 = 0xC3D854B8 * 0x1000193
# 0x058D5DA8 = C3D989058D5DA8 % 0x1000000000

# 0x058D5DD2 = 0x7A (z) ^ 0x058D5DA8
# 0x58D668F8AB196 = 0x058D5DD2 * 0x1000193
# 0x8F8AB196 = 0x58D668F8AB196 % 0x1000000000

# 0x8F8AB1C0 = 0x56 (V) ^ 0x8F8AB196
# 0x8F8AB1C0 = 0x8F8AB1C0 & 0xFFFFFFFF
# IF 0x31F009D2


def solve():
  result = ((0x811C9DC5 * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[0]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[1]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[2]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[3]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[4]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[5]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[6]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[7]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[8]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[9]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[10]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[11]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[12]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[13]) * 0x01000193) % 0x1000000000)
  result = (((result ^ flag_input[14]) * 0x01000193) % 0x1000000000)
  return (result ^ flag_input[15]) & 0xFFFFFFFF


def check(fi):
  print(f"[*] Checking: {fi}")
  result = ((0x811C9DC5 * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[0]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[1]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[2]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[3]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[4]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[5]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[6]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[7]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[8]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[9]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[10]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[11]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[12]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[13]) * 0x01000193) % 0x1000000000)
  result = (((result ^ fi[14]) * 0x01000193) % 0x1000000000)
  print(f"[*] Found: {hex((result ^ fi[15]) & 0xFFFFFFFF)}")
  return (result ^ fi[15]) & 0xFFFFFFFF




print("[*] Setting up solver constraints...")
flag_input = Array('flag_input', BitVecSort(8), BitVecSort(32))
for i in range(0,16):
  solver.add(flag_input[i] >= 32)
  solver.add(flag_input[i] <= 126)
  # solver.add(flag_input[i] != ord("}"))
  # solver.add(flag_input[i] != ord("~"))
  # solver.add(flag_input[i] != ord("["))
  # solver.add(flag_input[i] != ord(" "))
  # solver.add(flag_input[i] != ord("\""))
  # solver.add(flag_input[i] != ord("#"))
  # solver.add(flag_input[i] != ord("%"))
  # solver.add(flag_input[i] != ord("$"))
  # solver.add(flag_input[i] != ord("!"))
  # solver.add(flag_input[i] != ord("&"))

# solver.add(decode() == 0x8AE981A5)
# solver.add(decode() == 0x80076040)
solver.add(solve() == 0x31F009D2)



print("[*] Cracking...")
if solver.check() == sat:
  # Print the satisfying input array
  # print("[+] Satisfying input array:")
  model = solver.model()
  s = ""
  for i in range(0,16):
    value = model.eval(flag_input[i])
    # print(value)
    s += chr(int(value.as_string()))
    # s += chr(value.as_long() & 0xff)
  print(f"[+] Satisfying input array: {s}")
  assert(check(s.encode()) == 0x31F009D2)
else:
  print("No solution exists that makes the function output 0.")
