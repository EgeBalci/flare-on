from z3 import *


# Initialize Z3 solver
solver = Solver()

# 0x42 = ((0x41 + 1) % 0xFFF1)
# 0x42 = 0x42 + 00
# 0x42 = ((0x42) % 0xFFF1)
# 0x84 = 0x42 + 0x42
# 0x84 = ((0x84) % 0xFFF1)
# 0xC6 = 0x84 + 0x42
# 0xC6 = ((0xC6) % 0xFFF1)
# 0xC7 = 0x84 + 0x43 
# 0xC7 = ((0xC7) % 0xFFF1)
# 0x018D = 0xC7 + 0xC6 
# 0x018D = ((0x018D) % 0xFFF1)
# 0x010B = 0x44 + 0xC7
# 0x010B = ((0x010B) % 0xFFF1)
# 0x0298 = 0x010B + 0x018D
# 0x0298 = ((0x0298) % 0xFFF1)
# 0x0150 = 0x010B + 0x45
# 0x0150 = ((0x0150) % 0xFFF1)
# 0x03E8 = 0x0298 + 0x0150
# 0x03E8 = ((0x03E8) % 0xFFF1)
# 0x196 = 0x0150 + 0x46
# 0x196 = ((0x196) % 0xFFF1)
# 0x057E = 0x03E8 + 0x196
# 0x057E = ((0x057E) % 0xFFF1)
# 0x01C6 = 0x196 + 0x30
# 0x01C6 = ((0x01C6) % 0xFFF1)
# 0x0744 = 0x057E + 0x01C6
# 0x0744 = ((0x0744) % 0xFFF1)

# 0x01F7 = 0x01C6 + 0x31
# 0x01F7 = ((0x01F7) % 0xFFF1)

# 0x093B = 0x0744 + 0x01F7
# 0x093B = ((0x093B) % 0xFFF1)

# 0x093B01F7 = ((0x093B << 0x10) | 0x01F7) & 0xFFFFFFFF
# IF 0x0F910374 == 0x093B01F7


def solve():
    v1 = ((flag_input[0] + 0x01) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v1 = {hex(v1)}")
    v2 = (((flag_input[1] + v1)) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v2 = {hex(v2)}")
    v3 = ((v1 + v2) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v3 = {hex(v3)}")
    v4 = ((flag_input[2] + v2) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v4 = {hex(v4)}")
    v5 = ((v4 + v3) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v5 = {hex(v5)}")
    v6 = ((flag_input[3] + v4) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v6 = {hex(v6)}")
    v7 = ((v6 + v5) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v7 = {hex(v7)}")
    v8 = ((flag_input[4] + v6) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v8 = {hex(v8)}")
    v9 = ((v8 + v7) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v9 = {hex(v9)}")
    v10 = ((flag_input[5] + v8) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v10 = {hex(v10)}")
    v11 = ((v10 + v9) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v11 = {hex(v11)}")
    v12 = ((flag_input[6] + v10) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v12 = {hex(v12)}")
    v13 = ((v12 + v11) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v13 = {hex(v13)}")
    v14 = ((flag_input[7] + v12) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v14 = {hex(v14)}")
    v15 = ((v14 + v13) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v15 = {hex(v15)}")
    return ((v15 << 0x10) | v14) & 0xFFFFFFFF

def check(fi):
    print(f"[*] Checking: {fi}")
    v1 = ((fi[0] + 0x01) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v1 = {hex(v1)}")
    v2 = (((fi[1] + v1)) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v2 = {hex(v2)}")
    v3 = ((v1 + v2) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v3 = {hex(v3)}")
    v4 = ((fi[2] + v2) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v4 = {hex(v4)}")
    v5 = ((v4 + v3) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v5 = {hex(v5)}")
    v6 = ((fi[3] + v4) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v6 = {hex(v6)}")
    v7 = ((v6 + v5) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v7 = {hex(v7)}")
    v8 = ((fi[4] + v6) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v8 = {hex(v8)}")
    v9 = ((v8 + v7) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v9 = {hex(v9)}")
    v10 = ((fi[5] + v8) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v10 = {hex(v10)}")
    v11 = ((v10 + v9) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v11 = {hex(v11)}")
    v12 = ((fi[6] + v10) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v12 = {hex(v12)}")
    v13 = ((v12 + v11) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v13 = {hex(v13)}")
    v14 = ((fi[7] + v12) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v14 = {hex(v14)}")
    v15 = ((v14 + v13) % 0xFFF1) & 0xFFFFFFFF
    # print(f"v15 = {hex(v15)}")
    print(f"[*] Found: {hex(((v15 << 0x10) | v14) & 0xFFFFFFFF)}")
    return ((v15 << 0x10) | v14) & 0xFFFFFFFF


print("[*] Setting up solver constraints...")
flag_input = Array('flag_input', BitVecSort(8), BitVecSort(32))
for i in range(0,8):
  solver.add(flag_input[i] >= 32)
  solver.add(flag_input[i] <= 126)
  #solver.add(flag_input[i] != ord("}"))
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
solver.add(solve() == 0x0F910374)



print("[*] Cracking...")
if solver.check() == sat:
  # Print the satisfying input array
  # print("[+] Satisfying input array:")
  model = solver.model()
  s = ""
  for i in range(0,8):
    value = model.eval(flag_input[i])
    # print(value)
    s += chr(int(value.as_string()))
    # s += chr(value.as_long() & 0xff)
  print(f"[+] Satisfying input array: {s}")
  assert(check(s.encode()) == 0x0F910374)
else:
  print("No solution exists that makes the function output 0.")
