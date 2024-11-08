from z3 import *


# Initialize Z3 solver
solver = Solver()

# 0x01A80000 = (0x35 << 0x13) | (0x35 >> 0x0D) & 0xFFFFFFFF 
# 0x01A80000 + 0x36 = 0x01A80036
# 0x01B00D40 = ((0x01A80036 << 0x13)) | (0x01A80036 >> 0x0D) & 0xFFFFFFFF
# 0x01B00D40 + 0x37 = 0x01B00D77
# 0x6BB80D80 = ((0x01B00D77 << 0x13) | (0x01B00D77 >> 0x0D)) & 0xFFFFFFFF
# 0x6BB80DB8 = 0x6BB80D80 + 0x38
# 0x6BB80DB8 = 0x6BB80DB8 & 0xFFFFFFFF
# IF 0x8B681D82 == 0x6BB80DB8


def solve():
    result = ((flag_input[0] << 0x13) | (flag_input[0] >> 0x0D)) & 0xFFFFFFFF
    result += flag_input[1]
    result = ((result << 0x13) | (result >> 0x0D)) & 0xFFFFFFFF
    result += flag_input[2]
    result = ((result << 0x13) | (result >> 0x0D)) & 0xFFFFFFFF
    result += flag_input[3]
    return (result & 0xFFFFFFFF)

def check(fi):
    print(f"[*] Checking: {fi}")
    result = ((fi[0] << 0x13) | (fi[0] >> 0x0D)) & 0xFFFFFFFF
    result += fi[1]
    result = ((result << 0x13) | (result >> 0x0D)) & 0xFFFFFFFF
    result += fi[2]
    result = ((result << 0x13) | (result >> 0x0D)) & 0xFFFFFFFF
    result += fi[3]
    print(f"[*] Found: {hex(result & 0xFFFFFFFF)}")
    return (result & 0xFFFFFFFF)



# print("[*] Setting up solver constraints...")
flag_input = Array('flag_input', BitVecSort(8), BitVecSort(32))
for i in range(0,4):
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
solver.add(solve() == 0x8B681D82)



print("[*] Cracking...")
if solver.check() == sat:
  # Print the satisfying input array
  # print("[+] Satisfying input array:")
  model = solver.model()
  s = ""
  for i in range(0,4):
    value = model.eval(flag_input[i])
    # print(value)
    s += chr(int(value.as_string()))
    # s += chr(value.as_long() & 0xff)
  print(f"[+] Satisfying input array: {s}")
  assert(check(s.encode()) == 0x8B681D82)
else:
  print("No solution exists that makes the function output 0.")

