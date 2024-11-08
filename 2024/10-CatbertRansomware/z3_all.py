from z3 import *


# dword_71580 =  [0x00, 0x4C11DB7, 0x9823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD, 0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0x0BE2B5B58, 0x0BAEA46EF, 0x0B7A96036, 0x0B3687D81, 0x0AD2F2D84, 0x0A9EE3033, 0x0A4AD16EA, 0x0A06C0B5D, 0x0D4326D90, 0x0D0F37027, 0x0DDB056FE, 0x0D9714B49, 0x0C7361B4C, 0x0C3F706FB, 0x0CEB42022, 0x0CA753D95, 0x0F23A8028, 0x0F6FB9D9F, 0x0FBB8BB46, 0x0FF79A6F1, 0x0E13EF6F4, 0x0E5FFEB43, 0x0E8BCCD9A, 0x0EC7DD02D, 0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x18AEB13, 0x54BF6A4, 0x808D07D, 0x0CC9CDCA, 0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA, 0x0ACA5C697, 0x0A864DB20, 0x0A527FDF9, 0x0A1E6E04E, 0x0BFA1B04B, 0x0BB60ADFC, 0x0B6238B25, 0x0B2E29692, 0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A, 0x0E0B41DE7, 0x0E4750050, 0x0E9362689, 0x0EDF73B3E, 0x0F3B06B3B, 0x0F771768C, 0x0FA325055, 0x0FEF34DE2, 0x0C6BCF05F, 0x0C27DEDE8, 0x0CF3ECB31, 0x0CBFFD686, 0x0D5B88683, 0x0D1799B34, 0x0DC3ABDED, 0x0D8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB, 0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B, 0x315D626, 0x7D4CB91, 0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0x0F12F560E, 0x0F5EE4BB9, 0x0F8AD6D60, 0x0FC6C70D7, 0x0E22B20D2, 0x0E6EA3D65, 0x0EBA91BBC, 0x0EF68060B, 0x0D727BBB6, 0x0D3E6A601, 0x0DEA580D8, 0x0DA649D6F, 0x0C423CD6A, 0x0C0E2D0DD, 0x0CDA1F604, 0x0C960EBB3, 0x0BD3E8D7E, 0x0B9FF90C9, 0x0B4BCB610, 0x0B07DABA7, 0x0AE3AFBA2, 0x0AAFBE615, 0x0A7B8C0CC, 0x0A379DD7B, 0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30, 0x29F3D35, 0x65E2082, 0x0B1D065B, 0x0FDC1BEC, 0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0x0C5A92679, 0x0C1683BCE, 0x0CC2B1D17, 0x0C8EA00A0, 0x0D6AD50A5, 0x0D26C4D12, 0x0DF2F6BCB, 0x0DBEE767C, 0x0E3A1CBC1, 0x0E760D676, 0x0EA23F0AF, 0x0EEE2ED18, 0x0F0A5BD1D, 0x0F464A0AA, 0x0F9278673, 0x0FDE69BC4, 0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C, 0x0AFB010B1, 0x0AB710D06, 0x0A6322BDF, 0x0A2F33668, 0x0BCB4666D, 0x0B8757BDA, 0x0B5365D03, 0x0B1F740B4]



# Initialize Z3 solver
solver = Solver()


# print("[*] Filling map...")
# dword_71580_z3 = Array('dword_71580_z3', BitVecSort(32), BitVecSort(32))
# for i in range(0,256):
#   solver.add(dword_71580_z3[i] == dword_71580[i])

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


def stage_1():
    v1 = flag_input[0] + 0x02B5A5
    v2 = v1 << 0x05
    v2 += v1
    v2 += flag_input[1]
    v3 = v2 << 0x05 
    v3 += v2 
    v3 += flag_input[2]
    v4 = v3 << 0x05
    v4 += v3
    v4 += flag_input[3]
    v4 = v4 & 0xFFFFFFFF
    return v4

def stage_2():
    result = ((flag_input[4] << 0x13) | (flag_input[0] >> 0x0D)) & 0xFFFFFFFF
    result += flag_input[5]
    result = ((result << 0x13) | (result >> 0x0D)) & 0xFFFFFFFF
    result += flag_input[6]
    result = ((result << 0x13) | (result >> 0x0D)) & 0xFFFFFFFF
    result += flag_input[7]
    return (result & 0xFFFFFFFF)


def stage_3():
    v1 = ((flag_input[8] + 0x01) % 0xFFF1)
    # print(f"v1 = {hex(v1)}")
    v2 = (((flag_input[9] + v1)) % 0xFFF1)
    # print(f"v2 = {hex(v2)}")
    v3 = ((v1 + v2) % 0xFFF1)
    # print(f"v3 = {hex(v3)}")
    v4 = ((flag_input[10] + v2) % 0xFFF1)
    # print(f"v4 = {hex(v4)}")
    v5 = ((v4 + v3) % 0xFFF1)
    # print(f"v5 = {hex(v5)}")
    v6 = ((flag_input[11] + v4) % 0xFFF1)
    # print(f"v6 = {hex(v6)}")
    v7 = ((v6 + v5) % 0xFFF1)
    # print(f"v7 = {hex(v7)}")
    v8 = ((flag_input[12] + v6) % 0xFFF1)
    # print(f"v8 = {hex(v8)}")
    v9 = ((v8 + v7) % 0xFFF1)
    # print(f"v9 = {hex(v9)}")
    v10 = ((flag_input[13] + v8) % 0xFFF1)
    # print(f"v10 = {hex(v10)}")
    v11 = ((v10 + v9) % 0xFFF1)
    # print(f"v11 = {hex(v11)}")
    v12 = ((flag_input[14] + v10) % 0xFFF1)
    # print(f"v12 = {hex(v12)}")
    v13 = ((v12 + v11) % 0xFFF1)
    # print(f"v13 = {hex(v13)}")
    v14 = ((flag_input[15] + v12) % 0xFFF1)
    # print(f"v14 = {hex(v14)}")
    v15 = ((v14 + v13) % 0xFFF1)
    # print(f"v15 = {hex(v15)}")
    return ((v15 << 0x10) | v14) & 0xFFFFFFFF

def stage_4():
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


# def stage_5():
#   result = 0xFFFFFFFF
#   for i in range(0,16):
#     result = (dword_71580_z3[flag_input[i]  ^ ((result >> 24) & 0xFFFFFFFFFFFFFFFF)] ^ ((result << 8) & 0xFFFFFFFF)) & 0xFFFFFFFF
#   return result



print("[*] Setting up solver constraints...")
flag_input = Array('flag_input', BitVecSort(32), BitVecSort(32))
for i in range(0,16):
  solver.add(flag_input[i] >= 32)
  solver.add(flag_input[i] <= 126)
  # solver.add(flag_input[i] != ord("`"))
  # solver.add(flag_input[i] != ord("{"))
  # solver.add(flag_input[i] != ord("^"))
  # solver.add(flag_input[i] != ord("%"))
  # solver.add(flag_input[i] != ord("}"))
  # solver.add(flag_input[i] != ord("~"))
  # solver.add(flag_input[i] != ord("["))
  # solver.add(flag_input[i] != ord(" "))
  # solver.add(flag_input[i] != ord("\""))
  # solver.add(flag_input[i] != ord("#"))
  # solver.add(flag_input[i] != ord("$"))
  # solver.add(flag_input[i] != ord("!"))
  # solver.add(flag_input[i] != ord("&"))
  # solver.add(flag_input[i] != ord("|"))


solver.add(stage_1() == 0x7C8DF4CB)
solver.add(stage_2() == 0x8B681D82)
solver.add(stage_3() == 0x0F910374)
solver.add(stage_4() == 0x31F009D2)
# solver.add(stage_5() == 0x80076040)



print("[*] Cracking...")
if solver.check() == sat:
  # Print the satisfying input array
  # print("[+] Satisfying input array:")
  model = solver.model()
  s = ""
  for i in range(0,16):
    value = model.eval(flag_input[i])
    # print(value)
    # s += chr(int(value.as_string()))
    s += chr(value.as_long() & 0xff)
  print(f"[+] Satisfying input array: {s}")
else:
  print("[-] No solution exists!")
