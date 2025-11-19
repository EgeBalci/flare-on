import os

def compare_files(file1, file2):
    """Compare two binary files and return the first differing offset and bytes."""
    with open(file1, "rb") as f1, open(file2, "rb") as f2:
        offset = 0
        while True:
            b1 = f1.read(1)
            b2 = f2.read(1)

            if not b1 and not b2:
                # Both reached EOF, no differences
                return None
            if b1 != b2:
                return offset, b1[0], b2[0]
            offset += 1


diff_table = []


def main():
    og_file=open("/tmp/UnholyDragon-150.exe", "rb")
    og_file_bytes=bytearray(og_file.read())
    
    files = ["UnholyDragon.exe"]
    for i in range(1,151):
        files.append(f"UnholyDragon-{i}.exe")
    files.reverse()

    for i in range(len(files) - 1):
        f1, f2 = files[i], files[i+1]
        print(files[i])
        result = compare_files(f1, f2)
        if result:
            offset, b1, b2 = result
            # print(f"{f1} vs {f2} -> Offset {offset}: {b1.hex()} != {b2.hex()}")
            diff=(b1^b2)
            print(f"{offset:08x}: {diff:02x}")
            print(f"--> {og_file_bytes[offset]:02x}")
            og_file_bytes[offset] ^= diff
            print(f"--> {og_file_bytes[offset]:02x}")

    result=open("og_UnholyDragon.exe", "wb")
    result.write(og_file_bytes)
    result.close()
    print("Done!")
if __name__ == "__main__":
    main()
