def XORfn(hex_str, k):
    byte_str = bytes.fromhex(hex_str)
    return bytes([b ^ k for b in byte_str])

with open("4.txt", 'r') as file:
        lines = file.readlines()
        for line in lines:
            encoded = line.strip()
            print(f"----- ENCODED = {encoded} ------")
            for i in range(255):
                try:
                    print(f"key: {[chr(i), i]}\tunXOR-ed: {XORfn(encoded, i).decode('utf-8')}")
                except:
                    pass

