from pwn import *

# b64e() fn and unhex() fn required

hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

raw_bytes = unhex(hex_str)

b64_str = b64e(raw_bytes)

print(f"hex_str: {hex_str}\nraw_bytes: {raw_bytes}\nb64_str: {b64_str}")

