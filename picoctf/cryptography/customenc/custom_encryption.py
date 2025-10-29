from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(plaintext, key):
    cipher = []
    for char in plaintext:
        cipher.append(((ord(char) * key*311)))
    return cipher


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key): # basically xorring key and plain
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text

# ---------MYADDITION-----------
def dynamic_xor_decrypt(cipher, text_key):
    plaintxt = ""
    key_length = len(text_key)
    for i, char in enumerate(cipher):
        key_char = text_key[i % key_length]
        decrypted_char = chr(ord(char) ^ ord(key_char))
        plaintxt += decrypted_char
    return plaintxt[::-1]



def test(plain_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g): # p and g are 2 primes
        print("Enter prime numbers")
        return
    a = randint(p-10, p)
    b = randint(g-10, g)
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p) # g^a % p
    v = generator(g, b, p) # g^b % p
    key = generator(v, a, p) # v^a % p
    b_key = generator(u, b, p) # u^b % p
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key);
    cipher = encrypt(semi_cipher, shared_key)
    print(f'cipher is: {cipher}')
    return cipher

# ---------MYADDITION-----------
def decode(cipher, a, b, text_key):
    # for the question the value of a, b is given from which we can find out the value of g and p as we know g and p will be numbers greater than a and b by a maximum of 10 and prime
    ps = [] # possible vals of p
    gs = [] # possible vals of g
    for i in range(a, a+11):
        if(is_prime(i)):
            ps.append(i)
    for i in range(b, b+11):
        if(is_prime(i)):
            gs.append(i)
    print(ps, gs);
    for p in ps:
        for g in gs:
            # for each combination of p and g we decode the cipher
            u = generator(g, a, p) # g^a % p
            v = generator(g, b, p) # g^b % p
            key = generator(v, a, p) # v^a % p
            b_key = generator(u, b, p) # u^b % p
            shared_key = None
            if key == b_key:
                shared_key = key
            else:
                print("Invalid key")
                return
            print(f'shared key is: {shared_key}')
            # decryption
            semi_cipher = ""
            for c in cipher:
                charcode = c // shared_key;
                charcode = charcode // 311;
                semi_cipher = semi_cipher + chr(int(charcode))
            # de-xor
            plaintxt = dynamic_xor_decrypt(semi_cipher, text_key); # both encryption and decryption remains same for XOR
            print(plaintxt)

if __name__ == "__main__":
    # message = sys.argv[1]
    # cipher = test(message, "trudeau") # trudeau is the text key
    # ---------MYADDITION-----------
    # ab = eval(input("list [a, b]: "))
    # -- chall input
    cipher = [33588, 276168, 261240, 302292, 343344, 328416, 242580, 85836, 82104, 156744, 0, 309756, 78372, 18660, 253776, 0, 82104, 320952, 3732, 231384, 89568, 100764, 22392, 22392, 63444, 22392, 97032, 190332, 119424, 182868, 97032, 26124, 44784, 63444]
    ab = [89, 27]
    decode(cipher, ab[0], ab[1], "trudeau") 

