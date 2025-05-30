import sys, getopt, hashlib
from math import exp, expm1

ROUNDS = 8
BLOCKSIZE = 8
BLOCKSIZE_BITS = 64
PATH_TO_FILES = "Files/"
SECRET = "3f788083-77d3-4502-9d71-21319f1792b6"

def main(argv):
    decrypt = False
    encrypt = False
    verbose = False  # Add verbose flag

    try:
        opts, args = getopt.getopt(argv, "hdevm:t:k:o:", ["mode=", "ptext=", "key=", "outfile="])

    except getopt.getoptError:
        sys.exit(1)

    if len(sys.argv[1:]) < 6:
        print('Usage: ./feistel.py -[d|e] [-v] -m <mode> -t <inputfile> -k <key> -o <outputfile>')
        print('Options:')
        print('  -d: decrypt mode')
        print('  -e: encrypt mode')
        print('  -v: verbose output')
        print('  -m: mode (ecb or cbc)')
        print('  -t: input file')
        print('  -k: encryption key')
        print('  -o: output file')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print('Usage: ./feistel.py -[d|e] [-v] -m <mode> -t <inputfile> -k <key> -o <outputfile>')
            sys.exit()
        elif opt == "-d":
            decrypt = True
        elif opt == "-e":
            encrypt = True
        elif opt == "-v":
            verbose = True
        elif opt in ("-m", "--mode"):
            mode = str(arg).lower()
        elif opt in ("-t", "--ptext"):
            filename = str(arg)
        elif opt in ("-k", "--key"):
            key = str(arg)
        elif opt in ("-o", "--outfile"):
            outfilename = str(arg)

    if (encrypt and decrypt):
        print("Cannot encrypt AND decrypt")
        sys.exit(1)

    if (mode != "ecb" and mode != "cbc"):
        print ("Unknown cryptographic mode")
        sys.exit(1)


    with open(PATH_TO_FILES + filename, "rb") as f:
        input = f.read().decode('latin1')
        if verbose:
            print("\n=== Input ===")
            print(f"Original message: {input}")

    # call the crypto function
    if (encrypt):
        output = encryptMessage(key, input, mode, verbose)
    elif (decrypt):
        output = decryptCipher(key, input, mode, verbose)

    with open(PATH_TO_FILES + outfilename, 'wb') as fw:
        fw.write(output.encode('latin1'))
        if verbose:
            print(f"\n=== Output ===")
            print(f"{'Encrypted' if encrypt else 'Decrypted'} message written to: {outfilename}")

    # Print the ciphertext

    #print(ciphertext)


def encryptMessage(key, message, mode, verbose=False):
    ciphertext = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block

    # Split message into 64bit blocks
    message = [message[i: i + n] for i in range(0, len(message), n)]

    if verbose:
        print("\n=== Encryption Process ===")
        print(f"Number of blocks: {len(message)}")
        print(f"Block size: {BLOCKSIZE} bytes")
        print(f"Number of rounds: {ROUNDS}")
        print(f"Mode: {mode.upper()}")

    lengthOfLastBlock = len(message[len(message)-1])

    if (lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            message[len(message)-1] += " "

    if verbose:
        print("\nBlocks:")
        for i, block in enumerate(message):
            print(f"Block {i+1}: {repr(block)}")

    # generate a 256 bit key based of user inputted key
    key = key_256(key)
    key_initial = key
    
    if verbose:
        print(f"\nInitial key (SHA-256): {key}")

    for block_num, block in enumerate(message):
        if verbose:
            print(f"\nProcessing Block {block_num + 1}:")

        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[0] = block[0:BLOCKSIZE//2]
        R[0] = block[BLOCKSIZE//2:BLOCKSIZE]

        if verbose:
            print(f"  Initial L[0]: {repr(L[0])}")
            print(f"  Initial R[0]: {repr(R[0])}")

        for i in range(1, ROUNDS+1):
            L[i] = R[i - 1]
            if (mode == "cbc"):
                if (i == 1):
                    key = key_initial
                else:
                    key = subkeygen(L[i], key_initial, i)
                if verbose:
                    print(f"  Round {i} CBC key: {key[:16]}...")

            R[i] = xor(L[i - 1], scramble(R[i - 1], i, key))
            
            if verbose:
                print(f"  Round {i}:")
                print(f"    L[{i}]: {repr(L[i])}")
                print(f"    R[{i}]: {repr(R[i])}")

        ciphertext += (L[ROUNDS] + R[ROUNDS])

    return ciphertext

def decryptCipher(key, ciphertext, mode, verbose=False):
    message = ""
    n = BLOCKSIZE  # 8 bytes (64 bits) per block

    # Split message into 64bit blocks
    ciphertext = [ciphertext[i: i + n] for i in range(0, len(ciphertext), n)]

    if verbose:
        print("\n=== Decryption Process ===")
        print(f"Number of blocks: {len(ciphertext)}")
        print(f"Block size: {BLOCKSIZE} bytes")
        print(f"Number of rounds: {ROUNDS}")
        print(f"Mode: {mode.upper()}")

    lengthOfLastBlock = len(ciphertext[len(ciphertext)-1])

    if (lengthOfLastBlock < BLOCKSIZE):
        for i in range(lengthOfLastBlock, BLOCKSIZE):
            ciphertext[len(ciphertext)-1] += " "

    if verbose:
        print("\nBlocks:")
        for i, block in enumerate(ciphertext):
            print(f"Block {i+1}: {repr(block)}")

    # generate a 256 bit key based off the user inputted key
    key = key_256(key)
    key_initial = key

    if verbose:
        print(f"\nInitial key (SHA-256): {key}")

    for block_num, block in enumerate(ciphertext):
        if verbose:
            print(f"\nProcessing Block {block_num + 1}:")

        L = [""] * (ROUNDS + 1)
        R = [""] * (ROUNDS + 1)
        L[ROUNDS] = block[0:BLOCKSIZE//2]
        R[ROUNDS] = block[BLOCKSIZE//2:BLOCKSIZE]

        if verbose:
            print(f"  Initial L[{ROUNDS}]: {repr(L[ROUNDS])}")
            print(f"  Initial R[{ROUNDS}]: {repr(R[ROUNDS])}")

        for i in range(ROUNDS, 0, -1):
            if (mode == "cbc"):
                key = subkeygen(L[i], key_initial, i)
                if (i == 1):
                    key = key_initial
                if verbose:
                    print(f"  Round {i} CBC key: {key[:16]}...")

            R[i-1] = L[i]
            L[i-1] = xor(R[i], scramble(L[i], i, key))

            if verbose:
                print(f"  Round {i}:")
                print(f"    L[{i-1}]: {repr(L[i-1])}")
                print(f"    R[{i-1}]: {repr(R[i-1])}")

        message += (L[0] + R[0])

    return message


def key_256(key):
    return hashlib.sha256((key + SECRET).encode()).hexdigest()

def subkeygen(s1, s2, i):
    result = hashlib.sha256((s1 + s2).encode()).hexdigest()
    return result

def scramble(x, i, k):
    k = stobin(k)
    x = stobin(str(x))

    k = bintoint(k)
    x = bintoint(x)

    res = pow((x * k), i)
    res = itobin(res)

    return bintostr(res)


# xor two strings
def xor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


# string to binary
def stobin(s):
    return ''.join('{:08b}'.format(ord(c)) for c in s)


# binary to int
def bintoint(s):
    return int(s, 2)


# int to binary
def itobin(i):
    return bin(i)


# binary to string
def bintostr(b):
    n = int(b, 2)
    return ''.join(chr(int(b[i: i + 8], 2)) for i in range(0, len(b), 8))


if __name__ == "__main__":
    main(sys.argv[1:])