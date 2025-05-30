def ksa(key):
    key_length = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % key_length]) % 256
        s[i], s[j] = s[j], s[i]
    return s

def prga(s):
    i = j = 0
    while True:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        yield k

def rc4_verbose(key, plaintext):
    key_bytes = [ord(c) for c in key]
    print(f"Clé ASCII     : {key_bytes}")
    s = ksa(key_bytes)
    
    print("\n--- Début chiffrement RC4 ---")
    print(f"Texte clair    : {plaintext}")
    
    keystream = prga(s)
    ciphertext = ''
    
    print("\nIndex | P(char) | K(byte) | C(char)")
    print("-" * 35)
    
    for i, char in enumerate(plaintext):
        k = next(keystream)
        p_ord = ord(char)
        c_ord = p_ord ^ k
        print(f"{i:5} | {p_ord:7} | {k:7} | {c_ord:7} ({chr(c_ord)})")
        ciphertext += chr(c_ord)
    
    print("\nTexte chiffré  :", ciphertext)
    return ciphertext

def rc4_decrypt_verbose(key, ciphertext):
    print("\n--- Début déchiffrement RC4 ---")
    return rc4_verbose(key, ciphertext)

# ==== Exemple d'utilisation ====
key = "ma_cle_secrete"
plaintext = "Bonjour, ceci est un test."

ciphertext = rc4_verbose(key, plaintext)
decrypted = rc4_decrypt_verbose(key, ciphertext)

print("\nTexte déchiffré :", decrypted)
