import string
import random
import numpy as np # type: ignore
from collections import Counter

# 1. Caesar Cipher
def caesar_cipher(text, shift, decrypt=False):
    alphabet = string.ascii_uppercase
    result = []
    for char in text.upper():
        if char in alphabet:
            idx = alphabet.index(char)
            idx = (idx - shift) % 26 if decrypt else (idx + shift) % 26
            result.append(alphabet[idx])
        else:
            result.append(char)
    return ''.join(result)

# 2. Random Substitution Cipher
def random_substitution_cipher(text, key=None, decrypt=False):
    alphabet = string.ascii_uppercase
    if key is None:
        shuffled = list(alphabet)
        random.shuffle(shuffled)
        key = dict(zip(alphabet, shuffled))
    inv_key = {v: k for k, v in key.items()}
    mapping = inv_key if decrypt else key
    result = [mapping.get(c, c) for c in text.upper()]
    return ''.join(result), key

# 3. Frequency Analysis
def frequency_analysis(text):
    letters = [c for c in text.upper() if c in string.ascii_uppercase]
    freq = Counter(letters)
    total = sum(freq.values())
    return {ch: count/total for ch, count in freq.items()}

# 4. Affine Cipher
def affine_cipher(text, a, b, decrypt=False):
    m = 26
    def egcd(a, b):
        if b == 0: return (1, 0, a)
        x, y, g = egcd(b, a % b)
        return (y, x - (a // b) * y, g)

    result = []
    for char in text.upper():
        if char in string.ascii_uppercase:
            x = ord(char) - 65
            if decrypt:
                inv = egcd(a, m)[0] % m
                val = inv * (x - b) % m
            else:
                val = (a * x + b) % m
            result.append(chr(val + 65))
        else:
            result.append(char)
    return ''.join(result)

# 5. Hill Cipher (2x2)
def hill_cipher(text, key_matrix, decrypt=False):
    assert key_matrix.shape == (2, 2), "Key matrix must be 2x2"
    m = 26
    def mod_inv(mat):
        det = int(round(np.linalg.det(mat)))
        inv_det = pow(det, -1, m)
        adj = np.array([[mat[1,1], -mat[0,1]], [-mat[1,0], mat[0,0]]])
        return (inv_det * adj) % m

    km = mod_inv(key_matrix) if decrypt else key_matrix
    text = ''.join(c for c in text.upper() if c in string.ascii_uppercase)
    if len(text) % 2:
        text += 'X'

    result = []
    for i in range(0, len(text), 2):
        pair = np.array([[ord(text[i]) - 65], [ord(text[i+1]) - 65]])
        comp = km.dot(pair) % m
        result.extend(chr(int(comp[j,0]) + 65) for j in range(2))
    return ''.join(result)

# 6. Playfair Cipher
def playfair_cipher(text, key, decrypt=False):
    # Build 5x5 table without J
    key_str = ''.join(dict.fromkeys((key + string.ascii_uppercase).upper().replace('J','')))
    table = [list(key_str[i:i+5]) for i in range(0,25,5)]
    def find_pos(c):
        for r,row in enumerate(table):
            if c in row: return r, row.index(c)

    t = ''.join(c for c in text.upper().replace('J','I') if c in string.ascii_uppercase)
    bigrams = []
    i = 0
    while i < len(t):
        a = t[i]
        b = t[i+1] if i+1 < len(t) else 'X'
        if a == b:
            bigrams.append((a,'X'))
            i += 1
        else:
            bigrams.append((a,b))
            i += 2

    result = []
    for a,b in bigrams:
        ra,ca = find_pos(a)
        rb,cb = find_pos(b)
        if ra == rb:
            shift = -1 if decrypt else 1
            result.append(table[ra][(ca+shift)%5])
            result.append(table[rb][(cb+shift)%5])
        elif ca == cb:
            shift = -1 if decrypt else 1
            result.append(table[(ra+shift)%5][ca])
            result.append(table[(rb+shift)%5][cb])
        else:
            result.append(table[ra][cb])
            result.append(table[rb][ca])
    return ''.join(result)

# 7. Vigenere Cipher
def vigenere_cipher(text, key, decrypt=False):
    res = []
    key = key.upper()
    ki = 0
    for c in text.upper():
        if c in string.ascii_uppercase:
            shift = ord(key[ki % len(key)]) - 65
            shift = -shift if decrypt else shift
            res.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            res.append(c)
    return ''.join(res)

# 8. Kasiski Test
def kasiski_test(text, n=3):
    t = ''.join(c for c in text.upper() if c in string.ascii_uppercase)
    distances = []
    for i in range(len(t)-n+1):
        seq = t[i:i+n]
        for j in range(i+1, len(t)-n+1):
            if t[j:j+n] == seq:
                distances.append(j-i)
    from math import gcd
    gcds = [gcd(a,b) for a in distances for b in distances if a < b]
    return Counter(gcds)

# 9. Probable Word Method
def probable_word_method(ciphertext, word):
    res = []
    for i in range(len(ciphertext)-len(word)+1):
        seg = ciphertext[i:i+len(word)]
        shifts = [(ord(s)-ord(w)) % 26 for s,w in zip(seg.upper(), word.upper())]
        key_stream = ''.join(chr(s+65) for s in shifts)
        res.append((i, key_stream))
    return res

# 10. One-Time Pad
def one_time_pad(text, key):
    assert len(key) >= len(text), "Key too short"
    res = []
    for p,k in zip(text.upper(), key.upper()):
        if p in string.ascii_uppercase:
            res.append(chr(((ord(p)-65) ^ (ord(k)-65)) + 65))
        else:
            res.append(p)
    return ''.join(res)

# 11. Index of Coincidence
def index_of_coincidence(text):
    t = [c for c in text.upper() if c in string.ascii_uppercase]
    N = len(t)
    if N < 2: return 0
    freqs = Counter(t)
    return sum(f*(f-1) for f in freqs.values()) / (N*(N-1))

# ===================== TESTS =====================
if __name__ == "__main__":
    sample = "HELLO WORLD"
    print("--- Test Chiffre de César ---")
    enc = caesar_cipher(sample, 3)
    dec = caesar_cipher(enc, 3, decrypt=True)
    print(f"Clear : {sample}")
    print(f"Enc   : {enc}")
    print(f"Dec   : {dec}\n")

    print("--- Test Substitution Aléatoire ---")
    text, key = random_substitution_cipher(sample)
    decrypted, _ = random_substitution_cipher(text, key, decrypt=True)
    print(f"Clair : {sample}")
    print(f"Enc   : {text}")
    print(f"Dec   : {decrypted}")
    print(f"Clé   : {key}\n")

    print("--- Test Analyse des Fréquences ---")
    freq = frequency_analysis(sample)
    for ch, f in freq.items():
        print(f"{ch}: {f:.2f}")
    print()

    print("--- Test Chiffrement Affine ---")
    aff = affine_cipher(sample, 5, 8)
    aff_dec = affine_cipher(aff, 5, 8, decrypt=True)
    print(f"Enc   : {aff}")
    print(f"Dec   : {aff_dec}\n")

    print("--- Test Chiffre de Hill ---")
    km = np.array([[3,3],[2,5]])
    hill = hill_cipher(sample, km)
    hill_dec = hill_cipher(hill, km, decrypt=True)
    print(f"Enc   : {hill}")
    print(f"Dec   : {hill_dec}\n")

    print("--- Test Chiffre de Playfair ---")
    pf = playfair_cipher(sample, "KEYWORD")
    pf_dec = playfair_cipher(pf, "KEYWORD", decrypt=True)
    print(f"Enc   : {pf}")
    print(f"Dec   : {pf_dec}\n")

    print("--- Test Chiffre de Vigenère ---")
    vg = vigenere_cipher(sample, "KEY")
    vg_dec = vigenere_cipher(vg, "KEY", decrypt=True)
    print(f"Enc   : {vg}")
    print(f"Dec   : {vg_dec}\n")

    print("--- Test Kasiski ---")
    ks = kasiski_test("ABCABCABCABC")
    print(ks)
    print()

    print("--- Test Méthode du Mot Probable ---")
    pwm = probable_word_method(vg, "KEY")
    print(pwm)
    print()

    print("--- Test Masque Jetable (OTP) ---")
    otp_key = "XMCKL"
    otp = one_time_pad("HELLO", otp_key)
    otp_dec = one_time_pad(otp, otp_key)
    print(f"Enc   : {otp}")
    print(f"Dec   : {otp_dec}\n")

    print("--- Test Indice de Coïncidence ---")
    ic = index_of_coincidence(sample)
    print(f"Indice de coïncidence: {ic:.4f}")
