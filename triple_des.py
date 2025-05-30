# Tables pour DES (identiques à l'implémentation précédente)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41, 9, 49, 17, 57, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

SBOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2, S3, ..., S8 (simplifié, utiliser les tables complètes pour une implémentation réelle)
]

P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table):
    """Applique une permutation à un bloc selon une table donnée."""
    return ''.join(block[i - 1] for i in table)

def left_shift(bits, n):
    """Effectue un décalage à gauche de n positions."""
    return bits[n:] + bits[:n]

def generate_subkeys(key):
    """Génère 16 sous-clés à partir d'une clé de 64 bits."""
    key = permute(key, PC1)
    C, D = key[:28], key[28:]
    subkeys = []
    
    for shift in SHIFT_SCHEDULE:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        subkey = permute(C + D, PC2)
        subkeys.append(subkey)
    
    return subkeys

def sbox_substitution(bits):
    """Applique les S-boxes (simplifié pour S1 uniquement)."""
    result = ""
    for i in range(0, 6):
        row = int(bits[0] + bits[5], 2)
        col = int(bits[1:5], 2)
        val = SBOX[0][row][col]
        result += format(val, '04b')
    return result

def f_function(R, subkey):
    """Fonction F : expansion, XOR avec la sous-clé, S-boxes, permutation."""
    expanded = permute(R, E)
    xor_result = ''.join(str(int(a) ^ int(b)) for a, b in zip(expanded, subkey))
    sbox_result = sbox_substitution(xor_result)
    return permute(sbox_result, P)

def des_encrypt(plaintext, key):
    """Chiffre un bloc de 64 bits avec DES."""
    plaintext = ''.join(format(ord(c), '08b') for c in plaintext)[:64].ljust(64, '0')
    key = ''.join(format(ord(c), '08b') for c in key)[:64].ljust(64, '0')
    
    block = permute(plaintext, IP)
    L, R = block[:32], block[32:]
    subkeys = generate_subkeys(key)
    
    for i in range(16):
        temp = R
        R = ''.join(str(int(a) ^ int(b)) for a, b in zip(L, f_function(R, subkeys[i])))
        L = temp
    
    block = R + L
    return permute(block, IP_INV)

def des_decrypt(ciphertext, key):
    """Déchiffre un bloc de 64 bits avec DES."""
    ciphertext = ''.join(format(ord(c), '08b') for c in ciphertext)[:64].ljust(64, '0')
    key = ''.join(format(ord(c), '08b') for c in key)[:64].ljust(64, '0')
    
    block = permute(ciphertext, IP)
    L, R = block[:32], block[32:]
    subkeys = generate_subkeys(key)[::-1]  # Inverser l'ordre des sous-clés
    
    for i in range(16):
        temp = R
        R = ''.join(str(int(a) ^ int(b)) for a, b in zip(L, f_function(R, subkeys[i])))
        L = temp
    
    block = R + L
    return permute(block, IP_INV)

def triple_des_encrypt(plaintext, key1, key2, key3):
    """Chiffre un bloc avec Triple DES (EEE)."""
    # Étape 1 : Chiffrement avec K1
    intermediate = des_encrypt(plaintext, key1)
    # Étape 2 : Chiffrement avec K2
    intermediate = des_encrypt(intermediate, key2)
    # Étape 3 : Chiffrement avec K3
    ciphertext = des_encrypt(intermediate, key3)
    return ciphertext

def triple_des_decrypt(ciphertext, key1, key2, key3):
    """Déchiffre un bloc avec Triple DES (DDD)."""
    # Étape 1 : Déchiffrement avec K3
    intermediate = des_decrypt(ciphertext, key3)
    # Étape 2 : Déchiffrement avec K2
    intermediate = des_decrypt(intermediate, key2)
    # Étape 3 : Déchiffrement avec K1
    plaintext = des_decrypt(intermediate, key1)
    return plaintext

# Exemple d'utilisation
if __name__ == "__main__":
    plaintext = "12345678"  # 8 caractères = 64 bits
    key1 = "abcdefgh"      # Clé 1 (8 caractères)
    key2 = "stuvwxyz"      # Clé 2 (8 caractères)
    key3 = "ijklmnop"      # Clé 3 (8 caractères)
    
    # Chiffrement
    ciphertext = triple_des_encrypt(plaintext, key1, key2, key3)
    print(f"Texte chiffré (binaire) : {ciphertext}")
    
    # Déchiffrement
    decrypted = triple_des_decrypt(ciphertext, key1, key2, key3)
    print(f"Texte déchiffré (binaire) : {decrypted}")