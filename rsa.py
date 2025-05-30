import numpy as np

# Vérifie si un nombre est premier
def isprem(n):
    """Retourne True si n est premier, False sinon."""
    if n <= 1:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for x in range(3, int(n**0.5) + 1, 2):
        if n % x == 0:
            return False
    return True

# Calcul du PGCD
def pgcd(a, b):
    while b > 0:
        a, b = b, a % b
    return a

# Algorithme d’Euclide étendu
def pgcde(a, b):
    r, u, v = a, 1, 0
    rp, up, vp = b, 0, 1
    while rp != 0:
        q = r // rp
        r, u, v, rp, up, vp = rp, up, vp, r - q * rp, u - q * up, v - q * vp
    return (r, u, v)

# Génération des clés RSA
def key():
    # Choisir deux nombres premiers aléatoires entre 100 et 500
    while True:
        p = np.random.randint(100, 500)
        if isprem(p):
            break
    while True:
        q = np.random.randint(100, 500)
        if isprem(q) and q != p:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choisir un exposant public e tel que pgcd(e, phi) = 1
    while True:
        e = np.random.randint(3, phi)
        if pgcd(e, phi) == 1:
            break

    # Calcul de d, l’inverse modulaire de e mod phi
    _, d, _ = pgcde(e, phi)
    d = d % phi  # s'assurer que d est positif

    return {"priv": (n, d), "pub": (n, e)}

# Chiffrement RSA
def chiffre(n, e, msg):
    # Convertir chaque caractère en code ASCII sur 3 chiffres
    asc = ''.join(f'{ord(c):03}' for c in msg)

    # Ajouter des zéros à la fin pour que la longueur soit multiple de 4
    while len(asc) % 4 != 0:
        asc += '0'

    # Créer des blocs de 4 chiffres
    blocs = [asc[i:i+4] for i in range(0, len(asc), 4)]

    # Chiffrer chaque bloc
    crypt = [str(pow(int(b), e, n)) for b in blocs]
    return crypt

# Déchiffrement RSA
def dechiffre(n, d, *crypt):
    # Déchiffrer chaque bloc
    blocs = [str(pow(int(c), d, n)).zfill(4) for c in crypt]

    # Recomposer le message
    concat = ''.join(blocs)

    # Extraire chaque code ASCII de 3 chiffres
    chars = [chr(int(concat[i:i+3])) for i in range(0, len(concat), 3)]

    return ''.join(chars).rstrip('\x00')  # Supprimer les caractères nuls éventuels

# TEST
if __name__ == "__main__":
    # Générer les clés
    keys = key()
    priv = keys["priv"]
    pub = keys["pub"]

    print("Clé publique (n, e) :", pub)
    print("Clé privée  (n, d) :", priv)

    # Message à chiffrer
    msg = "HELLO RSA"
    print("\nMessage original :", msg)

    # Chiffrement
    crypted = chiffre(pub[0], pub[1], msg)
    print("Message chiffré :", crypted)

    # Déchiffrement
    decrypted = dechiffre(priv[0], priv[1], *crypted)
    print("Message déchiffré :", decrypted)
