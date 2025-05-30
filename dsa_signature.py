import hashlib
import random
from Crypto.Util.number import getPrime, isPrime, inverse

class SecureDSA:
    def __init__(self, L=2048, N=256):
        """
        Initialisation avec des paramètres de sécurité robustes
        L = taille de la clé (2048 bits recommandé pour une sécurité élevée)
        N = taille du sous-groupe (256 bits)
        """
        self.L = L
        self.N = N
        
        # Génération des paramètres de domaine sécurisés
        self.generate_domain_parameters()
        
        # Génération des clés
        self.generate_keys()

    def generate_domain_parameters(self):
        """Génération des paramètres de domaine p, q, g selon FIPS 186-4"""
        # 1. Choisir un nombre premier q de N bits
        self.q = getPrime(self.N)
        
        # 2. Choisir un nombre premier p de L bits tel que p-1 soit divisible par q
        while True:
            # Générer un grand nombre aléatoire de L bits
            p_candidate = getPrime(self.L)
            
            # Vérifier si p-1 est divisible par q
            if (p_candidate - 1) % self.q == 0:
                self.p = p_candidate
                break
        
        # 3. Trouver un générateur g du sous-groupe d'ordre q
        h = 2
        while True:
            g = pow(h, (self.p - 1) // self.q, self.p)
            if g != 1:
                self.g = g
                break
            h += 1

    def generate_keys(self):
        """Génération des clés privée et publique"""
        # Clé privée: nombre aléatoire entre 1 et q-1
        self.x = random.randint(1, self.q - 1)
        
        # Clé publique: y = g^x mod p
        self.y = pow(self.g, self.x, self.p)

    def sign(self, message):
        """Signature d'un message"""
        # Hachage sécurisé du message avec SHA-256
        H = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.q
        
        while True:
            # Générer un k aléatoire sécurisé
            k = random.randint(1, self.q - 1)
            
            # Calculer r = (g^k mod p) mod q
            r = pow(self.g, k, self.p) % self.q
            if r == 0:
                continue
            
            # Calculer s = (k^-1 * (H + x*r)) mod q
            try:
                k_inv = inverse(k, self.q)
            except ValueError:
                continue
                
            s = (k_inv * (H + self.x * r)) % self.q
            if s == 0:
                continue
                
            return (r, s)

    def verify(self, message, signature):
        """Vérification d'une signature"""
        r, s = signature
        
        # Vérification des bornes
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        
        # Hachage sécurisé du message avec SHA-256
        H = int.from_bytes(hashlib.sha256(message).digest(), 'big') % self.q
        
        try:
            w = inverse(s, self.q)
        except ValueError:
            return False
        
        u1 = (H * w) % self.q
        u2 = (r * w) % self.q
        
        v = (pow(self.g, u1, self.p) * pow(self.y, u2, self.p) % self.p) % self.q
        
        return v == r

# Exemple d'utilisation
if __name__ == "__main__":
    dsa = SecureDSA(L=2048, N=256)
    
    message = b"Ceci est un message important a signer"
    
    # Signature
    signature = dsa.sign(message)
    print(f"Signature générée: r={signature[0]}, s={signature[1]}")
    
    # Vérification
    is_valid = dsa.verify(message, signature)
    print(f"Signature valide? {'Oui' if is_valid else 'Non'}")
    
    # Test avec un message modifié
    fake_message = b"Ceci est un message modifie"
    is_valid_fake = dsa.verify(fake_message, signature)
    print(f"Signature valide pour message modifié? {'Oui' if is_valid_fake else 'Non'}")