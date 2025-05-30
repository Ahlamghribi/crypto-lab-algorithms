import hashlib
import random
import math
from typing import Tuple, Optional

class DSA:
    """
    Implémentation complète de l'algorithme DSA (Digital Signature Algorithm)
    """
    
    def __init__(self, L: int = 1024, N: int = 160):
        """
        Initialise DSA avec les tailles de clés spécifiées
        L: taille de p en bits (doit être multiple de 64, entre 512 et 1024)
        N: taille de q en bits (doit être 160)
        """
        self.L = L
        self.N = N
        self.p = None  # nombre premier de L bits
        self.q = None  # nombre premier de N bits, diviseur de (p-1)
        self.g = None  # générateur
        self.x = None  # clé privée
        self.y = None  # clé publique
    
    def _is_prime(self, n: int, k: int = 10) -> bool:
        """Test de primalité de Miller-Rabin"""
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False
        
        # Écrire n-1 comme d * 2^r
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
        
        # Test de Miller-Rabin k fois
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            
            if x == 1 or x == n - 1:
                continue
            
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        
        return True
    
    def _generate_prime(self, bits: int) -> int:
        """Génère un nombre premier de la taille spécifiée"""
        while True:
            # Générer un nombre aléatoire de la bonne taille
            candidate = random.getrandbits(bits)
            # S'assurer qu'il a exactement le bon nombre de bits
            candidate |= (1 << (bits - 1)) | 1  # MSB et LSB à 1
            
            if self._is_prime(candidate):
                return candidate
    
    def _generate_q(self) -> int:
        """Génère q, un nombre premier de N bits"""
        return self._generate_prime(self.N)
    
    def _generate_p(self, q: int) -> int:
        """Génère p tel que q divise (p-1) et p a L bits"""
        while True:
            # Générer un nombre aléatoire k tel que p = k*q + 1 ait L bits
            min_k = (1 << (self.L - 1)) // q
            max_k = (1 << self.L) // q
            
            if min_k >= max_k:
                continue
            
            k = random.randrange(min_k, max_k)
            p = k * q + 1
            
            if p.bit_length() == self.L and self._is_prime(p):
                return p
    
    def _generate_g(self, p: int, q: int) -> int:
        """Génère g, un générateur du sous-groupe d'ordre q dans Z*p"""
        h = 2
        while h < p:
            g = pow(h, (p - 1) // q, p)
            if g > 1:
                return g
            h += 1
        raise ValueError("Impossible de trouver un générateur")
    
    def generate_parameters(self) -> Tuple[int, int, int]:
        """
        Génère les paramètres du domaine DSA (p, q, g)
        Retourne: (p, q, g)
        """
        print("Génération des paramètres DSA...")
        
        # Étape 1: Générer q
        print("Génération de q...")
        self.q = self._generate_q()
        
        # Étape 2: Générer p tel que q divise (p-1)
        print("Génération de p...")
        self.p = self._generate_p(self.q)
        
        # Étape 3: Générer g
        print("Génération de g...")
        self.g = self._generate_g(self.p, self.q)
        
        print(f"Paramètres générés:")
        print(f"p ({self.p.bit_length()} bits): {hex(self.p)}")
        print(f"q ({self.q.bit_length()} bits): {hex(self.q)}")
        print(f"g: {hex(self.g)}")
        
        return self.p, self.q, self.g
    
    def generate_keys(self) -> Tuple[int, int]:
        """
        Génère une paire de clés DSA
        Retourne: (clé_privée, clé_publique)
        """
        if not all([self.p, self.q, self.g]):
            raise ValueError("Les paramètres du domaine doivent être générés d'abord")
        
        # Clé privée x: nombre aléatoire dans [1, q-1]
        self.x = random.randrange(1, self.q)
        
        # Clé publique y = g^x mod p
        self.y = pow(self.g, self.x, self.p)
        
        print(f"Clés générées:")
        print(f"Clé privée (x): {hex(self.x)}")
        print(f"Clé publique (y): {hex(self.y)}")
        
        return self.x, self.y
    
    def _hash_message(self, message: bytes) -> int:
        """Hache le message avec SHA-1 et convertit en entier"""
        hash_obj = hashlib.sha1(message)
        hash_bytes = hash_obj.digest()
        return int.from_bytes(hash_bytes, byteorder='big')
    
    def sign(self, message: bytes) -> Tuple[int, int]:
        """
        Signe un message avec DSA
        Retourne: (r, s) - la signature
        """
        if not self.x:
            raise ValueError("La clé privée doit être générée d'abord")
        
        # Hacher le message
        h = self._hash_message(message)
        
        while True:
            # Générer k aléatoire dans [1, q-1]
            k = random.randrange(1, self.q)
            
            # Calculer r = (g^k mod p) mod q
            r = pow(self.g, k, self.p) % self.q
            
            if r == 0:
                continue
            
            # Calculer l'inverse modulaire de k modulo q
            k_inv = self._mod_inverse(k, self.q)
            if k_inv is None:
                continue
            
            # Calculer s = k^(-1) * (h + x*r) mod q
            s = (k_inv * (h + self.x * r)) % self.q
            
            if s == 0:
                continue
            
            return r, s
    
    def verify(self, message: bytes, signature: Tuple[int, int], public_key: Optional[int] = None) -> bool:
        """
        Vérifie une signature DSA
        signature: (r, s)
        public_key: clé publique (utilise self.y si None)
        Retourne: True si la signature est valide, False sinon
        """
        r, s = signature
        y = public_key if public_key is not None else self.y
        
        if not y:
            raise ValueError("Clé publique requise pour la vérification")
        
        # Vérifier que 0 < r < q et 0 < s < q
        if not (0 < r < self.q and 0 < s < self.q):
            return False
        
        # Hacher le message
        h = self._hash_message(message)
        
        # Calculer w = s^(-1) mod q
        w = self._mod_inverse(s, self.q)
        if w is None:
            return False
        
        # Calculer u1 = h*w mod q et u2 = r*w mod q
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q
        
        # Calculer v = ((g^u1 * y^u2) mod p) mod q
        v = (pow(self.g, u1, self.p) * pow(y, u2, self.p)) % self.p % self.q
        
        # La signature est valide si v == r
        return v == r
    
    def _mod_inverse(self, a: int, m: int) -> Optional[int]:
        """Calcule l'inverse modulaire de a modulo m en utilisant l'algorithme d'Euclide étendu"""
        def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            return None  # L'inverse n'existe pas
        return (x % m + m) % m


# Exemple d'utilisation
def exemple_utilisation():
    """Exemple complet d'utilisation de DSA"""
    print("=== Exemple d'utilisation de DSA ===\n")
    
    # Créer une instance DSA
    dsa = DSA(L=1024, N=160)
    
    # Générer les paramètres du domaine
    dsa.generate_parameters()
    print()
    
    # Générer les clés
    dsa.generate_keys()
    print()
    
    # Message à signer
    message = b"Bonjour, ceci est un message secret!"
    print(f"Message à signer: {message.decode()}")
    
    # Signer le message
    print("\nSignature en cours...")
    signature = dsa.sign(message)
    r, s = signature
    print(f"Signature générée:")
    print(f"r: {hex(r)}")
    print(f"s: {hex(s)}")
    
    # Vérifier la signature
    print("\nVérification de la signature...")
    is_valid = dsa.verify(message, signature)
    print(f"Signature valide: {is_valid}")
    
    # Test avec un message modifié
    print("\nTest avec un message modifié...")
    message_modifie = b"Bonjour, ceci est un message modifie!"
    is_valid_modifie = dsa.verify(message_modifie, signature)
    print(f"Signature valide pour le message modifié: {is_valid_modifie}")
    
    # Test avec une signature modifiée
    print("\nTest avec une signature modifiée...")
    signature_modifiee = (r + 1, s)
    is_valid_sig_modifiee = dsa.verify(message, signature_modifiee)
    print(f"Signature modifiée valide: {is_valid_sig_modifiee}")


if __name__ == "__main__":
    # Définir une graine pour la reproductibilité (à supprimer en production)
    random.seed(42)
    
    # Exécuter l'exemple
    exemple_utilisation()