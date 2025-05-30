from utils import *

class Feistel:
    def __init__(self, key: int, rounds: int = 16, block_size: int = 64):
        self.key = key
        self.rounds = rounds
        self.block_size = block_size
        self.half_block_size = block_size // 2

    def split_block(self, block: str) -> tuple[str, str]:
        """Divise un bloc en deux moitiés égales."""
        return block[:self.half_block_size], block[self.half_block_size:]

    def feistel_function(self, right_half: str, round_key: int) -> str:
        """
        Fonction de Feistel qui prend la moitié droite et la clé du round
        et retourne le résultat de la transformation.
        """
        # Expansion de 32 bits à 48 bits
        expanded = self.expand(right_half)
        
        # XOR avec la clé du round
        xored = int_to_bin(int(expanded, 2) ^ round_key, len(expanded))
        
        # Substitution via S-boxes
        substituted = self.substitute(xored)
        
        # Permutation finale
        return self.permute(substituted)

    def expand(self, block: str) -> str:
        """Expansion de 32 bits à 48 bits."""
        # Table d'expansion DES
        expansion_table = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]
        return ''.join(block[i-1] for i in expansion_table)

    def substitute(self, block: str) -> str:
        """Substitution via S-boxes."""
        # Diviser le bloc en 8 parties de 6 bits
        blocks = [block[i:i+6] for i in range(0, len(block), 6)]
        result = ''
        
        # Table S-box DES (simplifiée pour l'exemple)
        s_boxes = [
            # S1
            [
                [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
            ]
        ]
        
        for i, b in enumerate(blocks):
            # Prendre le premier et dernier bit pour la ligne
            row = int(b[0] + b[-1], 2)
            # Prendre les 4 bits du milieu pour la colonne
            col = int(b[1:-1], 2)
            # Récupérer la valeur de la S-box
            val = s_boxes[0][row][col]
            # Convertir en binaire sur 4 bits
            result += format(val, '04b')
        
        return result

    def permute(self, block: str) -> str:
        """Permutation finale."""
        # Table de permutation DES (simplifiée)
        perm_table = [
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25
        ]
        return ''.join(block[i-1] for i in perm_table)

    def encrypt(self, block: str) -> str:
        """Chiffrement d'un bloc avec la structure de Feistel."""
        left, right = self.split_block(block)
        
        for round in range(self.rounds):
            # Calculer la nouvelle moitié droite
            feistel_output = self.feistel_function(right, self.key)
            new_right = int_to_bin(int(left, 2) ^ int(feistel_output, 2), self.half_block_size)
            
            # Mettre à jour les moitiés pour le prochain round
            left = right
            right = new_right
        
        # Concaténer les moitiés finales
        return left + right

    def decrypt(self, block: str) -> str:
        """Déchiffrement d'un bloc avec la structure de Feistel."""
        left, right = self.split_block(block)
        
        for round in range(self.rounds):
            # Calculer la nouvelle moitié droite
            feistel_output = self.feistel_function(right, self.key)
            new_right = int_to_bin(int(left, 2) ^ int(feistel_output, 2), self.half_block_size)
            
            # Mettre à jour les moitiés pour le prochain round
            left = right
            right = new_right
        
        # Concaténer les moitiés finales
        return left + right

def test_feistel():
    # Test de la structure de Feistel
    key = 0x133457799BBCDFF1
    message = "Hello"
    
    print("=== Test de la structure de Feistel ===")
    print(f"Clé: {hex(key)}")
    print(f"Message: '{message}'")
    
    feistel = Feistel(key)
    
    # Chiffrement caractère par caractère
    print("\n=== Chiffrement ===")
    ciphertext = []
    for char in message:
        binary = int_to_bin(ord(char), block_size=64)
        print(f"\nCaractère: '{char}'")
        print(f"Binaire: {binary}")
        encrypted = feistel.encrypt(binary)
        print(f"Chiffré: {encrypted}")
        ciphertext.append(encrypted)
    
    # Déchiffrement
    print("\n=== Déchiffrement ===")
    decrypted = []
    for block in ciphertext:
        decrypted_block = feistel.decrypt(block)
        decrypted_char = chr(int(decrypted_block, 2))
        print(f"Bloc déchiffré: {decrypted_block}")
        print(f"Caractère déchiffré: '{decrypted_char}'")
        decrypted.append(decrypted_char)
    
    decrypted_message = ''.join(decrypted)
    print(f"\nMessage déchiffré: '{decrypted_message}'")
    
    # Vérification
    print("\n=== Vérification ===")
    if message == decrypted_message:
        print("✅ Test réussi: Le message déchiffré correspond au message original!")
    else:
        print("❌ Test échoué: Le message déchiffré ne correspond pas au message original!")

if __name__ == "__main__":
    test_feistel() 