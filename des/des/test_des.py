from DES import DES

def test_des():
    # Clé de test (64 bits)
    key = 0x133457799BBCDFF1
    
    # Message de test
    message = "Hello DES!"
    
    print("=== Test de l'algorithme DES ===")
    print(f"Clé utilisée: {hex(key)}")
    print(f"Message original: '{message}'")
    
    # Création de l'instance DES
    des = DES(key)
    
    # Chiffrement
    print("\n=== Chiffrement ===")
    print("Chiffrement caractère par caractère:")
    ciphertext = []
    for i, char in enumerate(message.lower()):
        print(f"\nCaractère {i+1}: '{char}'")
        binary = int_to_bin(ord(char), block_size=64)
        print(f"Binaire: {binary}")
        encrypted = des.encrypt(binary)
        print(f"Chiffré: {encrypted}")
        ciphertext.append(int(encrypted, base=2))
    
    print("\nMessage chiffré complet (en hexadécimal):")
    for i, c in enumerate(ciphertext):
        print(f"Bloc {i+1}: {hex(c)}")
    
    # Déchiffrement
    print("\n=== Déchiffrement ===")
    decrypted_message = des.decrypt_message(ciphertext)
    print(f"Message déchiffré: '{decrypted_message}'")
    
    # Vérification
    print("\n=== Vérification ===")
    if message.lower() == decrypted_message:
        print("✅ Test réussi: Le message déchiffré correspond au message original!")
    else:
        print("❌ Test échoué: Le message déchiffré ne correspond pas au message original!")

if __name__ == "__main__":
    test_des() 