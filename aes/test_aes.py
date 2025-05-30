from aes import AES
import os

def test_aes_encryption():
    # Message à chiffrer
    message = b"Hello, AES! This is a test message."
    print(f"Message original: {message.decode()}")
    print(f"Taille du message: {len(message)} bytes")

    # Génération d'une clé aléatoire de 16 bytes (128 bits)
    key = os.urandom(16)
    print(f"\nClé AES (hex): {key.hex()}")

    # Création de l'instance AES
    cipher = AES(key)

    # Chiffrement du message
    iv = os.urandom(16)  # Vecteur d'initialisation
    print(f"IV (hex): {iv.hex()}")

    # Chiffrement en mode CBC
    encrypted = cipher.encrypt_cbc(message, iv)
    print(f"\nMessage chiffré (hex): {encrypted.hex()}")

    # Déchiffrement
    decrypted = cipher.decrypt_cbc(encrypted, iv)
    print(f"\nMessage déchiffré: {decrypted.decode()}")

    # Vérification
    if message == decrypted:
        print("\n✅ Test réussi: Le message déchiffré correspond au message original!")
    else:
        print("\n❌ Test échoué: Le message déchiffré ne correspond pas au message original!")

if __name__ == "__main__":
    print("=== Test d'encryption AES en mode CBC ===")
    test_aes_encryption() 