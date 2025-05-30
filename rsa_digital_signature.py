from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def generate_keys():
    # Génération des clés publiques et privées
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return key, private_key, public_key

def create_signature(key, message):
    # Création du hachage
    hash_obj = SHA256.new(message)
    # Création de la signature
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature, hash_obj

def verify_signature(public_key, hash_obj, signature):
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False

def main():
    # Étape 1 : Génération des clés
    print("Génération des clés...")
    key, private_key, public_key = generate_keys()
    print("Clé privée :", private_key.decode())
    print("Clé publique :", public_key.decode())

    # Étape 2 : Création de la signature
    message = b'Ceci est un message important.'
    print("\nMessage :", message.decode())
    print("Création de la signature...")
    signature, hash_obj = create_signature(key, message)
    print("Signature créée :", signature.hex())

    # Étape 3 : Vérification de la signature
    print("\nVérification de la signature...")
    is_valid = verify_signature(key.publickey(), hash_obj, signature)
    if is_valid:
        print("La signature est authentique.")
    else:
        print("La signature n'est pas valide.")

if __name__ == "__main__":
    main()