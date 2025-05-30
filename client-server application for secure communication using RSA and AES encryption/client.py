import socket
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Générer une clé privée RSA pour le client
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Sérialiser la clé publique pour l'envoyer
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def start_client():
    try:
        # Configurer le socket du client
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('172.20.10.2', 5555))  # Remplacer par l'IP du serveur
        print("Connecté au serveur")

        # Étape 1 : Recevoir la clé publique du serveur
        server_public_pem = client.recv(2048)
        server_public_key = serialization.load_pem_public_key(server_public_pem)
        print("Clé publique du serveur reçue")

        # Étape 2 : Envoyer la clé publique du client
        client.send(public_pem)
        print("Clé publique du client envoyée")

        # Étape 3 : Générer et chiffrer une clé AES pour la session
        session_key = os.urandom(32)  # Clé AES de 256 bits
        encrypted_session_key = server_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client.send(encrypted_session_key)
        print("Clé de session AES envoyée")

        # Boucle pour envoyer et recevoir des messages chiffrés
        while True:
            try:
                # Envoyer un message chiffré
                message = input("Entrez votre message (ou 'quit' pour quitter): ")
                if message.lower() == 'quit':
                    break
                    
                message_bytes = message.encode('utf-8')
                nonce = os.urandom(16)
                cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
                
                # Envoyer: nonce (16) + tag (16) + ciphertext
                data_to_send = nonce + encryptor.tag + ciphertext
                client.send(data_to_send)

                # Recevoir la réponse chiffrée
                data = client.recv(2048)
                if not data:
                    print("Connexion fermée par le serveur")
                    break

                # Extraire nonce, tag et ciphertext
                received_nonce = data[:16]
                received_tag = data[16:32]
                received_ciphertext = data[32:]

                # Déchiffrer la réponse
                cipher = Cipher(algorithms.AES(session_key), modes.GCM(received_nonce, received_tag))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(received_ciphertext) + decryptor.finalize()
                print(f"Message reçu du serveur: {plaintext.decode('utf-8')}")

            except Exception as e:
                print(f"Erreur lors de l'échange de messages: {e}")
                break

    except Exception as e:
        print(f"Erreur de connexion: {e}")
    finally:
        try:
            client.close()
        except:
            pass
        print("Client fermé")

if __name__ == "__main__":
    start_client()