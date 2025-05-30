import socket
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Générer une clé privée RSA pour le serveur
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Sérialiser la clé publique pour l'envoyer
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

def handle_client(conn, addr):
    print(f"Connecté à {addr}")
    
    try:
        # Étape 1 : Envoyer la clé publique du serveur au client
        conn.send(public_pem)
        print(f"Clé publique envoyée à {addr}")

        # Étape 2 : Recevoir la clé publique du client
        client_public_pem = conn.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_pem)
        print(f"Clé publique du client {addr} reçue")

        # Étape 3 : Recevoir la clé AES chiffrée envoyée par le client
        encrypted_session_key = conn.recv(2048)

        # Déchiffrer la clé AES avec la clé privée du serveur
        session_key = private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print(f"Clé de session établie avec {addr}")

        # Boucle pour recevoir et envoyer des messages chiffrés
        while True:
            try:
                # Recevoir le message chiffré (nonce + tag + ciphertext)
                data = conn.recv(2048)
                if not data:
                    print(f"Aucune donnée reçue de {addr}")
                    break

                # Extraire nonce, tag et ciphertext
                received_nonce = data[:16]
                received_tag = data[16:32]
                received_ciphertext = data[32:]

                # Déchiffrer le message
                cipher = Cipher(algorithms.AES(session_key), modes.GCM(received_nonce, received_tag))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(received_ciphertext) + decryptor.finalize()
                print(f"Message reçu de {addr}: {plaintext.decode('utf-8')}")

                # Envoyer une réponse chiffrée
                response = input(f"Réponse pour {addr}: ")
                response_bytes = response.encode('utf-8')
                nonce = os.urandom(16)
                cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce))
                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(response_bytes) + encryptor.finalize()
                
                # Envoyer: nonce (16) + tag (16) + ciphertext
                data_to_send = nonce + encryptor.tag + ciphertext
                conn.send(data_to_send)

            except Exception as e:
                print(f"Erreur lors de l'échange avec {addr}: {e}")
                break

    except Exception as e:
        print(f"Erreur avec le client {addr}: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
        print(f"Déconnexion de {addr}")

def start_server():
    try:
        # Configurer le socket du serveur
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permet de réutiliser l'adresse
        server.bind(('0.0.0.0', 5555))  # Écouter sur toutes les interfaces, port 5555
        server.listen()

        print("Serveur en attente de connexions sur le port 5555...")
        while True:
            try:
                conn, addr = server.accept()
                thread = threading.Thread(target=handle_client, args=(conn, addr))
                thread.daemon = True  # Le thread se fermera quand le programme principal se ferme
                thread.start()
            except Exception as e:
                print(f"Erreur lors de l'acceptation de connexion: {e}")
                
    except Exception as e:
        print(f"Erreur du serveur: {e}")
    finally:
        try:
            server.close()
        except:
            pass

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nArrêt du serveur...")
    except Exception as e:
        print(f"Erreur fatale: {e}")