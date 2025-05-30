# 🔐 Cryptographie Lab 

*Algorithms • Security • Implementation*

[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Cryptography](https://img.shields.io/badge/Cryptography-FF6B6B?style=for-the-badge&logo=security&logoColor=white)](#)
[![USTHB](https://img.shields.io/badge/USTHB-4ECDC4?style=for-the-badge&logo=university&logoColor=white)](#)

**Collection complète des algorithmes de la cryptographie - De César à ECC, tous les algorithmes essentiels implémentés**

🔒 **Sécurité** • 🧮 **Algorithmes** • 🎓 **Éducatif**

---

## 🚀 Algorithmes Implémentés

### 🏛️ **Cryptographie Classique**
```
🔤 César           🔀 Substitution      📊 Vigenère
📈 Analyse Freq.   🔍 Test Kasiski     📐 Indice Coïncidence
```

### 🔑 **Cryptographie Symétrique**
```
⚡ RC4             🏗️ DES              🛡️ AES/Rijndael
🔒 Triple DES      🎯 Feistel          
```

### 🌐 **Cryptographie Asymétrique**
```
🔐 RSA             🔑 ElGamal          📈 ECC
🤝 Diffie-Hellman
```

### 🔍️ **Hachage & Signatures**
```
#️⃣ MD5             🔐 SHA-256          🆕 BLAKE3
✍️ RSA Signature   📝 DSA Signature    🔒 HMAC
```

---

## 📱 Applications Pratiques

| **🖥️ Client-Server** | **🔐 Communication Sécurisée** |
|:---:|:---:|
| RSA + AES Hybrid | Chiffrement bout-en-bout |
| Authentification | Échange de clés sécurisé |

---

## 🛠️ Tech Stack

![Python](https://img.shields.io/badge/Python_3.x-3776AB?style=flat-square&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/cryptography-FF6B6B?style=flat-square)
![PyCryptodome](https://img.shields.io/badge/pycryptodome-4ECDC4?style=flat-square)
![Hashlib](https://img.shields.io/badge/hashlib-45B7D1?style=flat-square)

---

## 📂 Structure du Projet

```
crypto-lab-algorithms/
├── 🏛️ chap1.py                    # Cryptographie classique
├── ⚡ rc4.py                      # Algorithme RC4
├── 🏗️ des/                        # DES implementation
├── 🛡️ aes/                        # AES/Rijndael
├── 🔒 triple_des.py               # Triple DES
├── 🎯 feistel.py                  # Réseau de Feistel
├── 🔐 rsa.py                      # RSA encryption
├── 🔑 ecc_cryptography.py         # Courbes elliptiques
├── 🤝 diffie.py                   # Diffie-Hellman
├── #️⃣ md5_hash.py                 # MD5 hashing
├── 🔐 sha256_hash.py              # SHA-256
├── 🆕 blake3_hash.py              # BLAKE3
├── ✍️ rsa_digital_signature.py    # Signature RSA
├── 📝 dsa.py & dsa_signature.py   # DSA signatures
└── 🖥️ client-server/              # Application sécurisée
```

---

## 🚀 Quick Start

```bash
# Cloner le repository
git clone https://github.com/Ahlamghribi/crypto-lab-algorithms.git

# Naviguer vers le projet
cd crypto-lab-algorithms

# Installer les dépendances
pip install cryptography pycryptodome

# Exécuter un algorithme (exemple RSA)
python rsa.py
```

---

## 🎯 Cas d'Usage

### 🔒 **Chiffrement de Messages**
```python
# Exemple avec AES
from aes import encrypt_message
encrypted = encrypt_message("Hello World!", key)
```

### ✍️ **Signature Numérique**
```python
# Exemple avec RSA
from rsa_digital_signature import sign_message
signature = sign_message(message, private_key)
```

### 🤝 **Échange de Clés**
```python
# Diffie-Hellman
from diffie import generate_shared_secret
shared_key = generate_shared_secret(private_a, public_b, p)
```

---

## 📊 Algorithmes par Catégorie

| **Catégorie** | **Algorithmes** | **Fichiers** |
|:---:|:---:|:---:|
| 🏛️ **Classique** | César, Vigenère, Substitution | `chap1.py` |
| 🔑 **Symétrique** | RC4, DES, AES, 3DES | `rc4.py`, `des/`, `aes/`, `triple_des.py` |
| 🌐 **Asymétrique** | RSA, ECC, Diffie-Hellman | `rsa.py`, `ecc_cryptography.py`, `diffie.py` |
| 🔍 **Hachage** | MD5, SHA-256, BLAKE3 | `*_hash.py` |
| ✍️ **Signatures** | RSA-Sign, DSA | `*_signature.py`, `dsa.py` |

---

## 🎓 Objectifs Pédagogiques

- **Comprendre** les fondements de la cryptographie
- **Implémenter** les algorithmes classiques et modernes
- **Analyser** la sécurité des différentes méthodes
- **Appliquer** la cryptographie dans des cas concrets
- **Maîtriser** les protocoles de communication sécurisée

---

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- 🐛 Signaler des bugs
- 💡 Proposer des améliorations
- 📝 Améliorer la documentation
- ➕ Ajouter de nouveaux algorithmes

---

**🔐 Sécurité • 🎓 Éducation • 💻 Open Source**

*Made with ❤️ for cryptography enthusiasts*
