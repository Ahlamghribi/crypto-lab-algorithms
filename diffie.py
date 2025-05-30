class DH_Endpoint(object):
    def __init__(self, public_key1, public_key2, private_key):
        self.public_key1 = public_key1  # g
        self.public_key2 = public_key2  # p
        self.private_key = private_key  # a or b
        self.full_key = None
        
    def generate_partial_key(self):
        partial_key = pow(self.public_key1, self.private_key, self.public_key2)
        return partial_key
    
    def generate_full_key(self, partial_key_r):
        self.full_key = pow(partial_key_r, self.private_key, self.public_key2)
        return self.full_key
    
    def encrypt_message(self, message):
        encrypted_message = ""
        key = self.full_key
        for c in message:
            encrypted_message += chr((ord(c) + key) % 256)
        return encrypted_message
    
    def decrypt_message(self, encrypted_message):
        decrypted_message = ""
        key = self.full_key
        for c in encrypted_message:
            decrypted_message += chr((ord(c) - key) % 256)
        return decrypted_message


# Paramètres publics
g = 197
p = 151

# Clés privées
a = 199  # Sadat
b = 157  # Michael

# Création des deux endpoints
Sadat = DH_Endpoint(g, p, a)
Michael = DH_Endpoint(g, p, b)

# Génération des clés partielles
s_partial = Sadat.generate_partial_key()
m_partial = Michael.generate_partial_key()

print("Sadat envoie la clé partielle :", s_partial)
print("Michael envoie la clé partielle :", m_partial)

# Génération des clés complètes
s_full = Sadat.generate_full_key(m_partial)
m_full = Michael.generate_full_key(s_partial)

print("Clé complète chez Sadat   :", s_full)
print("Clé complète chez Michael :", m_full)

# Test chiffrement/déchiffrement
message = "This is a very secret message!!!"
encrypted = Sadat.encrypt_message(message)
print("Message chiffré :", encrypted)

decrypted = Michael.decrypt_message(encrypted)
print("Message déchiffré :", decrypted)
