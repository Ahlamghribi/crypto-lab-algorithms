import hashlib

message = "cyber_security"
hash_result = hashlib.sha256(message.encode()).hexdigest()

print("Hash SHA-256 :", hash_result)