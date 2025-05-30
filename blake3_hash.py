from blake3 import blake3

message = b"cyber security"
hash_result = blake3(message).hexdigest()

print("Hash BLAKE3 :", hash_result)