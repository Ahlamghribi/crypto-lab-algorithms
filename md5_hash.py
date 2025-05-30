import hashlib

s = "cyber_security"
res = hashlib.md5(s.encode())
print(res.hexdigest())