import hashlib
import secrets
import secp256k1

# Configurações
PRIVATE_KEY = bytes.fromhex("ee3375f2c778e0d0e69a8fd27679120cc447d5cf563a4cccf4e5acb0d70e939b")
PUBLIC_KEY = bytes.fromhex("0228706e2e9726468bc8eeffeeefb21aad093922041436fd5a562b3e9a705648eb")
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MESSAGE = b"test_message"

def tagged_hash(tag: str, data: bytes) -> bytes:
    """Calcula um hash etiquetado conforme BIP-340: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()

def has_even_y(point: secp256k1.PublicKey) -> bool:
    """Verifica se a coordenada y do ponto é par, conforme BIP-340."""
    serialized = point.serialize()
    return serialized[0] == 0x02  # 0x02 indica y par, 0x03 indica y ímpar

# Passo 1: Verificar a chave privada e pública
sk = secp256k1.PrivateKey(PRIVATE_KEY)
if sk.pubkey.serialize().hex() != PUBLIC_KEY.hex():
    raise ValueError("Chave privada não corresponde à chave pública!")

# Passo 2: Derivar d e P
d_int = int.from_bytes(PRIVATE_KEY, 'big')
if d_int == 0 or d_int >= CURVE_ORDER:
    raise ValueError("Chave privada inválida: d = 0 ou d >= n")
P = secp256k1.PublicKey(PUBLIC_KEY, raw=True)
if not has_even_y(P):
    d_int = (CURVE_ORDER - d_int) % CURVE_ORDER
    print("Ajustando d para garantir has_even_y(P)")

# Passo 3: Gerar dados aleatórios auxiliares a
a = secrets.token_bytes(32)

# Passo 4: Calcular t = bytes(d) XOR hash_BIP0340/aux(a)
d_bytes = d_int.to_bytes(32, 'big')
t = bytes(a_int ^ b_int for a_int, b_int in zip(d_bytes, tagged_hash("BIP0340/aux", a)))

# Passo 5: Calcular rand = hash_BIP0340/nonce(t || bytes(P) || m)
hash_input = t + P.serialize()[1:] + MESSAGE
rand = tagged_hash("BIP0340/nonce", hash_input)

# Passo 6: Derivar k' = int(rand) mod n
k_prime = int.from_bytes(rand, 'big') % CURVE_ORDER
if k_prime == 0:
    raise ValueError("Nonce inválido: k_prime = 0")

# Passo 7: Calcular R = k' * G
R = secp256k1.PrivateKey(k_prime.to_bytes(32, 'big')).pubkey

# Passo 8: Ajustar k para garantir has_even_y(R)
k = k_prime
if not has_even_y(R):
    k = (CURVE_ORDER - k_prime) % CURVE_ORDER
    R = secp256k1.PrivateKey(k.to_bytes(32, 'big')).pubkey

# Passo 9: Calcular o desafio e = hash_BIP0340/challenge(bytes(R) || bytes(P) || m)
hash_input = R.serialize()[1:] + P.serialize()[1:] + MESSAGE
e = tagged_hash("BIP0340/challenge", hash_input)
e_int = int.from_bytes(e, 'big') % CURVE_ORDER

# Passo 10: Calcular a assinatura s = (k + e * d) mod n
s = (k + e_int * d_int) % CURVE_ORDER
s_bytes = s.to_bytes(32, 'big')
print(f"Assinatura (R, s): {R.serialize()[1:].hex()}{s_bytes.hex()}")

# Passo 11: Montar a assinatura completa
signature = R.serialize()[1:] + s_bytes

# Passo 12: Verificar a assinatura com schnorr_verify
try:
    is_valid = P.schnorr_verify(MESSAGE, signature, None, raw=True)
    print(f"Assinatura válida: {is_valid}")
except Exception as e:
    print(f"Erro ao verificar a assinatura: {e}")