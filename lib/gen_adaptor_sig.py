import hashlib
import json
import secrets
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
ALICE_PRIVATE_KEY = "ee3375f2c778e0d0e69a8fd27679120cc447d5cf023a4cccf4e5acb0d70e939b"
ALICE_PUBLIC_KEY = "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5"
BOB_PUBLIC_KEY = "02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141

def tagged_hash(tag: str, data: bytes) -> bytes:
    """Calcula um hash etiquetado conforme BIP-340: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()

def has_even_y(point: secp256k1.PublicKey) -> bool:
    """Verifica se a coordenada y do ponto é par, conforme BIP-340."""
    serialized = point.serialize()
    return serialized[0] == 0x02  # 0x02 indica y par, 0x03 indica y ímpar

# Verificar consistência da chave de Alice
ka = secp256k1.PrivateKey(bytes.fromhex(ALICE_PRIVATE_KEY))
if ka.pubkey.serialize().hex() != ALICE_PUBLIC_KEY:
    raise ValueError("A chave privada de Alice não corresponde à chave pública fornecida!")

d_prime = int.from_bytes(ka.private_key, 'big')

if d_prime == 0 or d_prime >= CURVE_ORDER:
    raise ValueError("Chave privada inválida: d' = 0 ou d' >= n")

Pa = ka.pubkey  # Deriva P = d' * G
if not has_even_y(Pa):
    d_prime = (CURVE_ORDER - d_prime) % CURVE_ORDER
    ka = secp256k1.PrivateKey(d_prime.to_bytes(32, 'big'))
    Pa = ka.pubkey
    print("Ajustando d para garantir has_even_y(P)")

# Passo 1: Carregar o proof de Alice (Mint A, 8 sats)
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/p2pk_unblinded_proofs.json", "r") as f:
    proofs = json.load(f)
proof = next(p for p in proofs if p["amount"] == 8)
y = proof["secret"]  # O secret P2PK de Alice
print(f"Secret a ser assinado (y): {y}")

# Verificar se o secret contém a chave pública correta
secret_json = json.loads(y)
if secret_json[1]["data"] != ALICE_PUBLIC_KEY:
    raise ValueError(f"Chave pública no secret de Alice não corresponde: {secret_json[1]['data']} (esperado: {ALICE_PUBLIC_KEY})")

# Passo 2: Carregar o proof de Bob (Mint B, 8 sats) para x
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/p2pk_unblinded_proofs_bob.json", "r") as f:
    proofs_bob = json.load(f)
proof_b = next(p for p in proofs_bob if p["amount"] == 8)
x = proof_b["secret"]  # O secret P2PK de Bob
print(f"Secret de Bob (x): {x}")

# Passo 3: Carregar Rb de Bob
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/schnorr_signature_bob.json", "r") as f:
    bob_signature = json.load(f)
Rb_x = bytes.fromhex(bob_signature["Rb"])
Rb = secp256k1.PublicKey(b"\x02" + Rb_x, raw=True)  # Reconstruir ponto com prefixo 02
print(f"Rb carregado de Bob: {Rb_x.hex()}")

# Passo 4: Calcular o adaptor point T = Rb + H(Rb || Pb || H(x)) * Pb
Pb = secp256k1.PublicKey(bytes.fromhex(BOB_PUBLIC_KEY), raw=True)

# Calcular H(x)
x_hash = hashlib.sha256(x.encode('utf-8')).digest()

# Calcular H(Rb || Pb || H(x)) com tagged hash BIP0340/challenge
hash_input = Rb_x + Pb.serialize()[1:] + x_hash
h = tagged_hash("BIP0340/challenge", hash_input)
h_int = int.from_bytes(h, 'big') % CURVE_ORDER

hPb = Pb.mult(secp256k1.PrivateKey(h_int.to_bytes(32, 'big')))
T = Rb + hPb
print(f"Adaptor point (T): {T.serialize()[1:].hex()}")

# Passo 5: Calcular o nonce adaptador Radaptor = Ra + T
# Gerar dados aleatórios auxiliares a
a = secrets.token_bytes(32)
t = bytes(a_int ^ b_int for a_int, b_int in zip(ka.private_key, tagged_hash("BIP0340/aux", a)))

# Calcular H(y)
y_hash = hashlib.sha256(y.encode('utf-8')).digest()

# Calcular rand = hash_BIP0340/nonce(t || bytes(Pa) || H(y))
hash_input = t + Pa.serialize()[1:] + y_hash
rand = tagged_hash("BIP0340/nonce", hash_input)
ra_prime = int.from_bytes(rand, 'big') % CURVE_ORDER

if ra_prime == 0:
    raise ValueError("Nonce inválido: ra_prime = 0")

# Calcular Ra = ra_prime * G
Ra = secp256k1.PrivateKey(ra_prime.to_bytes(32, 'big')).pubkey

# Calcular Radaptor = Ra + T
Radaptor = Ra + T

# Ajustar ra para garantir has_even_y(Radaptor)
if not has_even_y(Radaptor):  # Verifica se y é par
    ra_prime = (CURVE_ORDER - ra_prime) % CURVE_ORDER
    Ra = secp256k1.PrivateKey(ra_prime.to_bytes(32, 'big')).pubkey
    Radaptor = Ra + T

print(f"Nonce adaptador (Radaptor): {Radaptor.serialize()[1:].hex()}")

# Passo 6: Calcular a adaptor signature sa = ra + H(Radaptor || Pa || H(y)) * ka
# Calcular H(Radaptor || Pa || H(y)) com tagged hash BIP0340/challenge
hash_input = Radaptor.serialize()[1:] + Pa.serialize()[1:] + y_hash
e = tagged_hash("BIP0340/challenge", hash_input)
e_int = int.from_bytes(e, 'big') % CURVE_ORDER

ka_int = int.from_bytes(ka.private_key, 'big')
sa = (ra_prime + e_int * ka_int) % CURVE_ORDER
sa_bytes = sa.to_bytes(32, 'big')
print(f"Adaptor signature (sa): {sa_bytes.hex()}")

# Passo 7: Salvar a assinatura
signature = {
    "Radaptor": Radaptor.serialize()[1:].hex(),
    "sa": sa_bytes.hex()
}
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/adaptor_signature_alice.json", "w") as f:
    json.dump(signature, f, indent=4)
print("Assinatura salva em adaptor_signature_alice.json")