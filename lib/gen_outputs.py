import hashlib
import secrets
import requests
import json
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_URL = "http://localhost:3338"
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141

# Passo 1: Obtenha os keysets da mint
response = requests.get(f"{MINT_URL}/v1/keys")
keysets = response.json()["keysets"]

keyset_id = keysets[0]["id"]
keys = keysets[0]["keys"]

print("Chaves disponíveis no keyset:", keys)

# Escolha as chaves públicas mais próximas de 8 sats e 2 sats
public_key_8 = keys.get("8")
public_key_2 = keys.get("2")

print(f"PK_8_sats: {public_key_8}")
print(f"PK_2_sats: {public_key_2}")

# Passo 2: Gere os outputs (amount, id, B_)
outputs = []
amounts = [8, 2]
public_keys = [public_key_8, public_key_2]
secrets_list = []
r_scalars = []

def hash_to_curve(x: bytes, counter=0) -> secp256k1.PublicKey:
    """Converte um segredo em um ponto Y na curva usando hash_to_curve, conforme Cashu."""
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + x).digest()
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            Y = secp256k1.PublicKey(b"\x02" + _hash, raw=True)
            print(f"Ponto Y encontrado com counter: {counter}, prefix: 02")
            return Y
        except Exception:
            counter += 1
    raise ValueError("No valid point found after 2**16 iterations.")

for i, (amount, pubkey) in enumerate(zip(amounts, public_keys)):
    # Gere um segredo x (aleatório)
    x = secrets.token_bytes(32)
    print(f"secret ${i}: {x.hex()}")
    secrets_list.append(x)

    # Gere o ponto Y
    Y = hash_to_curve(x)
    print(f"Y: {Y.serialize().hex()}")

    # Gere o fator de cegamento r
    r = secp256k1.PrivateKey()
    r_scalar = int.from_bytes(r.private_key, 'big')
    r_scalars.append(r_scalar)
    print(f"r_scalar pubkey ${i}: {r_scalar}")
    print(f"r.pubkey: {r.pubkey.serialize().hex()}")

    # Calcule B_ = Y + r * G
    B_ = Y + r.pubkey  # Agora funciona com o monkeypatching
    print("Adição de pontos bem-sucedida")

    # Serialize B_ no formato comprimido
    B_serialized = B_.serialize().hex()
    print(f"B_: {B_serialized}")

    outputs.append({
        "amount": amount,
        "id": keyset_id,
        "B_": B_serialized
    })

# Salvar os outputs, secrets e r_scalars em um arquivo
output_data = {
    "outputs": outputs,
    "secrets": [s.hex() for s in secrets_list],
    "r_scalars": r_scalars
}
with open("outputs_data.json", "w") as f:
    json.dump(output_data, f, indent=4)
print("Outputs, secrets e r_scalars salvos em outputs_data.json")

# Passo 3: Enviar os outputs para a mint
response = requests.post(f"{MINT_URL}/v1/mint/quote/bolt11", json={"unit": "sat", "amount": sum(amounts)})
quote_data = response.json()
quote_id = quote_data["quote"]

mint_response = requests.post(f"{MINT_URL}/v1/mint/bolt11", json={"quote": quote_id, "outputs": outputs})
proofs = mint_response.json()

# Salvar os proofs retornados pela mint
with open("proofs_response.json", "w") as f:
    json.dump(proofs, f, indent=4)
print("Proofs retornados pela mint salvos em proofs_response.json")

# Exiba a resposta
print("Resultado:", outputs)