import requests
import json
import secrets
import secp256k1
import hashlib
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_URL = "http://localhost:3338/v1/swap"
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141
KEYSET_ID = "000b4c3d8b0e7397"

def hash_to_curve(x: bytes, counter=0) -> secp256k1.PublicKey:
    """Converte um segredo em um ponto Y na curva usando hash_to_curve, conforme Cashu."""
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + x).digest()
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            return secp256k1.PublicKey(b"\x02" + _hash, raw=True)
        except Exception:
            counter += 1
    raise ValueError("No valid point found after 2**16 iterations.")

def generate_blinded_message(amount):
    """Gera uma BlindedMessage para o valor especificado, retornando também segredo e fator de cegamento."""
    x = secrets.token_bytes(32)
    Y = hash_to_curve(x)
    r = secp256k1.PrivateKey()
    r_scalar = int.from_bytes(r.private_key, 'big')
    B_ = Y + r.pubkey
    B_serialized = B_.serialize().hex()
    print(f"Gerando output para {amount} sats: B_={B_serialized}, secret={x.hex()}, r_scalar={r_scalar}")
    return {
        "amount": amount,
        "id": KEYSET_ID,
        "B_": B_serialized
    }, x, r_scalar

# Carregar os proofs descegados do arquivo unblinded_proofs.json
with open("unblinded_proofs.json", "r") as f:
    proofs = json.load(f)

# Verificar o total dos valores dos proofs
total_amount = sum(proof["amount"] for proof in proofs)
print(f"Total dos proofs: {total_amount} sats")
print("Proofs descegados:", proofs)

# Novos valores para swap (exemplo: trocar por 5 sats + 5 sats)
new_amounts = [5, 5]
if sum(new_amounts) != total_amount:
    raise ValueError(f"A soma dos novos valores ({sum(new_amounts)}) deve ser igual ao total dos proofs ({total_amount})")

# Gerar novos outputs (BlindedMessages) e salvar segredos e fatores de cegamento
new_outputs = []
new_secrets = []
new_r_scalars = []
for amount in new_amounts:
    output, x, r_scalar = generate_blinded_message(amount)
    new_outputs.append(output)
    new_secrets.append(x)
    new_r_scalars.append(r_scalar)

# Ordenar os outputs por amount (ordem crescente) para preservar privacidade
new_outputs = sorted(new_outputs, key=lambda x: x["amount"])

# Salvar segredos e fatores de cegamento para descegamento posterior
swap_data = {
    "outputs": new_outputs,
    "secrets": [s.hex() for s in new_secrets],
    "r_scalars": new_r_scalars
}
with open("swap_outputs_data.json", "w") as f:
    json.dump(swap_data, f, indent=4)
print("Novos outputs, secrets e r_scalars salvos em swap_outputs_data.json")

# Requisição para a mint
payload = {
    "inputs": proofs,
    "outputs": new_outputs
}

headers = {"Content-Type": "application/json"}

print("Payload enviado:", json.dumps(payload, indent=2))

response = requests.post(MINT_URL, data=json.dumps(payload), headers=headers)

# Exibir a resposta
print("Resposta da mint:", response.status_code)
print("Conteúdo da resposta:", response.text)

if response.status_code == 200:
    swap_proofs = response.json()
    with open("swap_proofs_response.json", "w") as f:
        json.dump(swap_proofs, f, indent=4)
    print("Swap bem-sucedido! Novos proofs salvos em swap_proofs_response.json")
else:
    print("Swap falhou. Verifique os proofs ou a mint.")