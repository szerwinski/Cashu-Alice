import hashlib
import json
import secrets
import requests
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_URL = "http://localhost:3338"  # Mint A
KEYSET_ID = "000b4c3d8b0e7397"  # Keyset da Mint A
ALICE_PRIVATE_KEY = "ee3375f2c778e0d0e69a8fd27679120cc447d5cf563a4cccf4e5acb0d70e939b"
ALICE_PUBLIC_KEY = "0228706e2e9726468bc8eeffeeefb21aad093922041436fd5a562b3e9a705648eb"
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141

# Passo 1: Carregar o proof de Alice (Mint A, 8 sats)
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/p2pk_unblinded_proofs.json", "r") as f:
    proofs = json.load(f)
proof = next(p for p in proofs if p["amount"] == 8)
print(f"Proof de Alice: {proof}")

# Passo 2: Verificar consistência da chave privada e pública
ka = secp256k1.PrivateKey(bytes.fromhex(ALICE_PRIVATE_KEY))
Pa = secp256k1.PublicKey(bytes.fromhex(ALICE_PUBLIC_KEY), raw=True)
derived_pubkey = ka.pubkey.serialize().hex()
print(f"Chave pública derivada da chave privada: {derived_pubkey}")
print(f"Chave pública esperada: {ALICE_PUBLIC_KEY}")
if derived_pubkey != ALICE_PUBLIC_KEY:
    raise ValueError("A chave privada não corresponde à chave pública fornecida!")

# Passo 3: Verificar a chave pública no Proof.secret
secret = proof["secret"]
try:
    secret_json = json.loads(secret)
    secret_pubkey = secret_json[1]["data"]
    print(f"Chave pública no Proof.secret: {secret_pubkey}")
    if secret_pubkey != ALICE_PUBLIC_KEY:
        raise ValueError(f"A chave pública no Proof.secret ({secret_pubkey}) não corresponde à ALICE_PUBLIC_KEY ({ALICE_PUBLIC_KEY})!")
except json.JSONDecodeError as e:
    raise ValueError(f"Erro ao parsear Proof.secret como JSON: {e}")

# Passo 4: Gerar a assinatura Schnorr
message = hashlib.sha256(secret.encode('utf-8')).digest()
print(f"Secret bruto: {repr(secret)}")
print(f"Hash da mensagem (hex): {message.hex()}")

try:
    # Gerar assinatura conforme o Cashu (bip340tag=None, raw=True)
    schnorr_signature = ka.schnorr_sign(message, None, raw=True)
    schnorr_signature_hex = schnorr_signature.hex()
    print(f"Assinatura Schnorr de Alice (64 bytes): {schnorr_signature_hex}")

    # Validar a assinatura
    is_valid = Pa.schnorr_verify(message, schnorr_signature, None, raw=True)
    print(f"Assinatura válida: {is_valid}")

    if not is_valid:
        raise ValueError("Assinatura Schnorr inválida. Atualize a biblioteca secp256k1 ou use uma alternativa como py_ecc.")
except Exception as e:
    print(f"Erro ao gerar ou verificar a assinatura Schnorr: {e}")
    raise

# Passo 5: Preparar o proof com witness
witness = {
    "signatures": [schnorr_signature_hex]
}
print(f"Witness gerado: {json.dumps(witness, indent=2)}")
proof_with_witness = {
    "amount": proof["amount"],
    "id": proof["id"],
    "secret": proof["secret"],
    "C": proof["C"],
    "witness": json.dumps(witness)
}

# Passo 6: Gerar novos outputs (2 tokens de 4 sats)
outputs = []
new_amounts = [4, 4]
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

for amount in new_amounts:
    x = secrets.token_bytes(32)
    secrets_list.append(x)
    print(f"Secret para novo output ({amount} sats): {x.hex()}")

    Y = hash_to_curve(x)
    print(f"Y: {Y.serialize().hex()}")

    r = secp256k1.PrivateKey()
    r_scalar = int.from_bytes(r.private_key, 'big')
    r_scalars.append(r_scalar)
    print(f"r_scalar: {r_scalar}")
    print(f"r.pubkey: {r.pubkey.serialize().hex()}")

    B_ = Y + r.pubkey
    print("Adição de pontos bem-sucedida")

    B_serialized = B_.serialize().hex()
    print(f"B_: {B_serialized}")

    outputs.append({
        "amount": amount,
        "id": KEYSET_ID,
        "B_": B_serialized
    })

# Passo 7: Salvar os dados dos novos outputs
swap_data = {
    "outputs": outputs,
    "secrets": [s.hex() for s in secrets_list],
    "r_scalars": r_scalars
}
with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/swap_outputs_data_alice.json", "w") as f:
    json.dump(swap_data, f, indent=4)
print("Novos outputs, secrets e r_scalars salvos em swap_outputs_data_alice.json")

# Passo 8: Enviar o pedido de swap
payload = {
    "inputs": [proof_with_witness],
    "outputs": outputs
}
headers = {"Content-Type": "application/json"}
print(f"Payload enviado: {json.dumps(payload, indent=2)}")
try:
    response = requests.post(f"{MINT_URL}/v1/swap", json=payload, headers=headers)
    print(f"Resposta da mint: {response.status_code}")
    print(f"Conteúdo da resposta: {response.text}")

    if response.status_code == 200:
        swap_response = response.json()
        with open("/Users/szerwinski/dev/Bitcoin/TCC/nutshell/swap_response_alice.json", "w") as f:
            json.dump(swap_response, f, indent=4)
        print("Swap bem-sucedido! Resposta salva em swap_response_alice.json")
    else:
        print("Swap falhou. Verifique o proof ou a mint.")
except requests.exceptions.RequestException as e:
    print(f"Erro na requisição de swap: {e}")