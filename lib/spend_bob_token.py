import hashlib
import json
import secrets
import requests
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_B_URL = "http://localhost:3339"  # URL da Mint B
BOB_PROOFS_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/p2pk_unblinded_proofs_bob.json"
BOB_SIGNATURE_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/schnorr_signature_bob.json"
T_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/bob_signature_t.json"
ALICE_PRIVATE_KEY = "ee3375f2c778e0d0e69a8fd27679120cc447d5cf023a4cccf4e5acb0d70e939b"
ALICE_PUBLIC_KEY = "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5"
BOB_PUBLIC_KEY = "02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"
OUTPUT_PROOFS_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/new_proofs_alice.json"

def tagged_hash(tag: str, data: bytes) -> bytes:
    """Calcula um hash etiquetado conforme BIP-340: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()

def has_even_y(point: secp256k1.PublicKey) -> bool:
    """Verifica se a coordenada y do ponto é par, conforme BIP-340."""
    serialized = point.serialize()
    return serialized[0] == 0x02  # 0x02 indica y par, 0x03 indica y ímpar

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

def load_bob_proof(amount: int) -> dict:
    """Carrega o Proof de Bob para o valor especificado."""
    with open(BOB_PROOFS_FILE, "r") as f:
        proofs = json.load(f)
    
    for proof in proofs:
        if proof["amount"] == amount:
            return proof
    
    raise ValueError(f"Nenhum Proof encontrado para {amount} sats")

def load_bob_signature() -> tuple[str, str]:
    """Carrega Rb e t de schnorr_signature_bob.json."""
    with open(BOB_SIGNATURE_FILE, "r") as f:
        data = json.load(f)
    Rb_hex = data.get("Rb")
    t_hex = data.get("t")
    if not Rb_hex or not t_hex:
        raise ValueError("Rb ou t inválidos em schnorr_signature_bob.json")
    return Rb_hex, t_hex

def load_t() -> str:
    """Carrega o escalar t de bob_signature_t.json."""
    with open(T_FILE, "r") as f:
        data = json.load(f)
    t_hex = data.get("t")
    if not t_hex or len(t_hex) != 64:  # 32 bytes em hex
        raise ValueError(f"Escalar t inválido: {t_hex}")
    return t_hex

def generate_alice_signature(secret: str, private_key: secp256k1.PrivateKey) -> bytes:
    """Gera uma assinatura Schnorr de Alice para o secret."""
    # Calcular H(secret)
    message = hashlib.sha256(secret.encode('utf-8')).digest()
    
    # Assinatura Schnorr usando a biblioteca
    signature = private_key.schnorr_sign(message, raw=True, bip340tag=None)
    return signature

def create_witness(signatures: list[bytes]) -> str:
    """Cria o witness com as assinaturas fornecidas."""
    witness = {
        "signatures": [sig.hex() for sig in signatures]
    }
    return json.dumps(witness)

def generate_new_output(amount: int, keyset_id: str) -> tuple[dict, bytes]:
    """Gera um novo output com um secret P2PK, Y, e B_."""
    # Gere o secret no formato P2PK
    nonce = secrets.token_bytes(32).hex()
    p2pk_secret = [
        "P2PK",
        {
            "nonce": nonce,
            "data": ALICE_PUBLIC_KEY,
            "tags": [["sigflag", "SIG_INPUTS"]]
        }
    ]
    secret_str = json.dumps(p2pk_secret)
    secret_bytes = secret_str.encode('utf-8')
    print(f"Novo secret P2PK: {secret_str}")

    # Gere o ponto Y
    Y = hash_to_curve(secret_bytes)
    print(f"Novo Y: {Y.serialize().hex()}")

    # Gere o fator de cegamento r
    r = secp256k1.PrivateKey()
    print(f"Novo r.pubkey: {r.pubkey.serialize().hex()}")

    # Calcule B_ = Y + r * G
    B_ = Y + r.pubkey
    B_serialized = B_.serialize().hex()
    print(f"Novo B_: {B_serialized}")

    output = {
        "amount": amount,
        "id": keyset_id,
        "B_": B_serialized
    }
    
    return output, secret_bytes

def swap_token(proof: dict, input_witness: str) -> dict:
    """Envia a requisição de swap para a Mint B."""
    endpoint = f"{MINT_B_URL}/v1/swap"
    headers = {"Content-Type": "application/json"}
    
    # Gerar novo output
    new_output, new_secret = generate_new_output(proof["amount"], proof["id"])
    
    payload = {
        "inputs": [
            {
                "amount": proof["amount"],
                "id": proof["id"],
                "secret": proof["secret"],
                "C": proof["C"],
                "witness": input_witness
            }
        ],
        "outputs": [new_output]
    }
    
    print(f"Payload enviado: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição de swap: {e}")
        return None

def validate_signature(pubkey: str, message: bytes, signature: bytes) -> bool:
    """Valida uma assinatura Schnorr para depuração."""
    try:
        pub = secp256k1.PublicKey(bytes.fromhex(pubkey), raw=True)
        return pub.schnorr_verify(message, signature, bip340tag=None)
    except Exception as e:
        print(f"Erro na validação da assinatura: {e}")
        return False

def main():
    # Passo 1: Carregar o Proof de Bob (8 sats)
    try:
        proof = load_bob_proof(8)
        print(f"Proof de Bob carregado: {proof['secret']}")
    except ValueError as e:
        print(f"Erro: {e}")
        return

    # Passo 2: Verificar o secret multisig
    secret_json = json.loads(proof["secret"])
    if not (secret_json[1]["data"] == BOB_PUBLIC_KEY and ["pubkeys", ALICE_PUBLIC_KEY] in secret_json[1]["tags"]):
        print(f"Secret não é multisig com Bob e Alice: {proof['secret']}")
        return
    if not ["sigflag", "SIG_INPUTS"] in secret_json[1]["tags"]:
        print(f"Secret não contém sigflag SIG_INPUTS: {proof['secret']}")
        return

    # Passo 3: Carregar Rb e t de Bob
    try:
        Rb_hex, t_hex = load_bob_signature()
        print(f"Rb de Bob: {Rb_hex}")
    except ValueError as e:
        print(f"Erro ao carregar assinatura de Bob: {e}")
        return

    # Passo 4: Carregar t calculado
    try:
        t_calculated = load_t()
        print(f"t calculado: {t_calculated}")
        if t_calculated != t_hex[64:]:  # Compara com s_b (últimos 32 bytes de t)
            print(f"AVISO: t calculado ({t_calculated}) não corresponde a s_b ({t_hex[64:]})")
    except ValueError as e:
        print(f"Erro ao carregar t: {e}")
        return

    # Passo 5: Gerar a assinatura de Alice para o input
    try:
        ka = secp256k1.PrivateKey(bytes.fromhex(ALICE_PRIVATE_KEY))
        alice_input_signature = generate_alice_signature(proof["secret"], ka)
        print(f"Assinatura de Alice (input): {alice_input_signature.hex()}")
        
        # Validar a assinatura de Alice
        message = hashlib.sha256(proof["secret"].encode('utf-8')).digest()
        is_valid = validate_signature(ALICE_PUBLIC_KEY, message, alice_input_signature)
        print(f"Assinatura de Alice válida: {is_valid}")
    except Exception as e:
        print(f"Erro ao gerar assinatura de Alice: {e}")
        return

    # Passo 6: Validar a assinatura de Bob
    try:
        bob_input_signature = bytes.fromhex(Rb_hex + t_calculated)
        is_valid = validate_signature(BOB_PUBLIC_KEY, message, bob_input_signature)
        print(f"Assinatura de Bob válida: {is_valid}")
    except Exception as e:
        print(f"Erro ao validar assinatura de Bob: {e}")
        return

    # Passo 7: Criar o witness para o input
    input_witness = create_witness([alice_input_signature, bob_input_signature])
    print(f"Witness (input): {input_witness}")

    # Passo 8: Realizar o swap
    response = swap_token(proof, input_witness)
    if response:
        print("Swap bem-sucedido!")
        # Salvar os novos proofs retornados
        with open(OUTPUT_PROOFS_FILE, "w") as f:
            json.dump(response, f, indent=4)
        print(f"Novos proofs salvos em: {OUTPUT_PROOFS_FILE}")
    else:
        print("Falha no swap.")

if __name__ == "__main__":
    main()