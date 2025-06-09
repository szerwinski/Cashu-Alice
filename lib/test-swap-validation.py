import hashlib
import json
import secrets
import requests
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_B_URL = "http://localhost:3339"  # URL da Mint B
ALICE_PRIVATE_KEY = "ee3375f2c778e0d0e69a8fd27679120cc447d5cf023a4cccf4e5acb0d70e939b"
ALICE_PUBLIC_KEY = "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5"
BOB_PUBLIC_KEY = "02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447"
BOB_SIGNATURE_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell_bob/schnorr_signature_bob.json"
T_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/bob_signature_t.json"
DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"

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

def is_valid_y(y_hex: str) -> bool:
    """Valida se o Y é um ponto comprimido válido na curva secp256k1."""
    try:
        y_bytes = bytes.fromhex(y_hex)
        if len(y_bytes) != 33 or y_bytes[0] not in (0x02, 0x03):
            print(f"Y inválido: tamanho ou prefixo incorreto ({y_hex})")
            return False
        secp256k1.PublicKey(y_bytes, raw=True)
        return True
    except ValueError:
        print(f"Y inválido: não é um ponto na curva ({y_hex})")
        return False

def check_token_state(y: str) -> str:
    """Consulta o estado do token na Mint B usando NUT-07."""
    if not is_valid_y(y):
        raise ValueError(f"Y fornecido não é válido: {y}")
    
    endpoint = f"{MINT_B_URL}/v1/checkstate"
    headers = {"Content-Type": "application/json"}
    payload = {
        "Ys": [y]
    }
    
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        states = response.json().get("states", [])
        if not states:
            print("Nenhum estado retornado pela mint.")
            return None
        state = states[0]
        y_returned = state.get("Y")
        token_state = state.get("state")
        print(f"Estado do token (Y: {y_returned}): {token_state}")
        return token_state
    except requests.exceptions.RequestException as e:
        print(f"Erro na requisição NUT-07: {e}")
        return None

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
    if not t_hex or len(t_hex) != 64:
        raise ValueError(f"Escalar t inválido: {t_hex}")
    return t_hex

def generate_alice_signature(secret: str) -> bytes:
    """Gera uma assinatura Schnorr de Alice para o secret."""
    ka = secp256k1.PrivateKey(bytes.fromhex(ALICE_PRIVATE_KEY))
    message = hashlib.sha256(secret.encode('utf-8')).digest()
    signature = ka.schnorr_sign(message, raw=True, bip340tag=None)
    return signature

def create_witness(alice_signature: bytes, bob_Rb: str, bob_t: str) -> str:
    """Cria o witness com as assinaturas de Alice e Bob."""
    alice_sig_hex = alice_signature.hex()
    bob_sig_hex = bob_Rb + bob_t
    witness = {
        "signatures": [alice_sig_hex, bob_sig_hex]
    }
    return json.dumps(witness)

def generate_test_output(amount: int, keyset_id: str) -> dict:
    """Gera um BlindedMessage para o output do swap de teste."""
    new_secret = json.dumps(["P2PK", {"nonce": secrets.token_bytes(32).hex(), "data": ALICE_PUBLIC_KEY, "tags": [["sigflag", "SIG_INPUTS"]]}]).encode('utf-8')
    Y = hash_to_curve(new_secret)
    r = secp256k1.PrivateKey()
    B_ = Y + r.pubkey
    B_serialized = B_.serialize().hex()
    print(f"Novo B_ para output: {B_serialized}")
    
    return {
        "amount": amount,
        "id": keyset_id,
        "B_": B_serialized
    }

def validate_proof_amount(proof: dict, witness: str) -> bool:
    """Valida o amount do proof com um swap de teste na Mint B."""
    output = generate_test_output(proof["amount"], proof["id"])
    
    payload = {
        "inputs": [
            {
                "amount": proof["amount"],
                "id": proof["id"],
                "secret": proof["secret"],
                "C": proof["C"],
                "witness": witness
            }
        ],
        "outputs": [output]
    }
    
    endpoint = f"{MINT_B_URL}/v1/swap"
    headers = {"Content-Type": "application/json"}
    
    print(f"Enviando swap de teste com payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        print(f"Swap de teste bem-sucedido! Amount {proof['amount']} sats é válido.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Erro no swap de teste: {e}")
        return False

def test_proof(proof: dict, manipulated_amount: int = None):
    """Testa a validade do proof, com e sem manipulação do amount."""
    # Calcular Y e verificar estado via NUT-07
    secret_bytes = proof["secret"].encode('utf-8')
    calculated_y = hash_to_curve(secret_bytes).serialize().hex()
    print(f"Ponto Y calculado: {calculated_y}")
    
    token_state = check_token_state(calculated_y)
    if token_state != "UNSPENT":
        print(f"Token não está disponível (estado: {token_state}).")
        return False
    
    # Carregar assinatura de Bob
    try:
        Rb_hex, t_hex = load_bob_signature()
        t_calculated = load_t()
        print(f"Rb de Bob: {Rb_hex}")
        print(f"t calculado: {t_calculated}")
        if t_calculated != t_hex[64:]:
            print(f"AVISO: t calculado ({t_calculated}) não corresponde a s_b ({t_hex[64:]})")
            return False
    except ValueError as e:
        print(f"Erro ao carregar assinatura de Bob: {e}")
        return False

    # Gerar assinatura de Alice
    alice_signature = generate_alice_signature(proof["secret"])
    print(f"Assinatura de Alice: {alice_signature.hex()}")

    # Criar witness
    witness = create_witness(alice_signature, Rb_hex, t_calculated)
    print(f"Witness: {witness}")

    # Testar o proof original
    print("\nTestando proof original:")
    if validate_proof_amount(proof, witness):
        print("Proof original é válido.")
    else:
        print("Proof original é inválido.")
        return False
    
    # Testar proof manipulado, se especificado
    if manipulated_amount is not None:
        manipulated_proof = proof.copy()
        manipulated_proof["amount"] = manipulated_amount
        print(f"\nTestando proof manipulado (amount: {manipulated_amount} sats):")
        if validate_proof_amount(manipulated_proof, witness):
            print("Proof manipulado foi aceito (FALHA DE SEGURANÇA)!")
            return False
        else:
            print("Proof manipulado foi rejeitado (esperado).")
    
    return True

def main():
    # Exemplo de proof recebido de Bob (substitua pelos valores reais)
    bob_proof = {
        "amount": 8,
        "id": "00afe2bda7e0855b",
        "secret": "[\"P2PK\", {\"nonce\": \"1c3ca38d62968431c88947fef98f1ff4c894a19cb0e45bcee674a9459dd5bacd\", \"data\": \"02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447\", \"tags\": [[\"sigflag\", \"SIG_INPUTS\"], [\"n_sigs\", \"2\"], [\"locktime\", \"1749506443\"], [\"refund\", \"02c15e12abf164078fd114c72b679ce186f0338de7086c559422297a76b432f447\"], [\"pubkeys\", \"02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5\"]]}]",
        "C": "0345e03fa254ad0e37f3bb2d7eeed211ce48b7ba2d3d9b5301f516b32cdb3e69b5"
    }
    
    # Testar com manipulação de amount (de 8 para 1 sat)
    manipulated_amount = 1
    
    print("Iniciando teste de validação do proof...")
    if test_proof(bob_proof, manipulated_amount):
        print("\nTeste concluído: O swap de teste validou corretamente o proof.")
    else:
        print("\nTeste concluído: O swap de teste detectou problemas no proof.")

if __name__ == "__main__":
    main()