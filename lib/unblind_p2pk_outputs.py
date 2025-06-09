import hashlib
import json
import secp256k1
from secp256k1_ext import *  # Importa o monkeypatching

# Configurações
MINT_URL = "http://localhost:3338"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAaedce6af48a03bbfd25e8cd0364141
PUBLIC_KEY_8 = "037a1fc79515736aa955efd758e12e10f93f9a8751b8301a254bcb10cace111028"
PUBLIC_KEY_2 = "0216fb146ffeb4cdf94e25ec0635f31c6934fad46dbcfee18e3a5db885fe79875c"

def hash_to_curve(secret: bytes, counter=0) -> secp256k1.PublicKey:
    """Converte um segredo em um ponto Y na curva usando hash_to_curve, conforme Cashu."""
    DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"
    msg_to_hash = hashlib.sha256(DOMAIN_SEPARATOR + secret).digest()
    while counter < 2**16:
        _hash = hashlib.sha256(msg_to_hash + counter.to_bytes(4, "little")).digest()
        try:
            return secp256k1.PublicKey(b"\x02" + _hash, raw=True)
        except Exception:
            counter += 1
    raise ValueError("No valid point found after 2**16 iterations.")

def hash_e(*publickeys: secp256k1.PublicKey) -> bytes:
    """Calcula o hash e = H(R1, R2, A, C_) para validação DLEQ, conforme Cashu."""
    e_ = ""
    for p in publickeys:
        _p = p.serialize(compressed=False).hex()
        e_ += str(_p)
    e = hashlib.sha256(e_.encode("utf-8")).digest()
    return e

def alice_verify_dleq(B_: secp256k1.PublicKey, C_: secp256k1.PublicKey, e: secp256k1.PrivateKey, s: secp256k1.PrivateKey, A: secp256k1.PublicKey) -> bool:
    """Verifica a equação DLEQ: e == hash_e(R1, R2, A, C_)."""
    R1 = s.pubkey - A.mult(e)
    R2 = B_.mult(s) - C_.mult(e)
    e_computed = hash_e(R1, R2, A, C_)
    print(f"R1: {R1.serialize().hex()}")
    print(f"R2: {R2.serialize().hex()}")
    print(f"A: {A.serialize().hex()}")
    print(f"C_: {C_.serialize().hex()}")
    print(f"e.private_key: {e.private_key.hex()}")
    print(f"e_computed: {e_computed.hex()}")
    return e.private_key == e_computed

def carol_verify_dleq(secret: bytes, r: secp256k1.PrivateKey, C: secp256k1.PublicKey, e: secp256k1.PrivateKey, s: secp256k1.PrivateKey, A: secp256k1.PublicKey) -> bool:
    """Verifica o DLEQ para um proof descegado."""
    Y = hash_to_curve(secret)
    C_ = C + A.mult(r)
    B_ = Y + r.pubkey
    print(f"Y: {Y.serialize().hex()}")
    print(f"C_: {C_.serialize().hex()}")
    print(f"B_: {B_.serialize().hex()}")
    return alice_verify_dleq(B_, C_, e, s, A)

def unblind_proofs(proofs_list, r_scalars, secrets):
    """
    Descega os proofs manualmente com base nos dados fornecidos, usando C = C_ - r * P.
    """
    proofs_unblinded = []

    for i, proof in enumerate(proofs_list):
        # Extraia os dados do proof
        amount = proof["amount"]
        id = proof["id"]
        C_ = proof["C_"]
        r_scalar = r_scalars[i]
        secret_hex = secrets[i]

        # Converte o secret de hex para bytes
        secret_bytes = bytes.fromhex(secret_hex)

        secret_json = json.loads(secret_bytes.decode('utf-8'))
        if secret_json[1]["data"] != "02c776bf1be8e58e9b900ecb9bd414fe48fe99bad2cb76754d39c2c3c7b519a2e5":
            raise ValueError(f"Chave pública no secret não corresponde: {secret_json[1]['data']}")

        # Para P2PK, o secret é uma string JSON serializada
        try:
            secret_json = json.loads(secret_bytes.decode('utf-8'))
            print(f"secret ${i} (P2PK JSON): {secret_json}")
        except json.JSONDecodeError:
            print(f"secret ${i} (não-P2PK): {secret_hex}")

        # Seleciona a chave pública com base no amount
        if amount == 8:
            P_hex = PUBLIC_KEY_8
        elif amount == 2:
            P_hex = PUBLIC_KEY_2
        else:
            raise ValueError(f"Chave pública não definida para o amount {amount} sats.")

        print(f"\nDescegando proof para {amount} sats:")
        print(f"Chave pública (P): {P_hex}")
        print(f"C_: {C_}")
        print(f"r_scalar: {r_scalar}")
        print(f"secret (hex): {secret_hex}")

        # Converte a chave pública P e C_ para objetos PublicKey
        try:
            P = secp256k1.PublicKey(bytes.fromhex(P_hex), raw=True)
            C_pubkey = secp256k1.PublicKey(bytes.fromhex(C_), raw=True)
        except Exception as e:
            raise ValueError(f"Erro ao converter chaves: {str(e)}")

        # Valida r_scalar
        if not (0 < r_scalar < CURVE_ORDER):
            raise ValueError(f"Fator de cegamento inválido: {r_scalar}")

        # Cria um objeto PrivateKey para r
        r = secp256k1.PrivateKey(r_scalar.to_bytes(32, 'big'))

        # Descegar: C = C_ - r * P
        try:
            C = C_pubkey - P.mult(r)
            print(f"C após descegamento: {C.serialize().hex()}")
            print("Descegamento bem-sucedido")
        except Exception as e:
            raise ValueError(f"Erro ao descegar proof: {str(e)}")

        # Monta o proof descegado
        proof_unblinded = {
            "amount": amount,
            "id": id,
            "secret": secret_bytes.decode('utf-8'),  # Salva como string JSON para P2PK
            "C": C.serialize().hex()
        }
        proofs_unblinded.append(proof_unblinded)
        print(f"Proof descegado: {proof_unblinded}")

    return proofs_unblinded

def verify_proofs_dleq(proofs_list, r_scalars, secrets):
    """
    Verifica os proofs descegados usando DLEQ, baseado no Cashu.
    """
    for i, proof in enumerate(proofs_list):
        amount = proof["amount"]
        id = proof["id"]
        C_ = proof["C_"]
        dleq = proof.get("dleq")
        if not dleq:
            print(f"Prova DLEQ não fornecida para {amount} sats.")
            continue

        r_scalar = r_scalars[i]
        secret_hex = secrets[i]
        secret_bytes = bytes.fromhex(secret_hex)

        # Seleciona a chave pública com base no amount
        if amount == 8:
            P_hex = PUBLIC_KEY_8
        elif amount == 2:
            P_hex = PUBLIC_KEY_2
        else:
            raise ValueError(f"Chave pública não definida para o amount {amount} sats.")

        print(f"\nVerificando DLEQ para {amount} sats:")
        print(f"secret (hex): {secret_hex}")
        print(f"C_: {C_}")
        print(f"r_scalar: {r_scalar}")
        print(f"e: {dleq['e']}")
        print(f"s: {dleq['s']}")

        try:
            P = secp256k1.PublicKey(bytes.fromhex(P_hex), raw=True)
            C_pubkey = secp256k1.PublicKey(bytes.fromhex(C_), raw=True)
            r = secp256k1.PrivateKey(r_scalar.to_bytes(32, 'big'))
            e = secp256k1.PrivateKey(bytes.fromhex(dleq["e"]))
            s = secp256k1.PrivateKey(bytes.fromhex(dleq["s"]))
        except Exception as e:
            print(f"Erro ao converter chaves ou DLEQ: {str(e)}")
            return False

        # Calcula C descegado para validação
        C = C_pubkey - P.mult(r)

        # Verifica DLEQ
        valid = carol_verify_dleq(secret_bytes, r, C, e, s, P)
        if not valid:
            print(f"Validação DLEQ falhou para {amount} sats.")
            return False
        print(f"Validação DLEQ bem-sucedida para {amount} sats.")

    return True

if __name__ == "__main__":
    # Carregar os dados gerados por gen_p2pk_outputs.py
    with open("p2pk_outputs_data.json", "r") as f:
        output_data = json.load(f)
    secrets = [s for s in output_data["secrets"]]  # Já estão em hex
    r_scalars = output_data["r_scalars"]

    # Carregar os proofs retornados pela mint
    with open("p2pk_proofs_response.json", "r") as f:
        proofs_data = json.load(f)

    # Acessar a lista de provas
    proofs_list = proofs_data["signatures"]

    # Imprimir os secrets e r_scalars para verificação
    print("Secrets (hex):", secrets)
    print("r_scalars:", r_scalars)

    # Descegar os proofs
    unblinded_proofs = unblind_proofs(proofs_list, r_scalars, secrets)

    # Verificar DLEQ
    is_valid = verify_proofs_dleq(proofs_list, r_scalars, secrets)
    print(f"Validação geral dos proofs: {is_valid}")

    # Salvar os proofs descegados
    with open("p2pk_unblinded_proofs.json", "w") as f:
        json.dump(unblinded_proofs, f, indent=4)
    print("Proofs descegados salvos em p2pk_unblinded_proofs.json")

    