import json
import secp256k1

# Configurações
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
WITNESS_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/witness_signature.json"
ADAPTOR_SIGNATURE_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/adaptor_signature_alice.json"
OUTPUT_FILE = "/Users/szerwinski/dev/Bitcoin/TCC/nutshell/bob_signature_t.json"

def load_witness_signature() -> str:
    """Carrega o escalar s do witness_signature.json."""
    with open(WITNESS_FILE, "r") as f:
        data = json.load(f)
    s_hex = data.get("s")
    if not s_hex or len(s_hex) != 64:  # 32 bytes em hex
        raise ValueError(f"Escalar s inválido: {s_hex}")
    return s_hex

def load_adaptor_signature() -> str:
    """Carrega o escalar sa de adaptor_signature_alice.json."""
    with open(ADAPTOR_SIGNATURE_FILE, "r") as f:
        data = json.load(f)
    sa_hex = data.get("sa")
    if not sa_hex or len(sa_hex) != 64:  # 32 bytes em hex
        raise ValueError(f"Escalar sa inválido: {sa_hex}")
    return sa_hex

def compute_t(s_hex: str, sa_hex: str) -> bytes:
    """Calcula t = s - sa mod n."""
    s_int = int.from_bytes(bytes.fromhex(s_hex), 'big') % CURVE_ORDER
    sa_int = int.from_bytes(bytes.fromhex(sa_hex), 'big') % CURVE_ORDER
    t_int = (s_int - sa_int) % CURVE_ORDER  # Subtração modular
    t_bytes = t_int.to_bytes(32, 'big')
    return t_bytes

def save_t(t_hex: str):
    """Salva o escalar t em um arquivo JSON."""
    output_data = {
        "t": t_hex
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(output_data, f, indent=4)
    print(f"Escalar t salvo em: {OUTPUT_FILE}")

def main():
    # Passo 1: Carregar s e sa
    try:
        s_hex = load_witness_signature()
        print(f"Escalar s (do witness): {s_hex}")
        sa_hex = load_adaptor_signature()
        print(f"Escalar sa (adaptor): {sa_hex}")
    except (FileNotFoundError, ValueError) as e:
        print(f"Erro ao carregar dados: {e}")
        return

    # Passo 2: Calcular t
    try:
        t_bytes = compute_t(s_hex, sa_hex)
        t_hex = t_bytes.hex()
        print(f"Escalar t calculado: {t_hex}")
    except ValueError as e:
        print(f"Erro ao calcular t: {e}")
        return

    # Passo 3: Salvar t
    save_t(t_hex)

if __name__ == "__main__":
    main()