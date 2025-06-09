from secp256k1 import PrivateKey, PublicKey

# Extensão da classe PublicKey para suportar operações do Cashu
class PublicKeyExt(PublicKey):
    def __add__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            new_pub = PublicKey()
            new_pub.combine([self.public_key, pubkey2.public_key])
            return new_pub
        else:
            raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def __neg__(self):
        serialized = self.serialize()
        first_byte, remainder = serialized[:1], serialized[1:]
        # Flip odd/even byte
        first_byte = {b"\x03": b"\x02", b"\x02": b"\x03"}[first_byte]
        return PublicKey(first_byte + remainder, raw=True)

    def __sub__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            return self + (-pubkey2)
        else:
            raise TypeError(f"Can't add pubkey and {pubkey2.__class__}")

    def mult(self, privkey):
        if isinstance(privkey, PrivateKey):
            return self.tweak_mul(privkey.private_key)
        else:
            raise TypeError("Can't multiply with non privatekey")

    def __eq__(self, pubkey2):
        if isinstance(pubkey2, PublicKey):
            seq1 = self.to_data()
            seq2 = pubkey2.to_data()
            return seq1 == seq2
        else:
            raise TypeError(f"Can't compare pubkey and {pubkey2.__class__}")

    def to_data(self):
        assert self.public_key
        return [self.public_key.data[i] for i in range(64)]

# Monkeypatching da classe PublicKey
PublicKey.__add__ = PublicKeyExt.__add__
PublicKey.__neg__ = PublicKeyExt.__neg__
PublicKey.__sub__ = PublicKeyExt.__sub__
PublicKey.mult = PublicKeyExt.mult
PublicKey.__eq__ = PublicKeyExt.__eq__
PublicKey.to_data = PublicKeyExt.to_data