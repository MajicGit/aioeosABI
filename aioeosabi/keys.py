"""EOS K1 key formats backed by libwally's native libsecp256k1 operations."""

import hashlib
import hmac
import secrets

import base58
import wallycore as wally

from aioeosabi.types import EosKeyWeight


class EosKey:
    """Generate, import, and sign with secp256k1 keys in EOS formats."""

    def __init__(self, *, private_key: str | None = None, public_key: str | None = None) -> None:
        if private_key and public_key:
            raise ValueError("Pass only one key")
        self._private_key: bytes | None = None
        if public_key:
            if public_key.startswith("EOS"):
                self._public_key = self._check_decode(public_key[3:])
            elif public_key.startswith("PUB_K1_"):
                self._public_key = self._check_decode(public_key[7:], "K1")
            else:
                raise ValueError("Unsupported public key format")
            if len(self._public_key) != 33:
                raise ValueError("33 byte public key required")
            wally.ec_public_key_verify(self._public_key)
        else:
            self._private_key = self._parse_key(private_key) if private_key else self._generate_key()
            wally.ec_private_key_verify(self._private_key)
            self._public_key = bytes(wally.ec_public_key_from_private_key(self._private_key))

    @staticmethod
    def _generate_key() -> bytes:
        while True:
            candidate = secrets.token_bytes(32)
            try:
                wally.ec_private_key_verify(candidate)
            except ValueError:
                continue
            return candidate

    def _parse_key(self, private_key: str) -> bytes:
        if private_key.startswith("PVT_K1_"):
            return self._check_decode(private_key[7:], "K1")
        if private_key.startswith("PVT_"):
            raise ValueError("Only K1 keys are supported")
        decoded = self._check_decode(private_key, "sha256x2")
        if len(decoded) != 33 or decoded[0] != 0x80:
            raise ValueError("Invalid WIF key")
        return decoded[1:]

    @staticmethod
    def _calculate_checksum(key: bytes, key_type: str = "") -> bytes:
        if key_type == "sha256x2":
            return hashlib.sha256(hashlib.sha256(key).digest()).digest()[:4]
        if key_type not in ("", "K1"):
            raise ValueError("Only K1 keys are supported")
        return bytes(wally.ripemd160(key + key_type.encode("ascii")))[:4]

    def _check_encode(self, key: bytes, key_type: str = "") -> str:
        return base58.b58encode(key + self._calculate_checksum(key, key_type)).decode("ascii")

    def _check_decode(self, encoded: str, key_type: str = "") -> bytes:
        decoded = base58.b58decode(encoded)
        key, checksum = decoded[:-4], decoded[-4:]
        if not key or not hmac.compare_digest(checksum, self._calculate_checksum(key, key_type)):
            raise ValueError("Invalid checksum")
        return key

    def to_public(self) -> str:
        """Return the compressed public key in legacy EOS format."""
        return f"EOS{self._check_encode(self._public_key)}"

    def to_wif(self) -> str:
        """Return the private key in legacy WIF format."""
        if self._private_key is None:
            raise ValueError("Private key required")
        return self._check_encode(b"\x80" + self._private_key, "sha256x2")

    def to_pvt(self, key_type: str = "K1") -> str:
        """Return the private key in PVT_K1 format."""
        if self._private_key is None:
            raise ValueError("Private key required")
        return f"PVT_{key_type}_{self._check_encode(self._private_key, key_type)}"

    @staticmethod
    def _is_canonical(signature: bytes) -> bool:
        # EOS requires r and s to each occupy exactly 32 bytes in DER encoding.
        return all(
            not signature[offset] & 0x80
            and not (signature[offset] == 0 and not signature[offset + 1] & 0x80)
            for offset in (1, 33)
        )

    def sign(self, digest: bytes) -> str:
        """Sign a SHA-256 digest as a canonical, recoverable SIG_K1 signature."""
        if len(digest) != 32:
            raise ValueError("32 byte buffer required")
        if self._private_key is None:
            raise ValueError("Private key required")
        flags = wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE
        for counter in range(256):
            # Auxiliary data changes RFC6979's nonce without changing the digest.
            auxiliary = counter.to_bytes(32, "big") if counter else None
            signature = bytes(wally.ec_sig_from_bytes_aux(self._private_key, digest, auxiliary, flags))
            if self._is_canonical(signature):
                return f"SIG_K1_{self._check_encode(signature, 'K1')}"
        raise RuntimeError("Unable to produce a canonical signature")

    def verify(self, encoded_sig: str, digest: bytes) -> bool:
        """Verify a recoverable signature, including signatures made by upstream."""
        try:
            if len(digest) != 32 or not encoded_sig.startswith("SIG_K1_"):
                return False
            signature = self._check_decode(encoded_sig[7:], "K1")
            if len(signature) != 65 or not 31 <= signature[0] <= 34:
                return False
            recovered = bytes(wally.ec_sig_to_public_key(digest, signature))
            return hmac.compare_digest(recovered, self._public_key)
        except (ValueError, TypeError):
            return False

    def to_key_weight(self, weight: int) -> EosKeyWeight:
        return EosKeyWeight(key=self.to_public(), weight=weight)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EosKey):
            return NotImplemented
        return self._public_key == other._public_key
