"""Compatibility vectors use public test keys, never production keys."""

import hashlib

import base58
import pytest
import wallycore as wally
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from aioeosabi import EosKey

WIF = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"
PVT = "PVT_K1_1111111111111111111111111111111D8bqLH"
PUBLIC = "EOS5p78kHbL33Rn3JWkTWRE2B9uz6gy4r1KbfAKLNQGE3ovMBS5bu"
PUBLIC_BYTES = bytes.fromhex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")


def decode_signature(signature: str) -> bytes:
    decoded = base58.b58decode(signature.removeprefix("SIG_K1_"))
    payload, checksum = decoded[:-4], decoded[-4:]
    assert bytes(wally.ripemd160(payload + b"K1"))[:4] == checksum
    return payload


@pytest.mark.parametrize("private_key", [WIF, PVT])
def test_upstream_key_formats(private_key: str) -> None:
    key = EosKey(private_key=private_key)
    assert key.to_public() == PUBLIC
    assert key.to_wif() == WIF
    assert key.to_pvt() == PVT
    assert key.to_key_weight(3).key == PUBLIC
    assert key.to_key_weight(3).weight == 3


@pytest.mark.parametrize("number", range(32))
def test_signatures_are_canonical_recoverable_and_independently_valid(number: int) -> None:
    key = EosKey(private_key=WIF)
    digest = hashlib.sha256(f"wax-transaction-{number}".encode()).digest()
    encoded = key.sign(digest)
    signature = decode_signature(encoded)
    assert len(signature) == 65
    assert 31 <= signature[0] <= 34
    for offset in (1, 33):
        assert not signature[offset] & 0x80
        assert signature[offset] != 0 or signature[offset + 1] & 0x80
    assert bytes(wally.ec_sig_to_public_key(digest, signature)) == PUBLIC_BYTES
    verifier = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), PUBLIC_BYTES)
    der = utils.encode_dss_signature(int.from_bytes(signature[1:33], "big"), int.from_bytes(signature[33:], "big"))
    verifier.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    assert key.verify(encoded, digest)
    assert encoded == key.sign(digest)


@pytest.mark.parametrize(
    ("message", "signature"),
    [
        ("greenwiz compatibility", "SIG_K1_KgREauitgfxNed3w55akj5zdVcoABbHJa58dPNWbwTUcQVuKLLEwBzXws6FUSuJ7pMDcDobqF3p2ysrCruCv5eDP5gotDx"),
        ("claimlink", "SIG_K1_KAK8C6hXUrejhZkvdqpSxCPLTpCNsFwdYDJk32XHK6akRU7aEyAZwaJsxeqMgphd4DqhdrFBFt3WSTPsiKnGJtq918idAs"),
        ("transfer", "SIG_K1_KYqkV4yBBaR3CfgvdY2aypvXarqpzGK192hH8vctQRSVKBbuojJqymooiaCB2obrLXJA37FksvungtpanQ8RS8oKx2hzNe"),
    ],
)
def test_verifies_signatures_created_by_aioeosabi_012(message: str, signature: str) -> None:
    key = EosKey(public_key=PUBLIC)
    digest = hashlib.sha256(message.encode()).digest()
    assert key.verify(signature, digest)
    assert not key.verify(signature, hashlib.sha256(b"different transaction").digest())
    assert not EosKey().verify(signature, digest)


def test_generated_keys_round_trip_and_public_only_verification() -> None:
    first, second = EosKey(), EosKey()
    assert first != second
    assert EosKey(private_key=first.to_wif()) == first
    assert EosKey(private_key=first.to_pvt()) == first
    public = EosKey(public_key=first.to_public())
    digest = hashlib.sha256(b"claimlink").digest()
    assert public.verify(first.sign(digest), digest)
    for operation in (public.to_wif, public.to_pvt, lambda: public.sign(digest)):
        with pytest.raises(ValueError, match="Private key required"):
            operation()


def test_pub_k1_format() -> None:
    checksum = bytes(wally.ripemd160(PUBLIC_BYTES + b"K1"))[:4]
    encoded = "PUB_K1_" + base58.b58encode(PUBLIC_BYTES + checksum).decode()
    assert EosKey(public_key=encoded).to_public() == PUBLIC


@pytest.mark.parametrize("size", [0, 31, 33])
def test_rejects_incorrect_digest_length(size: int) -> None:
    with pytest.raises(ValueError, match="32 byte buffer required"):
        EosKey(private_key=WIF).sign(bytes(size))


@pytest.mark.parametrize("encoded", [WIF[:-1] + "1", PVT[:-1] + "1", "PVT_R1_invalid", "not a key"])
def test_rejects_invalid_private_keys(encoded: str) -> None:
    with pytest.raises(ValueError):
        EosKey(private_key=encoded)


@pytest.mark.parametrize("scalar", [0, 2**256 - 1])
def test_rejects_invalid_scalars(scalar: int) -> None:
    encoded = base58.b58encode_check(b"\x80" + scalar.to_bytes(32, "big")).decode()
    with pytest.raises(ValueError):
        EosKey(private_key=encoded)


@pytest.mark.parametrize("encoded", [PUBLIC[:-1] + "1", "PUB_R1_invalid", "not a key"])
def test_rejects_invalid_public_keys(encoded: str) -> None:
    with pytest.raises(ValueError):
        EosKey(public_key=encoded)


def test_rejects_malformed_signatures() -> None:
    key = EosKey(private_key=WIF)
    digest = hashlib.sha256(b"wax transaction").digest()
    signature = key.sign(digest)
    for encoded in ("", "SIG_R1_invalid", "SIG_K1_invalid", signature[:-1] + "0"):
        assert not key.verify(encoded, digest)
    assert not key.verify(signature, b"short")


def test_canonical_retry_preserves_the_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    original = wally.ec_sig_from_bytes_aux
    calls = []
    digest = hashlib.sha256(b"canonical retry").digest()

    def sign(private_key: bytes, message: bytes, auxiliary: bytes | None, flags: int) -> bytes:
        calls.append((message, auxiliary))
        if len(calls) == 1:
            return bytes([31, 128]) + bytes(63)
        return original(private_key, message, auxiliary, flags)

    monkeypatch.setattr(wally, "ec_sig_from_bytes_aux", sign)
    key = EosKey(private_key=WIF)
    signature = key.sign(digest)
    assert key.verify(signature, digest)
    assert len(calls) > 1
    assert calls[0] == (digest, None)
    assert calls[1] == (digest, (1).to_bytes(32, "big"))
    assert all(message == digest for message, _ in calls)
