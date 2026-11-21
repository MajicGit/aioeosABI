"""A fixed transaction vector from the unmodified 0.1.2 serializer."""

import hashlib
from datetime import datetime, timezone

from aioeosabi import EosAccount, EosAction, EosTransaction, serializer


def test_transaction_serialization_and_signing() -> None:
    account = EosAccount(
        name="testaccount1",
        private_key="5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
    )
    transaction = EosTransaction(
        expiration=datetime(2026, 1, 1, tzinfo=timezone.utc),
        ref_block_num=123,
        ref_block_prefix=456,
        actions=[
            EosAction(
                account="atomicassets",
                name="transfer",
                authorization=[account.authorization("active")],
                data=bytes.fromhex("01020304"),
            )
        ],
    )
    packed = serializer.serialize(transaction)
    assert packed.hex() == (
        "00b955697b00c8010000000000000180b3c2d820276936000000572d3ccdcd"
        "0110f2d4142193b1ca00000000a8ed3232040102030400"
    )
    digest = hashlib.sha256(bytes(32) + packed + bytes(32)).digest()
    assert digest.hex() == "6fbba914ec1914ce655c947f42999677dca278d2bd41297ec0edcf929b96585c"
    assert account.key.verify(account.key.sign(digest), digest)
