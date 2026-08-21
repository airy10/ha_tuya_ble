"""Off-hardware checks for the Tuya lock credential codec.

Every layout asserted here was captured from a real lock. The codec imports
neither Home Assistant nor bleak, so this needs nothing but Python.

    python3 tests/test_lock_credentials.py

Set REPO_ROOT to point it at another checkout.
"""
import os
import sys
from pathlib import Path

REPO = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(REPO / "custom_components" / "tuya_ble"))

import lock_credentials as lc  # noqa: E402

FAILURES = []


def check(name, got, expected):
    if got != expected:
        FAILURES.append(f"{name}\n     got: {got!r}\nexpected: {expected!r}")
    else:
        print(f"  ok  {name}")


def check_raises(name, exc, fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except exc:
        print(f"  ok  {name}")
    except Exception as err:  # noqa: BLE001
        FAILURES.append(f"{name}\n     got: {type(err).__name__}: {err}\nexpected: {exc.__name__}")
    else:
        FAILURES.append(f"{name}\n     got: no exception\nexpected: {exc.__name__}")


print("encode_add")
# Type | Stage | Admin | MemberID(2) | HardwareID(2) | Validity(17) | Times |
# PwdLen | Pwd(n) | MsgUUID(2)
add = lc.encode_add(
    lc.CredentialType.FINGERPRINT,
    0x1234,
    member_id=1,
)
check("length with no secret", len(add), 1 + 1 + 1 + 2 + 2 + 17 + 1 + 1 + 0 + 2)
check("type byte", add[0], 0x03)
check("stage byte defaults to start", add[1], 0x00)
check("admin byte defaults to ordinary", add[2], 0x00)
check("member id big endian", add[3:5], b"\x00\x01")
check("hardware id defaults to auto", add[5:7], b"\xff\xff")
check("validity block is zeroed", add[7:24], bytes(17))
check("times", add[24], 0x00)
check("password length is zero", add[25], 0x00)
check("message uuid big endian", add[26:28], b"\x12\x34")

add_pwd = lc.encode_add(
    lc.CredentialType.PASSWORD,
    0x0001,
    member_id=7,
    hardware_id=3,
    admin=True,
    times=5,
    secret=b"1234",
)
check("admin flag", add_pwd[2], 0x01)
check("explicit hardware id", add_pwd[5:7], b"\x00\x03")
check("times carried", add_pwd[24], 0x05)
check("password length", add_pwd[25], 4)
check("password content", add_pwd[26:30], b"1234")
check("uuid after password", add_pwd[30:32], b"\x00\x01")

cancel = lc.encode_add(
    lc.CredentialType.FINGERPRINT,
    0x0002,
    member_id=1,
    stage=lc.AddStage.CANCEL,
)
check("cancel stage", cancel[1], 0xFE)

check_raises(
    "member id out of range rejected",
    ValueError,
    lc.encode_add,
    lc.CredentialType.FINGERPRINT,
    1,
    member_id=0x10000,
)
check_raises(
    "message uuid out of range rejected",
    ValueError,
    lc.encode_add,
    lc.CredentialType.FINGERPRINT,
    0x10000,
    member_id=1,
)
check_raises(
    "secret longer than one byte length rejected",
    ValueError,
    lc.encode_add,
    lc.CredentialType.PASSWORD,
    1,
    member_id=1,
    secret=b"x" * 256,
)

print("decode_add_report")
# Captured from a real enrollment. Seven bytes, no echo of the
# message uuid the request carried:
#   type | result | ?? (2) | hardware id | step | quality
accepted = lc.decode_add_report(bytes.fromhex("03000000040500"))
check("accepted type", accepted.type, lc.CredentialType.FINGERPRINT)
check("accepted result", accepted.result, lc.AddResult.ACCEPTED)
check("acceptance is not completion", accepted.succeeded, False)
check("lock assigned hardware id 4", accepted.hardware_id, 4)
check("lock wants five touches", accepted.step, 5)
check("acceptance is not progress", accepted.in_progress, False)

for step, raw in enumerate(
    ["03fc0000040125", "03fc0000040225", "03fc0000040325", "03fc0000040425"], start=1
):
    touch = lc.decode_add_report(bytes.fromhex(raw))
    check(f"touch {step} is in progress", touch.in_progress, True)
    check(f"touch {step} step number", touch.step, step)
    check(f"touch {step} hardware id", touch.hardware_id, 4)
    check(f"touch {step} has not succeeded yet", touch.succeeded, False)

last_touch = lc.decode_add_report(bytes.fromhex("03fc0000040500"))
check("fifth touch is still in progress", last_touch.in_progress, True)

done = lc.decode_add_report(bytes.fromhex("03ff0000040000"))
check("enrollment finished", done.succeeded, True)
check("finished is not in progress", done.in_progress, False)
check("finished keeps the hardware id", done.hardware_id, 4)

# The whole enrollment, in the order the lock sent it. Exactly one report may
# end the wait, and it must be the last: resolving on the acceptance ack makes
# a healthy enrollment look like a refusal.
ENROLLMENT = [
    "03000000040500",
    "03fc0000040125",
    "03fc0000040225",
    "03fc0000040325",
    "03fc0000040425",
    "03fc0000040500",
    "03ff0000040000",
]
terminal = [lc.decode_add_report(bytes.fromhex(r)).is_terminal for r in ENROLLMENT]
check("exactly one report ends the enrollment", terminal.count(True), 1)
check("and it is the last one", terminal[-1], True)
check("the acceptance ack does not end it", terminal[0], False)
check(
    "a refusal also ends it",
    lc.decode_add_report(bytes.fromhex("03fd0000040000")).is_terminal,
    True,
)
check(
    "a refusal has not succeeded",
    lc.decode_add_report(bytes.fromhex("03fd0000040000")).succeeded,
    False,
)

check_raises("short add report rejected", lc.TuyaLockCredentialError, lc.decode_add_report, b"\x03\x00")
check_raises(
    "unknown result byte rejected",
    lc.TuyaLockCredentialError,
    lc.decode_add_report,
    bytes.fromhex("03420000040000"),
)

print("encode_delete")
# The lock acts on the FIRST two byte id field, not the second one the
# reference names, so the id is written into both.
delete = lc.encode_delete(lc.CredentialType.FINGERPRINT, credential_id=4)
check("delete length", len(delete), 8)
check("delete type", delete[0], 0x03)
check("delete stage is zero", delete[1], 0x00)
check("credential id goes in the field the lock honours", delete[3:5], b"\x00\x04")
check("and in the second field too, so either reading hits it", delete[5:7], b"\x00\x04")
check("delete mode is single credential, never member", delete[7], 0x01)
check_raises(
    "credential id out of range rejected",
    ValueError,
    lc.encode_delete,
    lc.CredentialType.FINGERPRINT,
    credential_id=0x10000,
)

# The exact bytes that deleted credential 2, kept as a regression guard.
check(
    "reproduces the payload that deleted credential 2",
    lc.encode_delete(lc.CredentialType.FINGERPRINT, credential_id=2),
    bytes.fromhex("0300000002000201"),
)

print("decode_delete_report")
# Captured: the lock echoed the id it acted on and reported success.
drep = lc.decode_delete_report(bytes.fromhex("030000000200ff"))
check("delete report echoes the credential id", drep.credential_id, 2)
check("delete succeeded on 0xFF", drep.succeeded, True)
notfound = lc.decode_delete_report(bytes.fromhex("03000000020001"))
check("delete failed on unknown id", notfound.succeeded, False)
check("delete result readable", notfound.result, lc.DeleteResult.UNKNOWN_ID)
check_raises(
    "short delete report rejected",
    lc.TuyaLockCredentialError,
    lc.decode_delete_report,
    b"\x03\x00",
)

print("encode_sync_request")
check(
    "single type",
    lc.encode_sync_request([lc.CredentialType.FINGERPRINT]),
    b"\x03",
)
check(
    "several types, deduplicated and ordered",
    lc.encode_sync_request(
        [lc.CredentialType.CARD, lc.CredentialType.FINGERPRINT, lc.CredentialType.CARD]
    ),
    b"\x02\x03",
)
check_raises("empty sync request rejected", ValueError, lc.encode_sync_request, [])

print("decode_sync_report")
# Captured from the 0qxp5u7s in answer to a request for
# fingerprints, on a lock the owner confirms holds exactly four of them.
# Stage 0x00 | Seq 0x00, then four records of
# hardware id | credential type | admin flag | valid.
CAPTURE = bytes.fromhex("00000003ff01010301010203010103030101")
CAPTURE_TAIL = bytes.fromhex("0101")

real = lc.decode_sync_report(CAPTURE)
check("capture is not the closing packet", real.finished, False)
check("capture sequence", real.sequence, 0)
check("capture holds four credentials", len(real.credentials), 4)
check(
    "capture hardware ids",
    tuple(c.hardware_id for c in real.credentials),
    (0, 1, 2, 3),
)
check(
    "every capture record is a fingerprint",
    {c.type for c in real.credentials},
    {lc.CredentialType.FINGERPRINT},
)
check(
    "capture admin flags",
    tuple(c.admin_flag for c in real.credentials),
    (0xFF, 0x01, 0x01, 0x01),
)
check("every capture record is valid", {c.valid for c in real.credentials}, {True})

# The record this integration created, with admin explicitly not set. It is
# the only one whose admin byte is zero, which is what identified that byte.
AFTER_ENROLL = bytes.fromhex("00000003ff0101030101020301010303010104030001")
mine = lc.decode_sync_report(AFTER_ENROLL).credentials[-1]
check("own record hardware id", mine.hardware_id, 4)
check("own record is not admin", mine.is_admin, False)
check("own record is valid", mine.valid, True)
check(
    "the four app-made records are all admin",
    all(c.is_admin for c in lc.decode_sync_report(AFTER_ENROLL).credentials[:4]),
    True,
)
check(
    "hardware id 2 is present, the one DP 12 reports",
    2 in {c.hardware_id for c in real.credentials},
    True,
)

tail = lc.decode_sync_report(CAPTURE_TAIL)
check("capture tail is the closing packet", tail.finished, True)
check("capture tail packet count", tail.total_packets, 1)
check("closing packet carries no credentials", tail.credentials, ())

empty = lc.decode_sync_report(bytes([0x00, 0x00]))
check("packet with no records", empty.credentials, ())

check_raises("empty sync report rejected", lc.TuyaLockCredentialError, lc.decode_sync_report, b"")
check_raises(
    "unknown sync stage rejected", lc.TuyaLockCredentialError, lc.decode_sync_report, bytes([0x09, 0x00])
)
check_raises(
    "truncated record rejected",
    lc.TuyaLockCredentialError,
    lc.decode_sync_report,
    bytes([0x00, 0x00, 0x01, 0x03, 0x00]),
)
check_raises(
    "record with an unknown credential type rejected",
    lc.TuyaLockCredentialError,
    lc.decode_sync_report,
    bytes([0x00, 0x00, 0x01, 0x42, 0x00, 0x01]),
)

print("round trip")
# The exact request that the lock accepted and enrolled, kept as a guard.
check(
    "reproduces the enrollment request the lock accepted",
    lc.encode_add(
        lc.CredentialType.FINGERPRINT, 1, member_id=2, hardware_id=lc.HARDWARE_ID_AUTO
    ),
    bytes.fromhex("0300000002ffff000000000000000000000000000000000000000001"),
)

# A payload that has to survive being split across GATT packets (MTU 20).
big = lc.encode_add(
    lc.CredentialType.PASSWORD, 0x00FF, member_id=1, secret=b"9" * 120
)
check("payload larger than one GATT packet", len(big) > 20, True)
check("long password length byte", big[25], 120)
check("long password uuid still last", big[-2:], b"\x00\xff")

print()
if FAILURES:
    print(f"FAILED {len(FAILURES)}")
    for failure in FAILURES:
        print(" -", failure)
    sys.exit(1)
print("all green")
