"""Checks for lock_capabilities.discover.

Pins three product specifications captured from real devices, plus the two ways
a lock can end up with no specification at all.

    python3 tests/test_lock_capabilities.py

Set TUYA_BLE_COMPONENT to point it at another copy of the component.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types
from dataclasses import dataclass
from pathlib import Path

COMPONENT = Path(
    os.environ.get(
        "TUYA_BLE_COMPONENT",
        Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble",
    )
)


def _load(name: str, path: Path):
    """Import a module by path, with a stub package so relative imports work."""
    package = "tuya_ble_stub"
    if package not in sys.modules:
        stub = types.ModuleType(package)
        stub.__path__ = [str(COMPONENT)]
        sys.modules[package] = stub
        # lock_capabilities only needs the TuyaBLEDevice name for annotations.
        ble = types.ModuleType(f"{package}.tuya_ble")
        ble.TuyaBLEDevice = object
        sys.modules[f"{package}.tuya_ble"] = ble
    spec = importlib.util.spec_from_file_location(f"{package}.{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"{package}.{name}"] = module
    spec.loader.exec_module(module)
    return module


capabilities = _load("lock_capabilities", COMPONENT / "lock_capabilities.py")


@dataclass
class FakeSpec:
    """Stands in for the cloud specification entry of one datapoint."""

    dp_id: int


class FakeDevice:
    """Only the three attributes discovery reads."""

    def __init__(self, product_id: str, function: dict, status_range: dict) -> None:
        self.address = "AA:BB:CC:DD:EE:FF"
        self.product_id = product_id
        self.function = {code: FakeSpec(dp) for code, dp in function.items()}
        self.status_range = {code: FakeSpec(dp) for code, dp in status_range.items()}


FAILURES = 0


def check(label: str, actual, expected) -> None:
    global FAILURES
    if actual == expected:
        print(f"  ok  {label}")
        return
    FAILURES += 1
    print(f"  FAIL {label}\n       expected {expected!r}\n       got      {actual!r}")


# The write side lives in function and the reporting side in status_range,
# exactly as the cloud returns it.
SPEC_0QXP5U7S_FUNCTION = {
    "unlock_method_create": 1,
    "unlock_method_delete": 2,
    "synch_method": 54,
    "automatic_lock": 33,
}
SPEC_0QXP5U7S_STATUS = {
    "unlock_fingerprint": 12,
    "unlock_ble": 19,
    "unlock_phone_remote": 62,
    "unlock_voice_remote": 63,
    "lock_motor_state": 47,
    "synch_method": 54,
}

# From the specification quoted in issue #1713, for a lock with no entry in
# FALLBACK_CAPABILITIES.
SPEC_ISK2P555_FUNCTION = {
    "unlock_method_create": 1,
    "unlock_method_delete": 2,
    "synch_method": 54,
}
SPEC_ISK2P555_STATUS = {
    "unlock_fingerprint": 12,
    "unlock_password": 13,
    "unlock_dynamic": 14,
    "unlock_temporary": 55,
    "unlock_ble": 19,
    "unlock_phone_remote": 62,
    "unlock_voice_remote": 63,
    "unlock_offline_pd": 67,
}

print("a lock with a hand-written fallback")
found = capabilities.discover(
    FakeDevice("0qxp5u7s", SPEC_0QXP5U7S_FUNCTION, SPEC_0QXP5U7S_STATUS)
)
check("add datapoint", found.credential_add_dp_id, 1)
check("delete datapoint", found.credential_delete_dp_id, 2)
check("sync datapoint", found.credential_sync_dp_id, 54)
check(
    "unlock records",
    found.unlock_records,
    {12: "fingerprint", 19: "bluetooth", 62: "remote", 63: "voice"},
)
check("manages credentials", found.manages_credentials, True)
check("reports unlocks", found.reports_unlocks, True)
check(
    "matches the hand-written fallback exactly",
    found,
    capabilities.FALLBACK_CAPABILITIES["0qxp5u7s"],
)

print("a lock discovered from its specification alone")
found = capabilities.discover(
    FakeDevice("isk2p555", SPEC_ISK2P555_FUNCTION, SPEC_ISK2P555_STATUS)
)
check("add datapoint", found.credential_add_dp_id, 1)
check("delete datapoint", found.credential_delete_dp_id, 2)
check("sync datapoint", found.credential_sync_dp_id, 54)
check(
    "eight unlock methods",
    found.unlock_records,
    {
        12: "fingerprint",
        13: "password",
        14: "dynamic_password",
        55: "temporary_password",
        19: "bluetooth",
        62: "remote",
        63: "voice",
        67: "offline_password",
    },
)

print("no specification at all")
check(
    "a known product still falls back to the measured datapoints",
    capabilities.discover(FakeDevice("0qxp5u7s", {}, {})),
    capabilities.FALLBACK_CAPABILITIES["0qxp5u7s"],
)
bare = capabilities.discover(FakeDevice("unknown_lock", {}, {}))
check("an unknown product gets nothing", bare, capabilities.TuyaBLELockCapabilities())
check("and does not claim to manage credentials", bare.manages_credentials, False)

print("a device that is not a lock")
fingerbot = capabilities.discover(
    FakeDevice("blliqpsj", {"mode": 8, "click_sustain_time": 10}, {"battery_percentage": 12})
)
check("no credential datapoints", fingerbot.manages_credentials, False)
check("no unlock records", fingerbot.unlock_records, {})

print("the fallback table is not handed out to be mutated")
first = capabilities.discover(FakeDevice("0qxp5u7s", {}, {}))
first.unlock_records[99] = "nonsense"
check(
    "a second lookup is unaffected",
    capabilities.discover(FakeDevice("0qxp5u7s", {}, {})).unlock_records,
    {12: "fingerprint", 19: "bluetooth", 62: "remote", 63: "voice"},
)

print()
print("all green" if FAILURES == 0 else f"{FAILURES} FAILED")
sys.exit(1 if FAILURES else 0)
