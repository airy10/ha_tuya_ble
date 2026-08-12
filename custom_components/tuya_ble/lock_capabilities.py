"""Which access control datapoints a Tuya lock exposes.

Tuya locks share a platform-wide datapoint schema: 0qxp5u7s, isk2p555 and
ludzroix carry the same codes on the same datapoint ids. The integration
already downloads the product specification and keeps it in `device.function`
and `device.status_range`, keyed by code and carrying the datapoint id, so the
ids are looked up there rather than tabulated per product - which also covers
locks nobody here can test.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging

from .tuya_ble import TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)

CODE_CREDENTIAL_ADD = "unlock_method_create"
CODE_CREDENTIAL_DELETE = "unlock_method_delete"
CODE_CREDENTIAL_SYNC = "synch_method"

# Every way a Tuya lock reports that it was opened, mapped to the name the
# event entity exposes. The lock only has the ones its hardware supports.
UNLOCK_RECORD_CODES: dict[str, str] = {
    "unlock_fingerprint": "fingerprint",
    "unlock_password": "password",
    "unlock_dynamic": "dynamic_password",
    "unlock_temporary": "temporary_password",
    "unlock_card": "card",
    "unlock_face": "face",
    "unlock_key": "key",
    "unlock_ble": "bluetooth",
    "unlock_phone_remote": "remote",
    "unlock_voice_remote": "voice",
    "unlock_offline_pd": "offline_password",
}


@dataclass
class TuyaBLELockCapabilities:
    """Datapoint ids this particular lock exposes, zero when it does not."""

    credential_add_dp_id: int = 0
    credential_delete_dp_id: int = 0
    credential_sync_dp_id: int = 0
    # Datapoint id -> unlock method name.
    unlock_records: dict[int, str] = field(default_factory=dict)

    @property
    def manages_credentials(self) -> bool:
        """Return true if credentials can be listed, which is the entry point."""
        return self.credential_sync_dp_id > 0

    @property
    def reports_unlocks(self) -> bool:
        """Return true if the lock says how it was opened."""
        return bool(self.unlock_records)


# Fallback for config entries whose cached specification predates the version
# that started storing it. A product that is listed neither here nor in a
# specification gets nothing.
FALLBACK_CAPABILITIES: dict[str, TuyaBLELockCapabilities] = {
    "0qxp5u7s": TuyaBLELockCapabilities(
        credential_add_dp_id=1,
        credential_delete_dp_id=2,
        credential_sync_dp_id=54,
        unlock_records={12: "fingerprint", 19: "bluetooth", 62: "remote", 63: "voice"},
    ),
}


def _find_dp_id(device: TuyaBLEDevice, code: str) -> int:
    """Return the datapoint id the device gives a code, or zero."""
    for source in (device.function, device.status_range):
        entry = source.get(code)
        if entry is not None and entry.dp_id:
            return int(entry.dp_id)
    return 0


def discover(device: TuyaBLEDevice) -> TuyaBLELockCapabilities:
    """Read a lock's access control datapoints off its own specification."""
    fallback = FALLBACK_CAPABILITIES.get(
        device.product_id, TuyaBLELockCapabilities()
    )
    capabilities = TuyaBLELockCapabilities(
        credential_add_dp_id=(
            _find_dp_id(device, CODE_CREDENTIAL_ADD) or fallback.credential_add_dp_id
        ),
        credential_delete_dp_id=(
            _find_dp_id(device, CODE_CREDENTIAL_DELETE)
            or fallback.credential_delete_dp_id
        ),
        credential_sync_dp_id=(
            _find_dp_id(device, CODE_CREDENTIAL_SYNC) or fallback.credential_sync_dp_id
        ),
        # All or nothing rather than per datapoint: a specification that names
        # any unlock record describes the whole lock, so mixing the two sources
        # could only add records the lock does not have.
        unlock_records={
            dp_id: method
            for code, method in UNLOCK_RECORD_CODES.items()
            if (dp_id := _find_dp_id(device, code))
        }
        or dict(fallback.unlock_records),
    )

    _LOGGER.debug(
        "%s: lock capabilities add=%s delete=%s sync=%s unlock records=%s",
        device.address,
        capabilities.credential_add_dp_id,
        capabilities.credential_delete_dp_id,
        capabilities.credential_sync_dp_id,
        capabilities.unlock_records,
    )
    return capabilities
