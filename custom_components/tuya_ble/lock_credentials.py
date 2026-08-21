"""Codec for the Tuya access control credential datapoints.

Locks in the Tuya access control schema manage their unlocking methods through
three raw datapoints: one to add a credential, one to delete it and one to have
the lock report which slots are occupied. This module only translates between
those raw payloads and Python objects - it does not talk to the device, so it
can be exercised without a lock in reach.

Layouts follow the Tuya "Access Control DP Reference".
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from struct import pack, unpack_from
from typing import Iterable

# Ask the lock to pick the next free slot itself.
HARDWARE_ID_AUTO = 0xFFFF

# One credential per record in a sync answer: hardware id, type, admin, valid.
SYNC_RECORD_LENGTH = 4

# Both reports are seven bytes on the wire.
ADD_REPORT_LENGTH = 7
DELETE_REPORT_LENGTH = 7


class CredentialType(IntEnum):
    """Kind of unlocking method, the leading byte of every payload."""

    PASSWORD = 0x01
    CARD = 0x02
    FINGERPRINT = 0x03
    FACE = 0x04
    REMOTE = 0x07
    TEMPORARY_PASSWORD = 0xF0


class AddStage(IntEnum):
    """Stage byte of the add datapoint."""

    START = 0x00
    CANCEL = 0xFE


class AddResult(IntEnum):
    """Result byte the lock reports while adding a credential.

    ACCEPTED is the first report of an enrollment, not the last: it carries the
    hardware id the lock picked and how many touches it wants. Only FINISHED
    means the credential exists. The reference calls 0x00 "success".
    """

    ACCEPTED = 0x00
    IN_PROGRESS = 0xFC
    FAILED = 0xFD
    FINISHED = 0xFF


class DeleteMode(IntEnum):
    """What the delete datapoint should remove."""

    MEMBER = 0x00  # every credential of the member - never sent by this code
    CREDENTIAL = 0x01


class DeleteResult(IntEnum):
    """Result byte the lock reports after a delete."""

    FAILED = 0x00
    UNKNOWN_ID = 0x01
    NOT_DELETABLE = 0x02
    SUCCESS = 0xFF


class TuyaLockCredentialError(Exception):
    """Raised when a payload from the lock cannot be read."""


@dataclass(frozen=True)
class AddReport:
    """Progress report of an ongoing enrollment.

    Captured layout, seven bytes:

        type | result | ?? (2 bytes) | hardware id | step | quality

    The lock does not echo the message uuid the request carried, so requests
    cannot be correlated by uuid.
    """

    type: CredentialType
    result: AddResult
    hardware_id: int
    step: int

    @property
    def in_progress(self) -> bool:
        """Return true while the lock still expects the user to act."""
        return self.result is AddResult.IN_PROGRESS

    @property
    def succeeded(self) -> bool:
        """Return true once the credential exists on the lock."""
        return self.result is AddResult.FINISHED

    @property
    def is_terminal(self) -> bool:
        """Return true if this report ends the enrollment, either way.

        ACCEPTED opens an enrollment rather than ending it, so it is not
        terminal despite being the reference's "success".
        """
        return self.result in (AddResult.FINISHED, AddResult.FAILED)


@dataclass(frozen=True)
class DeleteReport:
    """Outcome of a delete request, echoing the credential it acted on."""

    type: CredentialType
    credential_id: int
    result: DeleteResult

    @property
    def succeeded(self) -> bool:
        """Return true if the credential is gone."""
        return self.result is DeleteResult.SUCCESS


@dataclass(frozen=True)
class SyncCredential:
    """One credential the lock reports as occupying a slot."""

    hardware_id: int
    type: CredentialType
    admin_flag: int
    valid: bool

    @property
    def is_admin(self) -> bool:
        """Return true if the lock marks this credential as an administrator."""
        return self.admin_flag != 0


@dataclass(frozen=True)
class SyncReport:
    """One packet of the lock's answer to a sync request."""

    finished: bool
    sequence: int | None
    total_packets: int | None
    credentials: tuple[SyncCredential, ...]


def _check_word(name: str, value: int) -> None:
    """Reject a value that does not fit the two bytes reserved for it."""
    if not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} out of range: {value}")


def _check_byte(name: str, value: int) -> None:
    """Reject a value that does not fit the single byte reserved for it."""
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} out of range: {value}")


def encode_add(
    credential_type: CredentialType,
    message_uuid: int,
    *,
    member_id: int,
    hardware_id: int = HARDWARE_ID_AUTO,
    admin: bool = False,
    stage: AddStage = AddStage.START,
    times: int = 0,
    secret: bytes = b"",
) -> bytes:
    """Build the payload that starts (or cancels) an enrollment."""
    _check_word("member_id", member_id)
    _check_word("hardware_id", hardware_id)
    _check_word("message_uuid", message_uuid)
    _check_byte("times", times)
    if len(secret) > 0xFF:
        raise ValueError(f"secret too long: {len(secret)}")

    return b"".join(
        (
            pack(">BBB", credential_type, stage, 1 if admin else 0),
            pack(">HH", member_id, hardware_id),
            # Validity period. All zeroes means the credential never expires,
            # which is the only thing this integration offers today.
            bytes(17),
            pack(">BB", times, len(secret)),
            secret,
            pack(">H", message_uuid),
        )
    )


def decode_add_report(data: bytes) -> AddReport:
    """Read a progress report of an enrollment."""
    if len(data) < ADD_REPORT_LENGTH:
        raise TuyaLockCredentialError(
            f"add report too short: {len(data)} bytes ({data.hex()})"
        )

    credential_type, result = unpack_from(">BB", data, 0)
    hardware_id, step = unpack_from(">BB", data, 4)

    try:
        return AddReport(
            type=CredentialType(credential_type),
            result=AddResult(result),
            hardware_id=hardware_id,
            step=step,
        )
    except ValueError as err:
        raise TuyaLockCredentialError(f"unreadable add report: {data.hex()}") from err


def encode_delete(
    credential_type: CredentialType,
    *,
    credential_id: int,
    admin: bool = False,
) -> bytes:
    """Build the payload that removes a single credential.

    The reference calls the two id fields "member id" then "hardware id" and
    says the second selects the credential. On the 0qxp5u7s it is the first,
    confirmed by capture, so the credential id goes into BOTH fields: whichever
    one the firmware honours, it targets the credential that was asked for.

    The mode byte is fixed to DeleteMode.CREDENTIAL. The lock also accepts
    DeleteMode.MEMBER, which wipes every credential a member owns; it has no
    caller here and cannot be reached by accident.
    """
    _check_word("credential_id", credential_id)

    return b"".join(
        (
            pack(">BBB", credential_type, 0x00, 1 if admin else 0),
            pack(">HH", credential_id, credential_id),
            pack(">B", DeleteMode.CREDENTIAL),
        )
    )


def decode_delete_report(data: bytes) -> DeleteReport:
    """Read the outcome of a delete request."""
    if len(data) < DELETE_REPORT_LENGTH:
        raise TuyaLockCredentialError(
            f"delete report too short: {len(data)} bytes ({data.hex()})"
        )

    credential_type = data[0]
    (credential_id,) = unpack_from(">H", data, 3)
    result = data[6]

    try:
        return DeleteReport(
            type=CredentialType(credential_type),
            credential_id=credential_id,
            result=DeleteResult(result),
        )
    except ValueError as err:
        raise TuyaLockCredentialError(
            f"unreadable delete report: {data.hex()}"
        ) from err


def encode_sync_request(types: Iterable[CredentialType]) -> bytes:
    """Build the payload asking the lock which slots are occupied."""
    wanted = sorted({int(credential_type) for credential_type in types})
    if not wanted:
        raise ValueError("sync request needs at least one credential type")
    return bytes(wanted)


def decode_sync_report(data: bytes) -> SyncReport:
    """Read one packet of the lock's slot occupancy answer.

    The Tuya reference describes partitions carrying a bitmap of eight slots
    each. The 0qxp5u7s sends something else: a stage byte, a sequence byte and
    one four byte record per credential, as captured from a lock holding four
    fingerprints:

        00 00 | 00 03 ff 01 | 01 03 01 01 | 02 03 01 01 | 03 03 01 01

    Byte 0 is the hardware id that the unlock datapoint reports, byte 1 the
    credential type, byte 2 the admin flag and byte 3 the valid flag. No member
    id appears. Asking for a credential type the lock holds none of produces no
    answer at all rather than an empty one.
    """
    if not data:
        raise TuyaLockCredentialError("empty sync report")

    stage = data[0]

    if stage == 0x01:
        if len(data) < 2:
            raise TuyaLockCredentialError(f"truncated sync tail: {data.hex()}")
        return SyncReport(
            finished=True, sequence=None, total_packets=data[1], credentials=()
        )

    if stage != 0x00:
        raise TuyaLockCredentialError(f"unknown sync stage {stage:#04x}: {data.hex()}")

    if len(data) < 2:
        raise TuyaLockCredentialError(f"truncated sync packet: {data.hex()}")

    records = data[2:]
    if len(records) % SYNC_RECORD_LENGTH:
        raise TuyaLockCredentialError(
            f"sync packet has a partial record: {data.hex()}"
        )

    credentials: list[SyncCredential] = []
    for offset in range(0, len(records), SYNC_RECORD_LENGTH):
        hardware_id, credential_type, admin_flag, valid = unpack_from(
            ">BBBB", records, offset
        )
        try:
            credentials.append(
                SyncCredential(
                    hardware_id=hardware_id,
                    type=CredentialType(credential_type),
                    admin_flag=admin_flag,
                    valid=bool(valid),
                )
            )
        except ValueError as err:
            raise TuyaLockCredentialError(
                f"sync record has an unknown credential type: {data.hex()}"
            ) from err

    return SyncReport(
        finished=False,
        sequence=data[1],
        total_packets=None,
        credentials=tuple(credentials),
    )
