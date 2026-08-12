"""Credential transactions with a Tuya access control lock.

Free of any entity, because the options flow enrolls fingerprints before and
independently of the lock entity, and some locks in this schema get no lock
entity at all.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDataPointType, TuyaBLEDevice

from .lock_credentials import (
    HARDWARE_ID_AUTO,
    AddReport,
    AddStage,
    CredentialType,
    DeleteReport,
    SyncCredential,
    TuyaLockCredentialError,
    decode_add_report,
    decode_delete_report,
    decode_sync_report,
    encode_add,
    encode_delete,
    encode_sync_request,
)

_LOGGER = logging.getLogger(__name__)

# The lock answers a sync request in well under a second when it has anything
# to say, and says nothing at all when it holds no credential of that type.
SYNC_TIMEOUT = 10
DELETE_TIMEOUT = 15
# Long enough for someone to present a finger five times without hurrying.
ENROLL_TIMEOUT = 120

# The lock does not report member ids, so this integration does not track them.
# Everything it creates belongs to the same nominal member.
DEFAULT_MEMBER_ID = 1


class TuyaBLELockCredentialsError(Exception):
    """Raised when the lock refuses or ignores a credential request."""


class TuyaBLELockCredentials:
    """Adds, removes and lists the credentials a lock holds."""

    def __init__(
        self,
        device: TuyaBLEDevice,
        *,
        add_dp_id: int,
        delete_dp_id: int,
        sync_dp_id: int,
    ) -> None:
        """Remember which datapoints this product uses."""
        self._device = device
        self._add_dp_id = add_dp_id
        self._delete_dp_id = delete_dp_id
        self._sync_dp_id = sync_dp_id

        # The lock does not echo the message uuid a request carried and does
        # one operation at a time, so a single slot is enough - tagged with the
        # datapoint it waits for, because reports also arrive unsolicited: the
        # lock replays every datapoint when asked for its status, and a
        # cancelled enrollment acknowledges itself late. Untagged, a stray add
        # report would satisfy a caller waiting for a credential list.
        self._pending: asyncio.Future | None = None
        self._pending_dp_id = 0
        self._sync_buffer: list[SyncCredential] = []
        self._message_uuid = 0

    @property
    def supported(self) -> bool:
        """Return true if this product exposes the access control datapoints."""
        return self._sync_dp_id > 0

    def start(self) -> Callable[[], None]:
        """Begin watching credential reports, returning an unsubscribe."""
        return self._device.register_callback(self._handle_report)

    def _claim(self, dp_id: int) -> asyncio.Future:
        """Take the single in-flight slot for one datapoint, or refuse."""
        if self._pending is not None and not self._pending.done():
            raise TuyaBLELockCredentialsError(
                "the lock is already busy with a credential operation"
            )
        self._pending = asyncio.get_running_loop().create_future()
        self._pending_dp_id = dp_id
        return self._pending

    def _release(self) -> None:
        """Give up the in-flight slot."""
        self._pending = None
        self._pending_dp_id = 0

    async def _send(self, dp_id: int, payload: bytes) -> None:
        """Write a raw credential payload to the lock.

        Every way the write can fail is reported as one exception type, so
        callers have a single thing to catch.
        """
        _LOGGER.debug(
            "%s: sending dp %s: %s", self._device.address, dp_id, payload.hex()
        )
        datapoint = self._device.datapoints.get_or_create(
            dp_id, TuyaBLEDataPointType.DT_RAW, payload
        )
        try:
            await datapoint.set_value(payload)
        except Exception as err:  # noqa: BLE001 - bleak raises a wide variety
            raise TuyaBLELockCredentialsError(
                f"could not reach the lock to send datapoint {dp_id}: {err}"
            ) from err

    def _handle_report(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        """Route a credential datapoint report to whoever is waiting for it."""
        for datapoint in datapoints:
            value = datapoint.value
            if not isinstance(value, (bytes, bytearray)):
                continue
            try:
                if datapoint.id == self._sync_dp_id:
                    self._handle_sync_report(bytes(value))
                elif datapoint.id == self._add_dp_id:
                    self._handle_add_report(decode_add_report(bytes(value)))
                elif datapoint.id == self._delete_dp_id:
                    self._resolve(
                        self._delete_dp_id, decode_delete_report(bytes(value))
                    )
            except TuyaLockCredentialError as err:
                _LOGGER.warning("%s: %s", self._device.address, err)

    def _handle_sync_report(self, raw: bytes) -> None:
        """Collect one packet of a sync answer, resolving on the last one."""
        report = decode_sync_report(raw)
        if not report.finished:
            self._sync_buffer.extend(report.credentials)
            return
        collected = list(self._sync_buffer)
        self._sync_buffer.clear()
        self._resolve(self._sync_dp_id, collected)

    def _handle_add_report(self, report: AddReport) -> None:
        """Note an enrollment's progress, resolving only on a terminal report.

        An acceptance ack, then one report per touch; resolving on either would
        end the enrollment before the finger is enrolled. Logged rather than
        surfaced, because a progress dialog renders its text once.
        """
        if not report.is_terminal:
            _LOGGER.debug(
                "%s: enrollment at touch %s (%s)",
                self._device.address,
                report.step,
                report.result.name.lower(),
            )
            return
        self._resolve(self._add_dp_id, report)

    def _resolve(self, dp_id: int, result: Any) -> None:
        """Hand a decoded report to the caller waiting for that datapoint."""
        if (
            self._pending is not None
            and not self._pending.done()
            and self._pending_dp_id == dp_id
        ):
            self._pending.set_result(result)

    async def async_list(
        self, credential_type: CredentialType = CredentialType.FINGERPRINT
    ) -> list[SyncCredential]:
        """Return the credentials of one type that the lock holds.

        The lock answers one type per request; asking for several at once gets
        no answer at all. Silence also means "none of that type", so a timeout
        waiting for the answer is an empty result rather than a failure.

        Only the wait is forgiven. A request that could not be sent is raised,
        because reporting "no fingerprints" for a lock that was never reached
        is the one wrong answer this must not give.
        """
        future = self._claim(self._sync_dp_id)
        self._sync_buffer.clear()
        try:
            await self._send(self._sync_dp_id, encode_sync_request([credential_type]))
            try:
                async with asyncio.timeout(SYNC_TIMEOUT):
                    return await future
            except TimeoutError:
                # The answer arrives in packets and only the last one says so,
                # so a dropped closing packet must not discard the records that
                # did arrive.
                collected = list(self._sync_buffer)
                _LOGGER.debug(
                    "%s: no closing sync packet for %s, keeping the %s record(s) "
                    "already reported",
                    self._device.address,
                    credential_type.name.lower(),
                    len(collected),
                )
                return collected
        finally:
            self._release()

    async def async_add_fingerprint(self) -> int:
        """Enroll a fingerprint and return the id the lock assigned it.

        Blocks for as long as the lock keeps asking for touches.
        """
        if not self._add_dp_id:
            raise TuyaBLELockCredentialsError("this lock cannot add credentials")

        future = self._claim(self._add_dp_id)
        self._message_uuid = (self._message_uuid + 1) & 0xFFFF
        try:
            await self._send(
                self._add_dp_id,
                encode_add(
                    CredentialType.FINGERPRINT,
                    self._message_uuid,
                    member_id=DEFAULT_MEMBER_ID,
                    hardware_id=HARDWARE_ID_AUTO,
                ),
            )
            async with asyncio.timeout(ENROLL_TIMEOUT):
                report: AddReport = await future
        except TimeoutError as err:
            # Release the slot first: cancelling talks to the lock, and a late
            # report arriving mid-cancel would go to a future already done.
            self._release()
            await self.async_cancel_enrollment()
            raise TuyaBLELockCredentialsError(
                "the lock stopped reporting before the fingerprint was enrolled"
            ) from err
        finally:
            self._release()

        if not report.succeeded:
            raise TuyaBLELockCredentialsError(
                f"the lock refused the fingerprint ({report.result.name.lower()})"
            )
        return report.hardware_id

    async def async_cancel_enrollment(self) -> None:
        """Tell the lock to stop waiting for a finger.

        Known gap: this does not claim the slot, and the reply arrives on the
        datapoint an enrollment uses. Abandoning the wizard and immediately
        starting another can therefore land the first acknowledgement on the
        second request; the datapoint tag cannot separate them and the lock
        echoes no message uuid.
        """
        self._message_uuid = (self._message_uuid + 1) & 0xFFFF
        try:
            await self._send(
                self._add_dp_id,
                encode_add(
                    CredentialType.FINGERPRINT,
                    self._message_uuid,
                    member_id=DEFAULT_MEMBER_ID,
                    stage=AddStage.CANCEL,
                ),
            )
        except TuyaBLELockCredentialsError as err:
            # Best effort: a lock that cannot be told to stop times out itself.
            _LOGGER.warning(
                "%s: could not cancel the enrollment: %s", self._device.address, err
            )

    async def async_remove(self, credential_id: int) -> None:
        """Remove a single credential from the lock."""
        if not self._delete_dp_id:
            raise TuyaBLELockCredentialsError("this lock cannot delete credentials")

        future = self._claim(self._delete_dp_id)
        try:
            await self._send(
                self._delete_dp_id,
                encode_delete(CredentialType.FINGERPRINT, credential_id=credential_id),
            )
            async with asyncio.timeout(DELETE_TIMEOUT):
                report: DeleteReport = await future
        except TimeoutError as err:
            raise TuyaBLELockCredentialsError(
                f"the lock did not answer the request to remove credential "
                f"{credential_id}"
            ) from err
        finally:
            self._release()

        if not report.succeeded:
            raise TuyaBLELockCredentialsError(
                f"the lock refused to remove credential {credential_id} "
                f"({report.result.name.lower()})"
            )
