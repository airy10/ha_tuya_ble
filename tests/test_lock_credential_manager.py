"""Checks for the credential transaction layer, no lock and no Home Assistant.

The manager imports nothing from homeassistant, so a fake device with a
datapoint that either records or refuses the write is enough. Pinned here:

  * a report from one datapoint must not satisfy a caller waiting on another
  * a request that could not be sent is an error, not "the lock holds nothing"
  * a sync answer whose closing packet never arrives keeps what did arrive

    python3 tests/test_lock_credential_manager.py

Set TUYA_BLE_COMPONENT to point it at another copy of the component, which is
how these can be run against the behaviour before a change:

    git show <old-rev>:custom_components/tuya_ble/lock_credential_manager.py > /tmp/old/...
    TUYA_BLE_COMPONENT=/tmp/old python3 tests/test_lock_credential_manager.py
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import sys
import types
from pathlib import Path

COMPONENT = Path(
    os.environ.get(
        "TUYA_BLE_COMPONENT",
        Path(__file__).resolve().parents[1] / "custom_components" / "tuya_ble",
    )
)
PACKAGE = "tuya_ble_stub"


def _load(name: str):
    """Import one module of the component under a stub package."""
    if PACKAGE not in sys.modules:
        stub = types.ModuleType(PACKAGE)
        stub.__path__ = [str(COMPONENT)]
        sys.modules[PACKAGE] = stub
        ble = types.ModuleType(f"{PACKAGE}.tuya_ble")
        ble.TuyaBLEDevice = object
        ble.TuyaBLEDataPoint = object

        class TuyaBLEDataPointType:
            DT_RAW = 0

        ble.TuyaBLEDataPointType = TuyaBLEDataPointType
        sys.modules[f"{PACKAGE}.tuya_ble"] = ble
    spec = importlib.util.spec_from_file_location(
        f"{PACKAGE}.{name}", COMPONENT / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"{PACKAGE}.{name}"] = module
    spec.loader.exec_module(module)
    return module


codec = _load("lock_credentials")
manager_module = _load("lock_credential_manager")

ADD_DP, DELETE_DP, SYNC_DP = 1, 2, 54


class FakeDataPoint:
    """A datapoint that records what was written, or refuses to write."""

    def __init__(self, sink: list[tuple[int, bytes]], dp_id: int, fail) -> None:
        self._sink = sink
        self.id = dp_id
        self._fail = fail
        self.value: bytes | None = None

    async def set_value(self, payload: bytes) -> None:
        if self._fail:
            error = OSError if self._fail is True else self._fail
            raise error("the lock is not connected")
        self._sink.append((self.id, payload))


class FakeDataPoints:
    """Stands in for TuyaBLEDevice.datapoints."""

    def __init__(self, sink: list[tuple[int, bytes]], fail) -> None:
        self._sink = sink
        self._fail = fail

    def get_or_create(self, dp_id: int, _type, _value) -> FakeDataPoint:
        return FakeDataPoint(self._sink, dp_id, self._fail)


class FakeDevice:
    """Only the two attributes the manager touches."""

    def __init__(self, fail=False) -> None:
        self.address = "AA:BB:CC:DD:EE:FF"
        self.sent: list[tuple[int, bytes]] = []
        self.datapoints = FakeDataPoints(self.sent, fail)


class FakeReport:
    """A datapoint report as the device callback delivers it."""

    def __init__(self, dp_id: int, value: bytes) -> None:
        self.id = dp_id
        self.value = value


def build(fail=False):
    """Return a manager wired to a fake device."""
    device = FakeDevice(fail)
    return device, manager_module.TuyaBLELockCredentials(
        device, add_dp_id=ADD_DP, delete_dp_id=DELETE_DP, sync_dp_id=SYNC_DP
    )


FAILURES = 0


def check(label: str, actual, expected) -> None:
    global FAILURES
    if actual == expected:
        print(f"  ok  {label}")
        return
    FAILURES += 1
    print(f"  FAIL {label}\n       expected {expected!r}\n       got      {actual!r}")


def check_raises(label: str, exc_type, coro_factory) -> None:
    global FAILURES
    try:
        asyncio.run(coro_factory())
    except exc_type as err:
        print(f"  ok  {label} ({err})")
        return
    except Exception as err:  # noqa: BLE001 - the point is that it was wrong
        FAILURES += 1
        print(f"  FAIL {label}\n       raised {type(err).__name__}: {err}")
        return
    FAILURES += 1
    print(f"  FAIL {label}\n       nothing was raised")


# Captured from the lock: an acceptance ack, a touch, the finished report, and
# one packet of a four-fingerprint sync answer.
ADD_ACCEPTED = bytes.fromhex("03000000040001")
ADD_TOUCH = bytes.fromhex("03fc000004020a")
ADD_FINISHED = bytes.fromhex("03ff000004050a")
SYNC_PACKET = bytes.fromhex("00000003ff0101030101")
SYNC_TAIL = bytes.fromhex("0101")


print("a report from the wrong datapoint does not answer the request")


async def stray_add_during_list() -> list:
    device, manager = build()
    task = asyncio.ensure_future(manager.async_list())
    await asyncio.sleep(0)  # let the request go out and the future be claimed

    # The lock acknowledges an enrollment nobody here asked for - a cancelled
    # one finishing late, or the status query replaying the datapoint.
    manager._handle_report([FakeReport(ADD_DP, ADD_FINISHED)])
    check("the sync request is still waiting", task.done(), False)

    # The real answer arrives afterwards and is the one that counts.
    manager._handle_report([FakeReport(SYNC_DP, SYNC_PACKET)])
    manager._handle_report([FakeReport(SYNC_DP, SYNC_TAIL)])
    return await task


held = asyncio.run(stray_add_during_list())
# Guarded: an AddReport here would end the run in a traceback rather than a
# readable failure.
check("the answer is a list, not the stray report", type(held).__name__, "list")
if isinstance(held, list):
    check("two credentials came back", [c.hardware_id for c in held], [0, 1])
    check(
        "and they are credentials",
        type(held[0]).__name__ if held else None,
        "SyncCredential",
    )


print("an enrollment is not ended by the reports that precede it")


async def enrollment_runs_to_the_end() -> int:
    device, manager = build()
    task = asyncio.ensure_future(manager.async_add_fingerprint())
    await asyncio.sleep(0)
    manager._handle_report([FakeReport(ADD_DP, ADD_ACCEPTED)])
    check("acceptance does not finish it", task.done(), False)
    manager._handle_report([FakeReport(ADD_DP, ADD_TOUCH)])
    check("a touch does not finish it", task.done(), False)
    manager._handle_report([FakeReport(ADD_DP, ADD_FINISHED)])
    return await task


check("the lock's own id comes back", asyncio.run(enrollment_runs_to_the_end()), 4)


print("a request that could not be sent is an error")
check_raises(
    "listing does not report an unreachable lock as empty",
    manager_module.TuyaBLELockCredentialsError,
    lambda: build(fail=True)[1].async_list(),
)
check_raises(
    "nor does enrolling swallow it",
    manager_module.TuyaBLELockCredentialsError,
    lambda: build(fail=True)[1].async_add_fingerprint(),
)
check_raises(
    "nor does removing",
    manager_module.TuyaBLELockCredentialsError,
    lambda: build(fail=True)[1].async_remove(3),
)
# The transport gives up on an unacknowledged packet with a TimeoutError, the
# same exception the wait for an answer produces. The two must not be caught
# together, or an unreachable lock reads as "holds no fingerprints".
check_raises(
    "a send that timed out is not an empty list either",
    manager_module.TuyaBLELockCredentialsError,
    lambda: build(fail=TimeoutError)[1].async_list(),
)


print("a truncated sync answer keeps what did arrive")


async def sync_without_its_closing_packet() -> list:
    device, manager = build()
    manager_module.SYNC_TIMEOUT = 0.05  # the wait is the point, not its length
    task = asyncio.ensure_future(manager.async_list())
    await asyncio.sleep(0)
    manager._handle_report([FakeReport(SYNC_DP, SYNC_PACKET)])
    return await task  # the closing packet never comes


check(
    "the reported records survive the timeout",
    [c.hardware_id for c in asyncio.run(sync_without_its_closing_packet())],
    [0, 1],
)


print("silence really does mean none of that type")


async def sync_with_nothing_at_all() -> list:
    device, manager = build()
    manager_module.SYNC_TIMEOUT = 0.05
    return await manager.async_list()


check("an empty list, not an error", asyncio.run(sync_with_nothing_at_all()), [])


print("the slot is free again afterwards")


async def slot_released_after_failure() -> bool:
    device, manager = build()
    manager_module.SYNC_TIMEOUT = 0.05
    await manager.async_list()
    await manager.async_list()  # would raise "already busy" if the slot leaked
    return True


check("a second request is accepted", asyncio.run(slot_released_after_failure()), True)

print()
print("all green" if FAILURES == 0 else f"{FAILURES} FAILED")
sys.exit(1 if FAILURES else 0)
