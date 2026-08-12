"""Unlock events for Tuya BLE locks.

The `unlock_*` sensors carry the same datapoints, but a sensor only notifies on
a change, so repeated unlocks with the same credential are indistinguishable
from no unlock at all. An event entity carries a timestamp per trigger, so
opening the door twice with the same finger is two events.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.event import EventEntity, EventEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDevice

from .const import CONF_PERSON, CONF_USER_ID, DOMAIN
from . import lock_credential_store as credential_store
from .devices import TuyaBLECoordinator, TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .lock_capabilities import TuyaBLELockCapabilities

_LOGGER = logging.getLogger(__name__)

ATTR_CREDENTIAL_ID = "credential_id"
ATTR_CREDENTIAL_NAME = "credential_name"


class TuyaBLELockUnlockEvent(TuyaBLEEntity, EventEntity):
    """Fires whenever the lock reports how it was opened."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        entry: ConfigEntry,
        capabilities: TuyaBLELockCapabilities,
    ) -> None:
        """Initialize the event entity."""
        self._entry = entry
        self._dp_events = dict(capabilities.unlock_records)
        super().__init__(
            hass,
            coordinator,
            device,
            product,
            EventEntityDescription(key="unlocked"),
        )
        self._attr_event_types = sorted(set(self._dp_events.values()))
        # Datapoints whose first report on the current connection has already
        # been seen and discarded.
        self._seen: set[int] = set()

    async def async_added_to_hass(self) -> None:
        """Start listening for unlock reports."""
        await super().async_added_to_hass()
        self.async_on_remove(self._device.register_callback(self._handle_report))
        self.async_on_remove(
            self._device.register_disconnected_callback(self._handle_disconnect)
        )

    @callback
    def _handle_disconnect(self) -> None:
        """Expect a replayed status again once the lock comes back.

        Every connection begins with a status query, so the replay described in
        _handle_report happens on each reconnection and not only at startup.
        """
        self._seen.clear()

    @callback
    def _handle_report(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        """Turn an unlock report into an event."""
        for datapoint in datapoints:
            event_type = self._dp_events.get(datapoint.id)
            if event_type is None:
                continue

            # Connecting asks the lock for its whole status, and the lock
            # answers with the last value of every datapoint, including the
            # credential that opened the door last - possibly days ago. That is
            # history, not an event, and the receive timestamp cannot tell the
            # two apart, because datapoints are stamped when they arrive rather
            # than when the lock recorded them. So the first report of each
            # datapoint on a connection is dropped, at the cost of missing an
            # unlock in the first seconds of a connection.
            if datapoint.id not in self._seen:
                self._seen.add(datapoint.id)
                continue

            # Fired on every report, not only when the value changes: the same
            # finger opening the door twice has to be two events.
            self._trigger_event(event_type, self._describe(datapoint.value))
            self.async_write_ha_state()

    def _describe(self, credential_id: int) -> dict[str, Any]:
        """Attach whatever Home Assistant knows about this credential."""
        known = credential_store.describe(self._entry, credential_id)
        return {
            ATTR_CREDENTIAL_ID: credential_id,
            ATTR_CREDENTIAL_NAME: known[CONF_NAME],
            CONF_PERSON: known[CONF_PERSON],
            CONF_USER_ID: known[CONF_USER_ID],
        }


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tuya BLE lock events."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    capabilities = data.lock_capabilities

    # Not tied to the lock platform's mapping: several products in this schema
    # report how they were opened but expose nothing to control.
    if capabilities is None or not capabilities.reports_unlocks:
        return

    async_add_entities(
        [
            TuyaBLELockUnlockEvent(
                hass,
                data.coordinator,
                data.device,
                data.product,
                entry,
                capabilities,
            )
        ]
    )
