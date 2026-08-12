"""The Tuya BLE lock integration."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.lock import (
    LockEntity,
    LockEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDataPointType, TuyaBLEDevice

from .const import DOMAIN
from .devices import TuyaBLECoordinator, TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo
from .lock_capabilities import TuyaBLELockCapabilities

import logging

_LOGGER = logging.getLogger(__name__)


@dataclass
class TuyaBLELockMapping:
    """Mapping for Tuya BLE Lock."""

    lock_dp_id: int  # DP for controlling lock (automatic_lock)
    state_dp_id: int  # DP for reading lock state (lock_motor_state)
    reverse: bool
    description: LockEntityDescription | None = None


@dataclass
class TuyaBLECategoryLockMapping:
    """Mapping for Tuya BLE Lock by category."""

    products: dict[str, list[TuyaBLELockMapping]] | None = None


category_mapping: dict[str, TuyaBLECategoryLockMapping] = {
    "ms": TuyaBLECategoryLockMapping(
        products={
            "0qxp5u7s": [  # Smart Lock
                TuyaBLELockMapping(
                    lock_dp_id=33,  # automatic_lock
                    state_dp_id=47,  # lock_motor_state (read-only)
                    reverse=True,
                    description=LockEntityDescription(
                        key="lock",
                        name="Lock",
                    ),
                ),
            ],
        },
    ),
}


def get_mapping_by_device(
    device: TuyaBLEDevice,
) -> list[TuyaBLELockMapping]:
    """Get lock mappings for device."""
    category = device.category
    product_id = device.product_id
    mappings: list[TuyaBLELockMapping] = []

    if category in category_mapping:
        category_map = category_mapping[category]
        if category_map.products and product_id in category_map.products:
            mappings.extend(category_map.products[product_id])

    return mappings


class TuyaBLELock(TuyaBLEEntity, LockEntity):
    """Representation of a Tuya BLE Lock."""

    def __init__(
        self,
        hass: HomeAssistant,
        coordinator: TuyaBLECoordinator,
        device: TuyaBLEDevice,
        product: TuyaBLEProductInfo,
        mapping: TuyaBLELockMapping,
        capabilities: TuyaBLELockCapabilities | None = None,
    ) -> None:
        """Initialize the lock."""
        description = mapping.description or LockEntityDescription(
            key="lock",
            name="Lock",
        )
        super().__init__(hass, coordinator, device, product, description)
        self._mapping = mapping
        # Locked state requested by the user, cleared once the device confirms it.
        self._requested_locked: bool | None = None
        self._unlock_dps = dict(capabilities.unlock_records) if capabilities else {}
        # Datapoints whose replayed value has been discarded on this connection.
        self._seen_unlock_dps: set[int] = set()

    def _logical_value(self, dp_id: int) -> bool | None:
        """Return a datapoint as a locked state, None if never reported."""
        datapoint = self._device.datapoints[dp_id]
        if datapoint is None:
            return None
        return self._mapping.reverse ^ bool(datapoint.value)

    @property
    def _reported_locked(self) -> bool | None:
        """Return the locked state as last reported by the device."""
        if self._mapping.state_dp_id > 0:
            return self._logical_value(self._mapping.state_dp_id)
        # Without a state datapoint the control datapoint is all there is, and
        # it already holds the requested value, so a mapping configured this way
        # reports the new state immediately instead of a transitional one.
        return self._logical_value(self._mapping.lock_dp_id)

    async def async_added_to_hass(self) -> None:
        """Start tracking who last operated the lock."""
        await super().async_added_to_hass()
        if self._unlock_dps:
            self.async_on_remove(
                self._device.register_callback(self._handle_unlock_record)
            )
            self.async_on_remove(
                self._device.register_disconnected_callback(self._handle_disconnect)
            )

    @callback
    def _handle_disconnect(self) -> None:
        """Expect the replayed status again once the lock comes back."""
        self._seen_unlock_dps.clear()

    @callback
    def _handle_unlock_record(self, datapoints: list[TuyaBLEDataPoint]) -> None:
        """Record who opened the lock, for LockEntity.changed_by.

        The first report of each datapoint on a connection is dropped, exactly
        as the event entity drops it: the lock answers a status query with the
        last value of every datapoint, and that value is not merely stale. It
        can name a credential that no longer exists on the lock, which is worse
        than reporting nothing until someone actually opens the door.
        """
        for datapoint in datapoints:
            method = self._unlock_dps.get(datapoint.id)
            if method is None:
                continue
            if datapoint.id not in self._seen_unlock_dps:
                self._seen_unlock_dps.add(datapoint.id)
                continue
            self._attr_changed_by = f"{method} #{datapoint.value}"
            self.async_write_ha_state()

    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked, None while it is unknown."""
        return self._reported_locked

    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return self._requested_locked is True and self._reported_locked is not True

    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return self._requested_locked is False and self._reported_locked is not False

    async def async_lock(self, **kwargs) -> None:
        """Lock the lock."""
        await self._async_request_locked(True)

    async def async_unlock(self, **kwargs) -> None:
        """Unlock the lock."""
        await self._async_request_locked(False)

    async def _async_request_locked(self, locked: bool) -> None:
        """Ask the device to lock or unlock and wait for it to confirm."""
        _LOGGER.debug(
            "%s: Requesting lock state %s",
            self._device.address,
            "locked" if locked else "unlocked",
        )

        # Reported immediately as is_locking/is_unlocking, until the device
        # reports the new state through its own datapoint.
        self._requested_locked = locked
        self.async_write_ha_state()

        value = self._mapping.reverse ^ locked
        datapoint = self._device.datapoints.get_or_create(
            self._mapping.lock_dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            value,
        )
        try:
            await datapoint.set_value(value)
        except Exception:
            self._requested_locked = None
            self.async_write_ha_state()
            raise

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # The transition ends only once the device reports the requested state;
        # any other report means the motor has not finished moving yet.
        if (
            self._requested_locked is not None
            and self._reported_locked == self._requested_locked
        ):
            self._requested_locked = None

        self.async_write_ha_state()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tuya BLE lock platform."""
    data: TuyaBLEData = hass.data[DOMAIN][entry.entry_id]
    mappings = get_mapping_by_device(data.device)

    entities: list[TuyaBLELock] = []
    for mapping in mappings:
        entities.append(
            TuyaBLELock(
                hass,
                data.coordinator,
                data.device,
                data.product,
                mapping,
                data.lock_capabilities,
            )
        )

    async_add_entities(entities)
