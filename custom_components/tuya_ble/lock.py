"""The Tuya BLE lock integration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
import asyncio

from homeassistant.components.lock import (
    LockEntity,
    LockEntityDescription,
    LockEntityFeature,
    LockState,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .tuya_ble import TuyaBLEDataPointType, TuyaBLEDevice

from .const import DOMAIN
from .devices import TuyaBLECoordinator, TuyaBLEData, TuyaBLEEntity, TuyaBLEProductInfo

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
    ) -> None:
        """Initialize the lock."""
        description = mapping.description or LockEntityDescription(
            key="lock",
            name="Lock",
        )
        super().__init__(hass, coordinator, device, product, description)
        self._mapping = mapping
        self._target_state: bool | None = None
        self._current_state: bool | None = None
    
    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        return self._target_state is True and self._current_state is not False 
    
    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return self._target_state is True and self._current_state is False
    
    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return self._target_state is False and self._current_state is True
    

    async def async_lock(self, **kwargs) -> None:
        """Lock the lock."""

        self._target_state = not self._mapping.reverse
        self.async_write_ha_state()

        datapoint = self._device.datapoints.get_or_create(
            self._mapping.lock_dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            not self._mapping.reverse,
        )
        
        if datapoint:
            self._hass.create_task(datapoint.set_value(not self._mapping.reverse))


    async def async_unlock(self, **kwargs) -> None:
        """Unlock the lock."""
        
        self._target_state = self._mapping.reverse
        self.async_write_ha_state()

        datapoint = self._device.datapoints.get_or_create(
            self._mapping.lock_dp_id,
            TuyaBLEDataPointType.DT_BOOL,
            self._mapping.reverse,
        )

        if datapoint:
            self._hass.create_task(datapoint.set_value(self._mapping.reverse))
        
    
    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        # Check both lock_motor_state and automatic_lock datapoints for changes
        lock_datapoint = self._device.datapoints[self._mapping.lock_dp_id]
        if lock_datapoint:
            self._target_state = self._mapping.reverse ^ bool(lock_datapoint.value)

        if self._mapping.state_dp_id > 0:
            state_datapoint = self._device.datapoints[self._mapping.state_dp_id]
            if state_datapoint:
                self._current_state = self._mapping.reverse ^ bool(state_datapoint.value)

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
            )
        )
    
    async_add_entities(entities)