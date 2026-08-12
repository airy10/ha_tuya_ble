"""Config flow for Tuya BLE integration."""

from __future__ import annotations

import asyncio
import logging
from functools import partial
import pycountry
from typing import Any

import voluptuous as vol
from tuya_iot import AuthType

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    OptionsFlowWithConfigEntry,
)
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.const import (
    CONF_ADDRESS, 
    CONF_DEVICE_ID,
    CONF_COUNTRY_CODE,
    CONF_NAME,
    CONF_PASSWORD,
    CONF_USERNAME,
)
from homeassistant.core import callback
from homeassistant.helpers import selector
from homeassistant.data_entry_flow import FlowHandler, FlowResult

from .tuya_ble import SERVICE_UUID, TuyaBLEDeviceCredentials

from .const import (
    TUYA_COUNTRIES,
    TUYA_SMART_APP,
    SMARTLIFE_APP,
    TUYA_RESPONSE_SUCCESS,
    TUYA_RESPONSE_CODE,
    TUYA_RESPONSE_MSG,
    CONF_ACCESS_ID,
    CONF_ACCESS_SECRET,
    CONF_APP_TYPE,
    CONF_AUTH_TYPE,
    CONF_ENDPOINT,
    CONF_PERSON,
    DOMAIN,
)
from . import lock_credential_store as credential_store
from .lock_credential_manager import (
    TuyaBLELockCredentials,
    TuyaBLELockCredentialsError,
)

from .devices import TuyaBLEData, get_device_readable_name
from .cloud import HASSTuyaBLEDeviceManager

# Picking this in the credential list starts an enrollment instead of editing.
CHOICE_ADD = "add"
CONF_CREDENTIAL = "credential"
CONF_DELETE = "delete"

_LOGGER = logging.getLogger(__name__)


async def _try_login(
    manager: HASSTuyaBLEDeviceManager,
    user_input: dict[str, Any],
    errors: dict[str, str],
    placeholders: dict[str, Any],
) -> dict[str, Any] | None:
    response: dict[Any, Any] | None
    data: dict[str, Any]

    country = [
        country
        for country in TUYA_COUNTRIES
        if country.name == user_input[CONF_COUNTRY_CODE]
    ][0]

    data = {
        CONF_ENDPOINT: country.endpoint,
        CONF_AUTH_TYPE: AuthType.CUSTOM,
        CONF_ACCESS_ID: user_input[CONF_ACCESS_ID],
        CONF_ACCESS_SECRET: user_input[CONF_ACCESS_SECRET],
        CONF_USERNAME: user_input[CONF_USERNAME],
        CONF_PASSWORD: user_input[CONF_PASSWORD],
        CONF_COUNTRY_CODE: country.country_code,
    }

    for app_type in (TUYA_SMART_APP, SMARTLIFE_APP, ""):
        data[CONF_APP_TYPE] = app_type
        if app_type == "":
            data[CONF_AUTH_TYPE] = AuthType.CUSTOM
        else:
            data[CONF_AUTH_TYPE] = AuthType.SMART_HOME

        response = await manager._login(data, True)

        if response.get(TUYA_RESPONSE_SUCCESS, False):
            return data

    errors["base"] = "login_error"
    if response:
        placeholders.update(
            {
                TUYA_RESPONSE_CODE: response.get(TUYA_RESPONSE_CODE),
                TUYA_RESPONSE_MSG: response.get(TUYA_RESPONSE_MSG),
            }
        )

    return None


def _show_login_form(
    flow: FlowHandler,
    user_input: dict[str, Any],
    errors: dict[str, str],
    placeholders: dict[str, Any],
    def_country_name: str | None = None,
) -> FlowResult:
    """Shows the Tuya IOT platform login form."""
    if user_input is not None and user_input.get(CONF_COUNTRY_CODE) is not None:
        for country in TUYA_COUNTRIES:
            if country.country_code == user_input[CONF_COUNTRY_CODE]:
                user_input[CONF_COUNTRY_CODE] = country.name
                break

    return flow.async_show_form(
        step_id="login",
        data_schema=vol.Schema(
            {
                vol.Required(
                    CONF_COUNTRY_CODE,
                    default=user_input.get(CONF_COUNTRY_CODE, def_country_name),
                ): vol.In(
                    # We don't pass a dict {code:name} because country codes can be duplicate.
                    [country.name for country in TUYA_COUNTRIES]
                ),
                vol.Required(
                    CONF_ACCESS_ID, default=user_input.get(CONF_ACCESS_ID, "")
                ): str,
                vol.Required(
                    CONF_ACCESS_SECRET,
                    default=user_input.get(CONF_ACCESS_SECRET, ""),
                ): str,
                vol.Required(
                    CONF_USERNAME, default=user_input.get(CONF_USERNAME, "")
                ): str,
                vol.Required(
                    CONF_PASSWORD, default=user_input.get(CONF_PASSWORD, "")
                ): str,
            }
        ),
        errors=errors,
        description_placeholders=placeholders,
    )


async def _async_get_default_country_name(hass) -> str | None:
    """Resolve the system country name without blocking the event loop."""
    if not hass.config.country:
        return None

    def_country = await hass.async_add_executor_job(
        partial(pycountry.countries.get, alpha_2=hass.config.country)
    )
    return def_country.name if def_country else None


class TuyaBLEOptionsFlow(OptionsFlowWithConfigEntry):
    """Handle a Tuya BLE options flow."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        super().__init__(config_entry)
        # The enrollment in flight, and the credential the fingerprint screens
        # are working on.
        self._task: asyncio.Task[int] | None = None
        self._selected: int | None = None

    def _credentials(self) -> TuyaBLELockCredentials | None:
        """Return the credential manager, when the lock has one."""
        data: TuyaBLEData | None = self.hass.data.get(DOMAIN, {}).get(
            self.config_entry.entry_id
        )
        if data is None or data.lock_credentials is None:
            return None
        return data.lock_credentials if data.lock_credentials.supported else None

    @callback
    def async_remove(self) -> None:
        """Tell the lock to stop when the wizard is abandoned.

        Home Assistant cancels the progress task itself just before calling
        this, which frees the credential manager's slot, but it cannot reach
        the lock: the reader would keep waiting for a finger until its own
        timeout. This is a callback, so the cancellation is left to the loop.
        """
        task, self._task = self._task, None
        if task is None:
            return
        manager = self._credentials()
        _LOGGER.debug(
            "Fingerprint wizard abandoned, telling the lock to stop (manager=%s)",
            manager is not None,
        )
        if manager is not None:
            self.hass.async_create_task(manager.async_cancel_enrollment())

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Offer the Tuya login and, for locks, fingerprint management."""
        if self._credentials() is None:
            return await self.async_step_login(user_input)
        return self.async_show_menu(
            step_id="init", menu_options=["credentials", "login"]
        )

    async def async_step_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """List what the lock holds and let one of them be picked.

        The lock is the source of truth for which credentials exist; Home
        Assistant only adds the labels, so a fingerprint enrolled from the Tuya
        app can be named here without re-enrolling it.
        """
        manager = self._credentials()
        if manager is None:
            return self.async_abort(reason="lock_unavailable")

        if user_input is not None:
            choice = user_input[CONF_CREDENTIAL]
            if choice == CHOICE_ADD:
                return await self.async_step_enroll()
            self._selected = int(choice)
            return await self.async_step_edit()

        try:
            held = await manager.async_list()
        except TuyaBLELockCredentialsError as err:
            _LOGGER.warning("Could not read the lock's fingerprints: %s", err)
            return self.async_abort(reason="lock_unavailable")

        known = credential_store.get_all(self.config_entry)
        # Credentials first and enrolment last: the frontend preselects the
        # first option, and that should not start an enrolment.
        options: dict[str, str] = {}
        for credential in held:
            described = known.get(str(credential.hardware_id), {})
            label = described.get(CONF_NAME) or "unnamed"
            options[str(credential.hardware_id)] = (
                f"#{credential.hardware_id} - {label}"
                + (" (admin)" if credential.is_admin else "")
            )
        options[CHOICE_ADD] = "Add a new fingerprint"

        return self.async_show_form(
            step_id="credentials",
            data_schema=vol.Schema(
                {vol.Required(CONF_CREDENTIAL): vol.In(options)}
            ),
            description_placeholders={"count": str(len(held))},
        )

    async def async_step_edit(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Rename a credential, link a person to it, or take it off the lock."""
        manager = self._credentials()
        if manager is None or self._selected is None:
            return self.async_abort(reason="lock_unavailable")

        if user_input is not None:
            if user_input.get(CONF_DELETE):
                try:
                    await manager.async_remove(self._selected)
                except TuyaBLELockCredentialsError as err:
                    return self.async_abort(
                        reason="remove_failed",
                        description_placeholders={"error": str(err)},
                    )
                credential_store.async_remove(
                    self.hass, self.config_entry, self._selected
                )
            else:
                credential_store.async_set(
                    self.hass,
                    self.config_entry,
                    self._selected,
                    name=user_input[CONF_NAME],
                    person=user_input.get(CONF_PERSON),
                )
            return await self.async_step_credentials()

        known = credential_store.get(self.config_entry, self._selected)
        schema: dict[Any, Any] = {
            vol.Required(CONF_NAME, default=known.get(CONF_NAME) or ""): (
                selector.TextSelector()
            ),
            # Optional on purpose: a guest or a cleaner may have no Home
            # Assistant account at all, and a name is enough.
            vol.Optional(
                CONF_PERSON,
                description={"suggested_value": known.get(CONF_PERSON)},
            ): selector.EntitySelector(
                selector.EntitySelectorConfig(domain="person")
            ),
            vol.Optional(CONF_DELETE, default=False): selector.BooleanSelector(),
        }
        return self.async_show_form(
            step_id="edit",
            data_schema=vol.Schema(schema),
            description_placeholders={"credential_id": str(self._selected)},
        )

    async def async_step_enroll(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Wait for the lock while the finger is presented."""
        manager = self._credentials()
        if manager is None:
            return self.async_abort(reason="lock_unavailable")

        if self._task is None:
            self._task = self.hass.async_create_task(manager.async_add_fingerprint())

        if not self._task.done():
            return self.async_show_progress(
                step_id="enroll",
                progress_action="enroll",
                progress_task=self._task,
            )

        return self.async_show_progress_done(next_step_id="enrolled")

    async def async_step_enrolled(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Take the id the lock assigned and go straight to naming it."""
        task, self._task = self._task, None
        if task is None:
            return self.async_abort(reason="lock_unavailable")
        try:
            self._selected = task.result()
        except TuyaBLELockCredentialsError as err:
            _LOGGER.warning("Enrolling a fingerprint failed: %s", err)
            return self.async_abort(
                reason="enroll_failed", description_placeholders={"error": str(err)}
            )
        return await self.async_step_edit()

    async def async_step_login(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the Tuya IOT platform login step."""
        errors: dict[str, str] = {}
        placeholders: dict[str, Any] = {}
        credentials: TuyaBLEDeviceCredentials | None = None
        address: str | None = self.config_entry.data.get(CONF_ADDRESS)

        if user_input is not None:
            entry: TuyaBLEData | None = None
            domain_data = self.hass.data.get(DOMAIN)
            if domain_data:
                entry = domain_data.get(self.config_entry.entry_id)
            if entry:
                login_data = await _try_login(
                    entry.manager,
                    user_input,
                    errors,
                    placeholders,
                )
                if login_data:
                    credentials = await entry.manager.get_device_credentials(
                        address, True, True
                    )
                    if credentials:
                        return self.async_create_entry(
                            title=self.config_entry.title,
                            data=entry.manager.data,
                        )
                    else:
                        errors["base"] = "device_not_registered"

        if user_input is None:
            user_input = {}
            user_input.update(self.config_entry.options)

        def_country_name = None
        if not user_input.get(CONF_COUNTRY_CODE):
            def_country_name = await _async_get_default_country_name(self.hass)

        return _show_login_form(
            self,
            user_input,
            errors,
            placeholders,
            def_country_name,
        )


class TuyaBLEConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Tuya BLE."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        super().__init__()
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}
        self._data: dict[str, Any] = {}
        self._manager: HASSTuyaBLEDeviceManager | None = None
        self._get_device_info_error = False

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        """Handle the bluetooth discovery step."""
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovery_info = discovery_info
        if self._manager is None:
            self._manager = HASSTuyaBLEDeviceManager(self.hass, self._data)
        await self._manager.build_cache()
        self.context["title_placeholders"] = {
            "name": await get_device_readable_name(
                discovery_info,
                self._manager,
            )
        }
        return await self.async_step_login()

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step."""
        if self._manager is None:
            self._manager = HASSTuyaBLEDeviceManager(self.hass, self._data)
        await self._manager.build_cache()
        return await self.async_step_login()

    async def async_step_login(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the Tuya IOT platform login step."""
        data: dict[str, Any] | None = None
        errors: dict[str, str] = {}
        placeholders: dict[str, Any] = {}

        if user_input is not None:
            data = await _try_login(
                self._manager,
                user_input,
                errors,
                placeholders,
            )
            if data:
                self._data.update(data)
                return await self.async_step_device()

        if user_input is None:
            user_input = {}
            if self._discovery_info:
                await self._manager.get_device_credentials(
                    self._discovery_info.address,
                    False,
                    True,
                )
            if self._data is None or len(self._data) == 0:
                self._manager.get_login_from_cache()
            if self._data is not None and len(self._data) > 0:
                user_input.update(self._data)

        def_country_name = None
        if not user_input.get(CONF_COUNTRY_CODE):
            def_country_name = await _async_get_default_country_name(self.hass)

        return _show_login_form(
            self,
            user_input,
            errors,
            placeholders,
            def_country_name,
        )

    async def async_step_device(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the user step to pick discovered device."""
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            discovery_info = self._discovered_devices[address]
            local_name = await get_device_readable_name(discovery_info, self._manager)
            await self.async_set_unique_id(
                discovery_info.address, raise_on_progress=False
            )
            self._abort_if_unique_id_configured()
            credentials = await self._manager.get_device_credentials(
                discovery_info.address, self._get_device_info_error, True
            )
            self._data[CONF_ADDRESS] = discovery_info.address
            if credentials is None:
                self._get_device_info_error = True
                errors["base"] = "device_not_registered"
            else:
                return self.async_create_entry(
                    title=local_name,
                    data={CONF_ADDRESS: discovery_info.address},
                    options=self._data,
                )

        if discovery := self._discovery_info:
            self._discovered_devices[discovery.address] = discovery
        else:
            current_addresses = self._async_current_ids()
            for discovery in async_discovered_service_info(self.hass):
                if (
                    discovery.address in current_addresses
                    or discovery.address in self._discovered_devices
                    or discovery.service_data is None
                    or not SERVICE_UUID in discovery.service_data.keys()
                ):
                    continue
                self._discovered_devices[discovery.address] = discovery

        if not self._discovered_devices:
            return self.async_abort(reason="no_unconfigured_devices")

        def_address: str
        if user_input:
            def_address = user_input.get(CONF_ADDRESS)
        else:
            def_address = list(self._discovered_devices)[0]

        return self.async_show_form(
            step_id="device",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_ADDRESS,
                        default=def_address,
                    ): vol.In(
                        {
                            service_info.address: await get_device_readable_name(
                                service_info,
                                self._manager,
                            )
                            for service_info in self._discovered_devices.values()
                        }
                    ),
                },
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: ConfigEntry,
    ) -> TuyaBLEOptionsFlow:
        """Get the options flow for this handler."""
        return TuyaBLEOptionsFlow(config_entry)
