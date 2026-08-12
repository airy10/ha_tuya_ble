"""Names and people for the credentials a lock holds.

The lock stores numbers; the name and the person live here, keyed by that
number. In `entry.data` rather than `entry.options`, because the Tuya login
flow finishes with `async_create_entry(data=...)` and replaces the options
wholesale.
"""
from __future__ import annotations

from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant, callback

from .const import CONF_CREDENTIALS, CONF_PERSON, CONF_USER_ID


def get_all(entry: ConfigEntry) -> dict[str, dict[str, Any]]:
    """Return every credential description, keyed by credential id."""
    return dict(entry.data.get(CONF_CREDENTIALS, {}))


def get(entry: ConfigEntry, credential_id: int) -> dict[str, Any]:
    """Return what is known about one credential, empty when nothing is."""
    return dict(get_all(entry).get(str(credential_id), {}))


def describe(entry: ConfigEntry, credential_id: int) -> dict[str, Any]:
    """Return name, person and account for a credential the lock reported."""
    known = get_all(entry).get(str(credential_id), {})
    return {
        CONF_NAME: known.get(CONF_NAME),
        CONF_PERSON: known.get(CONF_PERSON),
        CONF_USER_ID: known.get(CONF_USER_ID),
    }


@callback
def async_set(
    hass: HomeAssistant,
    entry: ConfigEntry,
    credential_id: int,
    *,
    name: str,
    person: str | None,
) -> None:
    """Name a credential and optionally link it to a person."""
    credentials = get_all(entry)
    credentials[str(credential_id)] = {
        CONF_NAME: name,
        CONF_PERSON: person,
        # Stored alongside the person: the account is reachable through the
        # person entity, not the other way round.
        CONF_USER_ID: _async_user_id_of(hass, person),
    }
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, CONF_CREDENTIALS: credentials}
    )


@callback
def async_remove(
    hass: HomeAssistant, entry: ConfigEntry, credential_id: int
) -> None:
    """Forget what Home Assistant knew about a credential."""
    credentials = get_all(entry)
    if credentials.pop(str(credential_id), None) is None:
        return
    hass.config_entries.async_update_entry(
        entry, data={**entry.data, CONF_CREDENTIALS: credentials}
    )


def _async_user_id_of(hass: HomeAssistant, person_entity_id: str | None) -> str | None:
    """Return the account behind a person, when there is one."""
    if not person_entity_id:
        return None
    state = hass.states.get(person_entity_id)
    return state.attributes.get("user_id") if state else None
