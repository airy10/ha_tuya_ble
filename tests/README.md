# Off-hardware checks for the lock support

Plain scripts, no framework, no dependencies beyond the standard library - the
modules they cover import neither Home Assistant nor bleak, which is a property
worth keeping.

```
python3 tests/test_lock_credentials.py          # wire format of the raw datapoints
python3 tests/test_lock_capabilities.py         # which datapoints a given lock has
python3 tests/test_lock_credential_manager.py   # request/report transactions
```

Each exits non-zero on the first failure.

Every byte layout asserted in `test_lock_credentials.py` was captured from a
real lock rather than copied out of the Tuya reference; where the two disagree,
the comments say so and the capture wins.

`TUYA_BLE_COMPONENT` points a harness at another copy of the component, which is
how a change can be checked against the behaviour before it. `REPO_ROOT` does
the same for `test_lock_credentials.py`.
