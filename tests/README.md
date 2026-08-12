# Off-hardware checks for the lock support

Plain scripts, no framework, no dependencies beyond the standard library - the
module they cover imports neither Home Assistant nor bleak, which is a property
worth keeping.

```
python3 tests/test_lock_capabilities.py   # which datapoints a given lock has
```

Exits non-zero on the first failure.

The product specifications it asserts against were captured from real devices
rather than copied out of the Tuya reference; where the two disagree, the
comments say so and the capture wins.

`TUYA_BLE_COMPONENT` points the harness at another copy of the component, which
is how a change can be checked against the behaviour before it.
