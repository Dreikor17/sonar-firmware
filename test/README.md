# Host unit tests

Fast, hardware-free unit tests for the fork's pure logic, run on the host with
GoogleTest via PlatformIO's `native` environment. They cover the extractable
observer/WebConfig logic (validation, preset table, topic templates, key
parsing) — the parts that don't depend on the ESP32, radio, or network stack.
Integration behavior (AsyncTCP transport, WiFi/MQTT, SoftAP) is exercised
separately; see "Local testing without hardware" in `MQTT_IMPLEMENTATION.md`.

## Running

```sh
pio test -e native                      # all suites
pio test -e native -f test_webconfig_keys   # a single suite
```

A green `[PASSED]` per suite means GoogleTest returned 0 (all assertions
passed). PlatformIO's "0 test cases" line is just its Unity-style counter and
does not reflect the GoogleTest count — run the built binary directly
(`.pio/build/native/program`) to see the per-assertion breakdown.

## Suites

| Suite | Source under test | Covers |
|-------|-------------------|--------|
| `test_mqtt_presets` | `src/helpers/MQTTPresets.h` | preset lookup; table integrity (unique names, non-empty URLs, JWT-audience invariant, names fit the slot buffer); `mqttPresetNeedsSlotCredentials`; slot-count constants |
| `test_observer_validation` | `src/helpers/MQTTObserverValidation.h` | IATA (exactly 3 alphanumerics), owner key (64 hex), NTP hostname, and the buffer-fit check behind the #17 length validation — including boundaries and nulls |
| `test_webconfig_keys` | `src/helpers/WebConfigKeys.h` | POST-key allowlist, secret detection, slot-index bounds, and the short-key out-of-bounds guard (attacker-supplied keys) |
| `test_topic_template` | `src/helpers/MQTTTopicTemplate.h` | `{iata}/{device}/{token}/{type}` expansion, overflow/NUL-termination, and a buffer-size fuzz |
| `test_utils` | `src/Utils.cpp` | `Utils::toHex` (upstream) |

## Conventions (and how to add a suite)

- Each `test/test_<name>/` directory builds into its **own** GoogleTest program
  and must define its own `main()` (`::testing::InitGoogleTest` + `RUN_ALL_TESTS`).
- Tests are **host-only**: include only pure headers. Arduino/crypto stubs live
  in `test/mocks/` (on the include path via `-I test/mocks`).
- Firmware headers are included from `src` (via `-I src`, e.g.
  `#include "helpers/MQTTPresets.h"`). Some are guarded or ESP-flavored, so a
  suite may need shims **before** the include — e.g. `test_mqtt_presets` does
  `#define WITH_MQTT_BRIDGE 1` (the preset table is behind that flag) and
  `#define PROGMEM` (the embedded CA-cert strings are PROGMEM-qualified).
- To add a suite: create `test/test_<name>/test_<name>.cpp` with a `main()`, and
  add any host-only source it links to the `native` env's `build_src_filter` in
  `platformio.ini` (header-only code needs no source entry). No other wiring.
- Keep logic testable by extracting pure functions into headers (as
  `MQTTObserverValidation.h` / `WebConfigKeys.h` / `MQTTTopicTemplate.h` do) and
  having the firmware call the same functions.
