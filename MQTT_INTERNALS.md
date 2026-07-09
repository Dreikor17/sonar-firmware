# MQTT Bridge Internals

Developer-facing notes on how the MQTT observer feature is structured in the codebase: source files, the seams that keep it isolated from upstream MeshCore code, and how on-device settings are migrated across firmware versions. For user-facing setup and CLI reference, see [MQTT_IMPLEMENTATION.md](MQTT_IMPLEMENTATION.md).

## Files

### Core Implementation
- `src/helpers/bridges/MQTTBridge.h` - MQTT bridge class definition
- `src/helpers/bridges/MQTTBridge.cpp` - MQTT bridge implementation
- `src/helpers/MQTTPresets.h` - Preset definitions, CA certificates, and lookup functions
- `src/helpers/MQTTDefaults.h` - Compile-time defaults for fresh `/mqtt_prefs`
- `src/helpers/MQTTMessageBuilder.h` - JSON message formatting utilities
- `src/helpers/MQTTMessageBuilder.cpp` - JSON message formatting implementation
- `src/helpers/JWTHelper.h` - JWT token generation for Ed25519-based authentication
- `src/helpers/CommonCLI_Observer.cpp` - All observer CLI command handling (MQTT, WiFi,
  timezone, NTP, OTA, SNMP, alerts)

### Integration seams with upstream code

The observer feature is kept out of upstream-tracked files through three mechanisms:

- **CLI hook methods** — upstream `CommonCLI.cpp` delegates to three `CommonCLI`
  methods defined in the fork-owned `CommonCLI_Observer.cpp`: `handleObserverCommand()`,
  `handleObserverSetCmd()`, and `handleObserverGetCmd()`. Each returns `true` if it
  consumed the command, otherwise the upstream parser runs. Only these three call
  sites touch upstream CLI code.
- **Callback virtuals** — observer behaviour needed from the application is exposed
  as default-no-op virtuals on `CommonCLICallbacks` (e.g. `restartBridgeSlot`,
  `isMqttBridgeRunning`, `syncMqttNtp`, `onAlertConfigChanged`, `sendAlertText`,
  `resolveAlertScope`, `beginDeferredOtaUpdate`). The example apps override them
  behind `#ifdef WITH_MQTT_BRIDGE`.
- **Separate settings file** — observer settings (MQTT slots, WiFi, timezone, SNMP,
  radio watchdog, fault alerts) live in the `MQTTPrefs` struct persisted to
  `/mqtt_prefs`, keeping `NodePrefs` / `/com_prefs` aligned with the upstream layout.

Remaining integration points in upstream files:
- `examples/simple_repeater/MyMesh.{h,cpp}`, `examples/simple_room_server/MyMesh.{h,cpp}` -
  bridge/alerter/SNMP wiring and packet-feed hooks, guarded by `#ifdef WITH_MQTT_BRIDGE`
- `src/helpers/CommonCLI.{h,cpp}` - the three CLI hooks, `MQTTPrefs` load/save/migration
- `src/Dispatcher.{h,cpp}` - radio watchdog block, guarded by `#ifdef WITH_MQTT_BRIDGE`

### Settings upgrade / migration

`loadPrefs()` handles all historical on-device formats one-time at boot:
- `/mqtt_prefs` written in the pre-slot or 3-slot layouts is field-copied into the
  current 6-slot `MQTTPrefs` layout (size-based detection).
- A `/com_prefs` written by fork firmware that predates the `MQTTPrefs` split (which
  contained a zero-filled MQTT gap plus a trailing observer block) is detected by its
  size; the trailing SNMP / radio-watchdog / fault-alert settings and the
  `rx_boosted_gain` / `flood_max_*` fields are recovered, carried into `/mqtt_prefs`,
  and both files are rewritten in the current formats.
- Settings the pre-split firmware stored *inside* the `/com_prefs` MQTT gap (the MQTT
  slot/WiFi config itself) are **not** recovered — users upgrading from firmware that
  old must re-enter their MQTT and WiFi configuration.
