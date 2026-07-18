#pragma once

#include <string.h>
#include "MQTTPresets.h"  // MAX_MQTT_SLOTS

// Classification of the config keys the web portal is allowed to drive through
// the CLI `set` handlers. Factored out of WebConfigServer.cpp so the allowlist
// and the (attacker-facing) key parsing can be unit-tested on the host without
// pulling in the whole ESP32 web server (see test/test_webconfig_keys).
//
// Everything here is pure string logic. The functions are `static inline` so
// each translation unit that includes this gets its own copy (there are only
// two: WebConfigServer.cpp and the test), avoiding any ODR concern.

// Keys mapping to CLI `set <key> <value>` handlers. Everything not listed here
// is rejected, so a crafted request can't reach arbitrary commands (`erase`,
// `password`, ...) through the batch.
static const char* const WC_ALLOWED_SET_KEYS[] = {
  // NodePrefs (radio / node)
  "name", "lat", "lon", "radio", "tx", "af", "rxdelay", "txdelay",
  "cad", "radio.rxgain", "repeat", "advert.interval", "flood.advert.interval",
  "flood.max", "flood.max.advert", "flood.max.unscoped", "loop.detect",
  // MQTTPrefs (WiFi / MQTT / misc observer)
  "wifi.ssid", "wifi.pwd", "wifi.powersave",
  "mqtt.origin", "mqtt.iata", "mqtt.status", "mqtt.packets", "mqtt.raw",
  "mqtt.tx", "mqtt.rx", "mqtt.interval", "mqtt.ntp", "mqtt.owner", "mqtt.email",
  "timezone", "timezone.offset", "snmp", "snmp.community",
};
static const char* const WC_ALLOWED_SLOT_KEYS[] = {
  "preset", "server", "port", "username", "password", "token", "topic", "audience",
};

// True when `key` is a well-formed per-slot key ("mqttN.<field>" with N in
// 1..MAX_MQTT_SLOTS). The shortest such key is "mqttN.x" (7 chars), and this
// probes key[4..6], so the length guard must come first — an attacker-supplied
// "mqtt" or "m" would otherwise read past the terminator.
static inline bool wcIsSlotKeyPrefix(const char* key) {
  return strlen(key) >= 7 && memcmp(key, "mqtt", 4) == 0
      && key[4] >= '1' && key[4] <= ('0' + MAX_MQTT_SLOTS) && key[5] == '.';
}

static inline bool wcIsAllowedSetKey(const char* key) {
  for (size_t i = 0; i < sizeof(WC_ALLOWED_SET_KEYS) / sizeof(WC_ALLOWED_SET_KEYS[0]); i++) {
    if (strcmp(key, WC_ALLOWED_SET_KEYS[i]) == 0) return true;
  }
  // mqtt<1-6>.<field>
  if (wcIsSlotKeyPrefix(key)) {
    for (size_t i = 0; i < sizeof(WC_ALLOWED_SLOT_KEYS) / sizeof(WC_ALLOWED_SLOT_KEYS[0]); i++) {
      if (strcmp(&key[6], WC_ALLOWED_SLOT_KEYS[i]) == 0) return true;
    }
  }
  return false;
}

// Keys carrying a secret whose stored value is masked with the placeholder in
// the UI; a POST echoing the placeholder for one of these is dropped (unchanged).
static inline bool wcIsSecretKey(const char* key) {
  if (strcmp(key, "wifi.pwd") == 0) return true;
  if (wcIsSlotKeyPrefix(key)
      && (strcmp(&key[6], "password") == 0 || strcmp(&key[6], "token") == 0)) return true;
  return false;
}
