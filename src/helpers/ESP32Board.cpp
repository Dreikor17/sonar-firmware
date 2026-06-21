#ifdef ESP_PLATFORM

#include "ESP32Board.h"

#if defined(ADMIN_PASSWORD) && !defined(DISABLE_WIFI_OTA)   // Repeater or Room Server only
#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <AsyncElegantOTA.h>

#include <SPIFFS.h>

bool ESP32Board::startOTAUpdate(const char* id, char reply[]) {
  inhibit_sleep = true;   // prevent sleep during OTA
  WiFi.softAP("MeshCore-OTA", NULL);

  sprintf(reply, "Started: http://%s/update", WiFi.softAPIP().toString().c_str());
  MESH_DEBUG_PRINTLN("startOTAUpdate: %s", reply);

  static char id_buf[60];
  sprintf(id_buf, "%s (%s)", id, getManufacturerName());
  static char home_buf[90];
  sprintf(home_buf, "<H2>Hi! I am a MeshCore Repeater. ID: %s</H2>", id);

  AsyncWebServer* server = new AsyncWebServer(80);

  server->on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", home_buf);
  });
  server->on("/log", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(SPIFFS, "/packet_log", "text/plain");
  });

  AsyncElegantOTA.setID(id_buf);
  AsyncElegantOTA.begin(server);    // Start ElegantOTA
  server->begin();

  return true;
}

#else
bool ESP32Board::startOTAUpdate(const char* id, char reply[]) {
  return false; // not supported
}
#endif

// ---------------------------------------------------------------------------
// Manifest-driven pull OTA (observer / MQTT-bridge builds only)
//
// The observer already holds a live WiFi station connection (for the MQTT
// bridge) and embeds a root-CA bundle, so it can fetch its own firmware. The
// caller (CommonCLI) stops the MQTT bridge first to free heap/TLS, then calls
// this. We read the web-flasher manifest (config.json), find the `flash-update`
// (app-only) build for our own variant, refuse partition-change releases (OTA
// can't rewrite the partition table), skip if already up to date, then stream
// the .bin straight into the inactive OTA slot via HTTPUpdate.
// ---------------------------------------------------------------------------
#if defined(WITH_MQTT_BRIDGE)
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <ArduinoJson.h>

// Embedded CA bundle (produced by board_build.embed_files). Weak so non-bundle
// builds still link; we check for presence at runtime.
extern const uint8_t rootca_crt_bundle_start[] asm("_binary_src_certs_x509_crt_bundle_bin_start") __attribute__((weak));
extern const uint8_t rootca_crt_bundle_end[] asm("_binary_src_certs_x509_crt_bundle_bin_end") __attribute__((weak));

// Extract the trailing build hash. For a filename we first drop a ".bin"
// suffix, then take the token after the last '-'. Works for both the manifest
// asset name ("...-v1.16.0-8b084d5.bin" -> "8b084d5") and the embedded
// FIRMWARE_VERSION ("v1.16.0-observer-8b084d5" -> "8b084d5").
static void ota_extractHash(const char* s, char* out, size_t out_sz) {
  if (!s) { if (out_sz) out[0] = 0; return; }
  size_t len = strlen(s);
  if (len > 4 && strcmp(s + len - 4, ".bin") == 0) len -= 4;
  size_t i = len;
  while (i > 0 && s[i - 1] != '-') i--;
  size_t n = len - i;
  if (n >= out_sz) n = out_sz - 1;
  memcpy(out, s + i, n);
  out[n] = 0;
}

bool ESP32Board::otaFromManifest(const char* current_ver, bool dry_run, char reply[]) {
#if !defined(OTA_MANIFEST_URL) || !defined(OTA_VARIANT)
  strcpy(reply, "ERR: OTA not configured (build via build.sh)");
  return false;
#else
  if (WiFi.status() != WL_CONNECTED) {
    strcpy(reply, "ERR: WiFi not connected");
    return false;
  }

  size_t bundle_len = 0;
  if (rootca_crt_bundle_start != nullptr && rootca_crt_bundle_end != nullptr &&
      rootca_crt_bundle_end > rootca_crt_bundle_start) {
    bundle_len = (size_t)(rootca_crt_bundle_end - rootca_crt_bundle_start);
  }
  if (bundle_len == 0) {
    strcpy(reply, "ERR: no embedded cert bundle");
    return false;
  }

  // --- Fetch + filter-parse the manifest -----------------------------------
  WiFiClientSecure mclient;
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  mclient.setCACertBundle(rootca_crt_bundle_start, bundle_len);
#else
  mclient.setCACertBundle(rootca_crt_bundle_start);
#endif
  mclient.setTimeout(15000);

  HTTPClient http;
  if (!http.begin(mclient, OTA_MANIFEST_URL)) {
    strcpy(reply, "ERR: manifest connect failed");
    return false;
  }
  int code = http.GET();
  if (code != HTTP_CODE_OK) {
    snprintf(reply, 160, "ERR: manifest HTTP %d", code);
    http.end();
    return false;
  }

  // Filter keeps only staticPath + each firmware entry's notice/version, so the
  // parsed document stays a fraction of the full manifest. (The dynamic version
  // key forces keeping its whole subtree, incl. release notes.) ArduinoJson v7
  // JsonDocument allocates elastically, so this only grows to the kept subset.
  JsonDocument filter;
  filter["staticPath"] = true;
  filter["device"][0]["firmware"][0]["notice"] = true;
  filter["device"][0]["firmware"][0]["version"] = true;

  JsonDocument doc;
  DeserializationError err =
      deserializeJson(doc, http.getStream(), DeserializationOption::Filter(filter));
  http.end();
  if (err) {
    snprintf(reply, 160, "ERR: manifest parse (%s)", err.c_str());
    return false;
  }

  // Copy out of the document up front: doc gets cleared before these are used.
  char base_url[128] = {0};
  strncpy(base_url, doc["staticPath"] | "", sizeof(base_url) - 1);
  if (!base_url[0]) {
    strcpy(reply, "ERR: manifest missing staticPath");
    return false;
  }

  // --- Locate the flash-update build for our variant -----------------------
  const char* variant = OTA_VARIANT;
  size_t vlen = strlen(variant);
  char target_name[128] = {0};
  bool partition_change = false;
  bool found = false;

  for (JsonObject dev : doc["device"].as<JsonArray>()) {
    for (JsonObject fw : dev["firmware"].as<JsonArray>()) {
      const char* notice = fw["notice"].is<const char*>() ? fw["notice"].as<const char*>() : nullptr;
      for (JsonPair vp : fw["version"].as<JsonObject>()) {
        for (JsonObject file : vp.value()["files"].as<JsonArray>()) {
          const char* type = file["type"] | "";
          const char* name = file["name"] | "";
          if (strcmp(type, "flash-update") != 0) continue;
          if (strncmp(name, variant, vlen) != 0 || name[vlen] != '-') continue;
          strncpy(target_name, name, sizeof(target_name) - 1);
          partition_change = (notice != nullptr && strcmp(notice, "partition-change") == 0);
          found = true;
          break;
        }
        if (found) break;
      }
      if (found) break;
    }
    if (found) break;
  }
  doc.clear();

  if (!found) {
    snprintf(reply, 160, "ERR: no build for %s in manifest", variant);
    return false;
  }

  char avail_hash[24], cur_hash[24];
  ota_extractHash(target_name, avail_hash, sizeof(avail_hash));
  ota_extractHash(current_ver, cur_hash, sizeof(cur_hash));
  // Compare by shared prefix: git abbreviates the same commit to 7 chars on a
  // shallow CI clone but 8 locally, so an exact match would miss equal builds.
  size_t la = strlen(avail_hash), lc = strlen(cur_hash);
  size_t m = (la < lc) ? la : lc;
  bool up_to_date = (m >= 7 && strncmp(avail_hash, cur_hash, m) == 0);

  if (dry_run) {
    snprintf(reply, 160, "%s: %s -> %s%s", up_to_date ? "up to date" : "update available",
             cur_hash, avail_hash, partition_change ? " [partition change: cable flash]" : "");
    return true;
  }
  if (partition_change) {
    snprintf(reply, 160, "ERR: %s needs cable flash (partition change)", avail_hash);
    return false;
  }
  if (up_to_date) {
    snprintf(reply, 160, "OK: already up to date (%s)", cur_hash);
    return false;
  }

  // --- Stream the .bin into the inactive OTA slot --------------------------
  char url[256];
  snprintf(url, sizeof(url), "%s/%s", base_url, target_name);

  inhibit_sleep = true;  // keep awake through the flash

  WiFiClientSecure uclient;
#if ESP_ARDUINO_VERSION_MAJOR >= 3
  uclient.setCACertBundle(rootca_crt_bundle_start, bundle_len);
#else
  uclient.setCACertBundle(rootca_crt_bundle_start);
#endif
  uclient.setTimeout(20000);

  httpUpdate.rebootOnUpdate(true);  // reboots into the new image on success
  t_httpUpdate_return ret = httpUpdate.update(uclient, url);

  // Only reached on failure (success reboots inside update()).
  inhibit_sleep = false;
  snprintf(reply, 160, "ERR: OTA failed (%d): %s", (int)ret,
           httpUpdate.getLastErrorString().c_str());
  return false;
#endif  // OTA_MANIFEST_URL && OTA_VARIANT
}
#else
bool ESP32Board::otaFromManifest(const char* current_ver, bool dry_run, char reply[]) {
  strcpy(reply, "ERR: not supported");
  return false;
}
#endif  // WITH_MQTT_BRIDGE

#endif
