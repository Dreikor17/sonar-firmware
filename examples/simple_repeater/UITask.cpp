#include "UITask.h"
#include "target.h"
#include "RFLabBrand.h"
#include <Arduino.h>
#include <helpers/CommonCLI.h>

#ifndef USER_BTN_PRESSED
#define USER_BTN_PRESSED LOW
#endif

#ifdef WITH_MQTT_BRIDGE
#include <WiFi.h>
#include <helpers/bridges/MQTTBridge.h>   // MQTT slot status for the status lines
#include <string.h>
#include <helpers/esp32/WebConfigServer.h>   // defines WITH_WEBCONFIG on ESP32
#endif

#define AUTO_OFF_MILLIS      20000  // 20 seconds
#define BOOT_SCREEN_MILLIS   4000   // 4 seconds

#define POWEROFF_DELAY 3000

// 'meshcore', 128x13px
static const uint8_t meshcore_logo [] PROGMEM = {
    0x3c, 0x01, 0xe3, 0xff, 0xc7, 0xff, 0x8f, 0x03, 0x87, 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 
    0x3c, 0x03, 0xe3, 0xff, 0xc7, 0xff, 0x8e, 0x03, 0x8f, 0xfe, 0x3f, 0xfe, 0x1f, 0xff, 0x1f, 0xfe, 
    0x3e, 0x03, 0xc3, 0xff, 0x8f, 0xff, 0x0e, 0x07, 0x8f, 0xfe, 0x7f, 0xfe, 0x1f, 0xff, 0x1f, 0xfc, 
    0x3e, 0x07, 0xc7, 0x80, 0x0e, 0x00, 0x0e, 0x07, 0x9e, 0x00, 0x78, 0x0e, 0x3c, 0x0f, 0x1c, 0x00, 
    0x3e, 0x0f, 0xc7, 0x80, 0x1e, 0x00, 0x0e, 0x07, 0x1e, 0x00, 0x70, 0x0e, 0x38, 0x0f, 0x3c, 0x00, 
    0x7f, 0x0f, 0xc7, 0xfe, 0x1f, 0xfc, 0x1f, 0xff, 0x1c, 0x00, 0x70, 0x0e, 0x38, 0x0e, 0x3f, 0xf8, 
    0x7f, 0x1f, 0xc7, 0xfe, 0x0f, 0xff, 0x1f, 0xff, 0x1c, 0x00, 0xf0, 0x0e, 0x38, 0x0e, 0x3f, 0xf8, 
    0x7f, 0x3f, 0xc7, 0xfe, 0x0f, 0xff, 0x1f, 0xff, 0x1c, 0x00, 0xf0, 0x1e, 0x3f, 0xfe, 0x3f, 0xf0, 
    0x77, 0x3b, 0x87, 0x00, 0x00, 0x07, 0x1c, 0x0f, 0x3c, 0x00, 0xe0, 0x1c, 0x7f, 0xfc, 0x38, 0x00, 
    0x77, 0xfb, 0x8f, 0x00, 0x00, 0x07, 0x1c, 0x0f, 0x3c, 0x00, 0xe0, 0x1c, 0x7f, 0xf8, 0x38, 0x00, 
    0x73, 0xf3, 0x8f, 0xff, 0x0f, 0xff, 0x1c, 0x0e, 0x3f, 0xf8, 0xff, 0xfc, 0x70, 0x78, 0x7f, 0xf8, 
    0xe3, 0xe3, 0x8f, 0xff, 0x1f, 0xfe, 0x3c, 0x0e, 0x3f, 0xf8, 0xff, 0xfc, 0x70, 0x3c, 0x7f, 0xf8, 
    0xe3, 0xe3, 0x8f, 0xff, 0x1f, 0xfc, 0x3c, 0x0e, 0x1f, 0xf8, 0xff, 0xf8, 0x70, 0x3c, 0x7f, 0xf8, 
};

void UITask::begin(NodePrefs* node_prefs, const char* build_date, const char* firmware_version) {
  _prevBtnState = HIGH;
  _auto_off = millis() + AUTO_OFF_MILLIS;
  _started_at = millis();
  _node_prefs = node_prefs;
  _display->turnOn();

#if defined(PIN_USER_BTN) && defined(DISPLAY_CLASS)
  user_btn.begin();
#endif

  // strip off dash and commit hash by changing dash to null terminator
  // e.g: v1.2.3-abcdef -> v1.2.3
  char *version = strdup(firmware_version);
  char *dash = strchr(version, '-');
  if(dash){
    *dash = 0;
  }

  // v1.2.3 (1 Jan 2025)
  snprintf(_version_info, sizeof(_version_info), "%s (%s)", version, build_date);
  free(version);
}

// Take one sample of the radio's cumulative transmit counter, at most one per window.
// Called from loop(), not from the render, so the rate does not depend on the screen
// being awake -- the display sleeps and the counter must keep its history regardless.
void UITask::sampleTxCounter() {
  const unsigned long now = millis();
  if (_tx_next_sample != 0 && now < _tx_next_sample) return;
  _tx_next_sample = now + TX_SAMPLE_MS;
  _tx_head = (_tx_head + 1) % TX_SAMPLES;
  _tx_ring[_tx_head] = (uint32_t)radio_driver.getPacketsSent();
  _tx_ring_at[_tx_head] = now;
  if (_tx_filled < TX_SAMPLES) _tx_filled++;
}

// Transmits in the last hour, or as much of one as we have. False until there is a span
// worth dividing by: a rate extrapolated from a few seconds is noise dressed as data.
bool UITask::txPerHour(uint32_t* out) const {
  if (_tx_filled < 2) return false;
  const int oldest = (_tx_head + TX_SAMPLES - (_tx_filled - 1)) % TX_SAMPLES;
  const unsigned long span = _tx_ring_at[_tx_head] - _tx_ring_at[oldest];
  if (span < 60UL * 1000UL) return false;
  const uint32_t sent = _tx_ring[_tx_head] - _tx_ring[oldest];   // wraps correctly
  *out = (uint32_t)(((uint64_t)sent * 3600000ULL) / span);
  return true;
}

void UITask::renderCurrScreen() {
  char tmp[80];
  if (millis() < _started_at + BOOT_SCREEN_MILLIS) { // boot screen
    // meshcore logo
    _display->setColor(UIColor::corp_blue);
    int logoWidth = 128;
    _display->drawXbm((_display->width() - logoWidth) / 2, 3, meshcore_logo, logoWidth, 13);

    // meshcore website
    const char* website = "https://meshcore.io";
    _display->setColor(UIColor::primary_txt);
    _display->setTextSize(1);
    _display->drawTextCentered(_display->width() / 2, 22, website);

    // version info
    _display->setTextSize(1);
    _display->drawTextCentered(_display->width() / 2, 35, _version_info);

    // node type
    const char* node_type = "< Repeater >";
    _display->drawTextCentered(_display->width() / 2, 48, node_type);
  } else if (_powering_off_at > 0) {
    // meshcore logo
    _display->setColor(UIColor::corp_blue);
    int logoWidth = 128;
    _display->drawXbm((_display->width() - logoWidth) / 2, 3, meshcore_logo, logoWidth, 13);

    // meshcore website
    const char* website = "https://meshcore.io";
    _display->setColor(UIColor::primary_txt);
    _display->setTextSize(1);
    _display->drawTextCentered(_display->width()/ 2, 22, website);

    // Powering off
    const char* poweroff_string = "Turning OFF";
    uint16_t poffWidth = _display->getTextWidth(poweroff_string);
    _display->setCursor((_display->width() - poffWidth) / 2, 48);
    _display->drawTextCentered(_display->width()/2, 48, poweroff_string);
  } else {  // home screen
#ifdef WITH_WEBCONFIG
    if (WebConfigServer::isRebootPending()) {
      // save confirmed on-device: show ground truth even if the browser
      // lost its connection before the confirmation reached it
      _display->setTextSize(1);
      _display->setColor(UIColor::corp_blue);
      _display->setCursor(0, 14);
      _display->print("Config saved!");
      _display->setColor(UIColor::primary_txt);
      _display->setCursor(0, 30);
      _display->print("Rebooting...");
      return;
    }
    char wc_ssid[33], wc_ip[16];
    if (WebConfigServer::getSetupInfo(wc_ssid, sizeof(wc_ssid), wc_ip, sizeof(wc_ip))) {
      // setup portal active: show join instructions instead of the home screen
      _display->setTextSize(1);
      _display->setColor(UIColor::corp_blue);
      _display->setCursor(0, 0);
      _display->print("Observer WiFi Setup");

      _display->setColor(UIColor::primary_txt);
      _display->setCursor(0, 14);
      _display->print("Join WiFi:");
      _display->setColor(UIColor::warning_txt);
      _display->setCursor(6, 24);
      _display->print(wc_ssid);

      _display->setColor(UIColor::primary_txt);
      _display->setCursor(0, 40);
      _display->print("Then browse to:");
      _display->setColor(UIColor::warning_txt);
      _display->setCursor(6, 50);
      _display->print(wc_ip);
      return;
    }
#endif
#ifdef WITH_MQTT_BRIDGE
    // ---- Sonar node screen (128x64) -------------------------------------------------
    // Geometry is fixed by the design handoff: a 38px brand block on the left, a 90px
    // text column on the right, five lines at a 10px pitch. 90px is 15 characters at the
    // stock font's 6px advance, which is exactly what the longest IPv4 (255.255.255.255)
    // needs -- the column was widened from the mock's 75px for that one reason, and the
    // brand block absorbed the difference by dropping the padding around the logo.
    const int BLOCK_W = 38, TEXT_X = BLOCK_W, TEXT_MAX = (128 - BLOCK_W) / 6;
    char line[24];

    // Header: node name, centred, hard-truncated. Names run past 128px easily
    // ("RFLab.io Royal Oaks SNR" is 138px); an ellipsis would cost 3 of 21 characters, so
    // the cut is silent and the operator reads the rest on the Probes page.
    snprintf(line, sizeof(line), "%.21s", _node_prefs->node_name);
    _display->setTextSize(1);
    _display->setColor(UIColor::primary_txt);
    _display->drawTextCentered(64, 2, line);

    // Brand block. The logo is the approved art cropped to its ink, so it is drawn at the
    // position the full 42x42 would have put the ink: x = 4 centres 30px in 38px, and
    // y = 12 + 11 keeps it exactly where the mock has it.
    _display->drawXbm(4, 23, RFLAB_LOGO_BITS, RFLAB_LOGO_W, RFLAB_LOGO_H);
    _display->drawXbm((BLOCK_W - RFLAB_WORDMARK_W) / 2, 54,
                      RFLAB_WORDMARK_BITS, RFLAB_WORDMARK_W, RFLAB_WORDMARK_H);

    // ---- text column ---------------------------------------------------------------
    int ty = 13;
    _display->setColor(UIColor::primary_txt);

    // 1. IP address. Bare, no "IP:" prefix -- the column is sized for the address itself.
    if (WiFi.status() == WL_CONNECTED) {
      IPAddress ip = WiFi.localIP();
      snprintf(line, sizeof(line), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    } else {
      snprintf(line, sizeof(line), "no wifi");
    }
    _display->setCursor(TEXT_X, ty); _display->print(line); ty += 10;

    // 2-3. The first two CONFIGURED MQTT slots, by index order. getSlotStatusSnapshot()
    // returns false for a slot that was never set up, so this skips the gaps rather than
    // showing empty rows for them. A node with one slot shows one line and leaves the
    // second blank; the alternative -- an "MQTT2: --" that never changes -- is noise.
    {
      int shown = 0;
      for (int i = 0; i < MQTTBridge::getRuntimeSlotCount() && shown < 2; i++) {
        MQTTBridge::SlotStatusSnapshot snap;
        if (!MQTTBridge::getSlotStatusSnapshot(i, &snap)) continue;   // unconfigured
        const char* st = snap.state ? snap.state : "?";
        // The node's own vocabulary, shortened to fit and upper-cased to read as status.
        // "fail" is the circuit breaker having given up, which is the one an operator
        // must act on, so it gets the loudest word.
        const char* txt = !strcmp(st, "ok")       ? "OK"
                        : !strcmp(st, "wait")     ? "WAIT"
                        : !strcmp(st, "disc")     ? "DISC"
                        : !strcmp(st, "fail")     ? "ERROR"
                        : !strcmp(st, "inactive") ? "OFF"
                        : st;
        shown++;
        snprintf(line, sizeof(line), "MQTT%d: %s", shown, txt);
        _display->setColor(!strcmp(st, "ok") ? UIColor::primary_txt : UIColor::warning_txt);
        _display->setCursor(TEXT_X, ty); _display->print(line);
        ty += 10;
      }
      while (shown < 2) { shown++; ty += 10; }   // keep the lines below on their rows
      _display->setColor(UIColor::primary_txt);
    }

    // 4. Has a controller adopted this node? A node cannot put itself into the "issued"
    // state -- only a controller holding the shipped key can hand it one of its own -- so
    // this is a truthful answer on the device itself, with nothing to cross-check on a
    // screen somewhere else. It says whether the node is CLAIMED, not whether it is up.
    {
      const uint8_t st = probeControllerKeyState(_node_prefs->probe_controller_pubkey,
                                                 sizeof(_node_prefs->probe_controller_pubkey));
      const bool authed = (st == PROBE_CTRL_ISSUED);
      _display->setColor(authed ? UIColor::corp_blue : UIColor::warning_txt);
      _display->setCursor(TEXT_X, ty);
      _display->print(authed ? "Echo Auth: Yes" : "Echo Auth: No");
      _display->setColor(UIColor::primary_txt);
      ty += 10;
    }

    // 5. LoRa transmits per hour -- the airtime proxy, not MQTT publishes. "--" until
    // there is a wide enough sample window to divide by.
    {
      uint32_t rate;
      if (txPerHour(&rate)) snprintf(line, sizeof(line), "TX/hr: %lu", (unsigned long)rate);
      else                  snprintf(line, sizeof(line), "TX/hr: --");
      _display->setCursor(TEXT_X, ty); _display->print(line);
    }
#else
    // Stock (non-Sonar) build keeps the upstream screen: this fork's branding has no
    // business on an image that is not ours.
    _display->setCursor(0, 0);
    _display->setTextSize(1);
    _display->setColor(UIColor::primary_txt);
    _display->print(_node_prefs->node_name);

    _display->setCursor(0, 20);
    sprintf(tmp, "FREQ: %06.3f SF%d", _node_prefs->freq, _node_prefs->sf);
    _display->print(tmp);

    _display->setCursor(0, 30);
    sprintf(tmp, "BW: %03.2f CR: %d", _node_prefs->bw, _node_prefs->cr);
    _display->print(tmp);
#endif
  }
}

void UITask::loop() {
#if defined(WITH_MQTT_BRIDGE)
  sampleTxCounter();   // independent of the screen being on
#endif
#if defined(PIN_USER_BTN) && defined(DISPLAY_CLASS)
  int ev = user_btn.check();
  if (ev == BUTTON_EVENT_CLICK) {
    if (_display->isOn()) {
      // TODO: any action ?
    } else {
      _display->turnOn();
    }
    _auto_off = millis() + AUTO_OFF_MILLIS;   // extend auto-off timer
  } else if (ev == BUTTON_EVENT_LONG_PRESS) {
      _display->turnOn();
      Serial.println("Powering Off");
      _powering_off_at = millis() + POWEROFF_DELAY; 
  }
#endif

#ifdef WITH_WEBCONFIG
  // While the setup portal is up there's no user button to wake the screen
  // reliably - keep it on so the join instructions stay visible.
  if (WebConfigServer::getSetupInfo(NULL, 0, NULL, 0)) {
    if (!_display->isOn()) _display->turnOn();
    _auto_off = millis() + AUTO_OFF_MILLIS;
  }
#endif

  if (_display->isOn()) {
    if (millis() >= _next_refresh) {
      _display->startFrame();
      renderCurrScreen();
      _display->endFrame();

      _next_refresh = millis() + 1000;   // refresh every second
    }
    if (millis() > _auto_off) {
      _display->turnOff();
    }
  }

  if (_powering_off_at > 0) { // power off timer armed
#ifdef LED_PIN
    digitalWrite(LED_PIN, LED_STATE_ON); // switch on the led until poweroff
#endif
    if (millis() > _powering_off_at) {
      _board->powerOff();  // should not return
    }
  }
}
