#pragma once

#include <helpers/ui/DisplayDriver.h>
#include <helpers/CommonCLI.h>

class UITask {
  mesh::MainBoard* _board;
  DisplayDriver* _display;
  unsigned long _next_read, _next_refresh, _auto_off;
  int _prevBtnState;
  NodePrefs* _node_prefs;
  char _version_info[32];
  unsigned long _powering_off_at = 0;
  unsigned long _started_at = 0;

  // TX/hr is a RATE, and the radio only offers a counter that climbs from boot. Sampling
  // that counter into a ring and differencing the ends is what turns one into the other.
  // 13 samples at 5-minute spacing spans a full hour; the rate is scaled by the real
  // elapsed span, so it is honest during the first hour instead of reading low.
  static const int TX_SAMPLES = 13;
  static const unsigned long TX_SAMPLE_MS = 5UL * 60UL * 1000UL;
  uint32_t _tx_ring[TX_SAMPLES] = {0};
  unsigned long _tx_ring_at[TX_SAMPLES] = {0};
  int _tx_head = 0;             // newest slot
  int _tx_filled = 0;           // how many slots hold a real sample
  unsigned long _tx_next_sample = 0;
  void sampleTxCounter();
  bool txPerHour(uint32_t* out) const;

  void renderCurrScreen();
public:
  UITask(mesh::MainBoard& board, DisplayDriver& display) : _board(&board), _display(&display) { _next_read = _next_refresh = 0; }
  void begin(NodePrefs* node_prefs, const char* build_date, const char* firmware_version);

  void loop();
};