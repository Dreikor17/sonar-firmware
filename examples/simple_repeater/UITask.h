#pragma once

#include <helpers/ui/DisplayDriver.h>
#include <helpers/CommonCLI.h>

// Reports whether the MQTT bridge currently has a live connection, for the home
// screen. A plain function pointer rather than a MyMesh reference on purpose: this
// header is shared by every repeater variant, most of which have no bridge at all,
// and the UI must not start depending on the mesh class to draw a status line.
typedef bool (*UIMqttStatusFn)();

class UITask {
  mesh::MainBoard* _board;
  DisplayDriver* _display;
  unsigned long _next_read, _next_refresh, _auto_off;
  int _prevBtnState;
  NodePrefs* _node_prefs;
  char _version_info[32];
  unsigned long _powering_off_at = 0;
  unsigned long _started_at = 0;
  UIMqttStatusFn _mqtt_status = NULL;

  void renderCurrScreen();
public:
  UITask(mesh::MainBoard& board, DisplayDriver& display) : _board(&board), _display(&display) { _next_read = _next_refresh = 0; }
  void begin(NodePrefs* node_prefs, const char* build_date, const char* firmware_version);

  // Optional: unset leaves the home screen reporting MQTT as down, which is the
  // honest answer for a build that has no bridge to ask.
  void setMqttStatusFn(UIMqttStatusFn fn) { _mqtt_status = fn; }

  void loop();
};