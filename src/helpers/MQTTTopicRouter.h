#pragma once

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "MQTTObserverValidation.h"
#include "MQTTTopicTemplate.h"

// Pure MQTT publication-topic policy shared by MQTTBridge and the native tests.
// Keep these values aligned with MQTTBridge::MQTTMessageType; the bridge passes
// its enum value as an int so this helper stays independent of ESP/Arduino types.
enum MQTTPublicationType {
  MQTT_PUBLICATION_STATUS = 0,
  MQTT_PUBLICATION_PACKETS = 1,
  MQTT_PUBLICATION_RAW = 2,
  MQTT_PUBLICATION_NEIGHBORS = 3,
};

enum MQTTTopicRouteStyle {
  MQTT_ROUTE_MESHCORE,
  MQTT_ROUTE_MESHRANK,
  MQTT_ROUTE_CUSTOM,
};

static inline bool mqttTopicSlotIndexValid(int index, size_t slot_count) {
  return index >= 0 && (size_t)index < slot_count;
}

static inline const char* mqttPublicationTypeName(int type) {
  switch (type) {
    case MQTT_PUBLICATION_STATUS: return "status";
    case MQTT_PUBLICATION_PACKETS: return "packets";
    case MQTT_PUBLICATION_RAW: return "raw";
    case MQTT_PUBLICATION_NEIGHBORS: return "neighbors";
    default: return NULL;
  }
}

static inline bool mqttWriteTopic(char* buf, size_t buf_size, const char* format,
                                  const char* first, const char* second,
                                  const char* third) {
  if (!buf || buf_size == 0 || !format || !first || !second || !third) return false;
  buf[0] = '\0';
  int written = snprintf(buf, buf_size, format, first, second, third);
  return written > 0 && (size_t)written < buf_size;
}

// Build the complete topic for one publication. MeshRank takes status, packets,
// and neighbors under meshrank/uplink/{token}/{device}/, using the same type
// suffixes as the MeshCore layout, and requires a per-slot token rather than an
// IATA. MeshCore routes require a configured IATA and device id. Custom
// templates may omit either placeholder, so their individual values are allowed
// to be empty.
// LEGACY private admin channel for the Echo Observer-Probe:
//   meshcore/{IATA}/{PUBKEY}/serial/commands   (Echo -> Observer)
//   meshcore/{IATA}/{PUBKEY}/serial/responses  (Observer -> Echo)
// Four segments, so it deliberately does not go through mqttWriteTopic's
// three-placeholder format.
//
// Superseded by mqttBuildProbeTopic() below, but kept registered alongside it
// through the transition so a BROKER rollback still has a working path — see the
// comment there.
//
// NOTE: this builder does not, and never did, check the route style; a custom
// template or a MeshRank slot reaches it just the same. The only gates are the
// caller's probe_enable / probe_control_slot checks.
static inline bool mqttBuildSerialTopic(const char* iata, const char* device,
                                        bool commands, char* buf, size_t buf_size) {
  if (!buf || buf_size == 0) return false;
  buf[0] = '\0';
  if (!mqttIataValid(iata) || strcmp(iata, "XXX") == 0 || !device || device[0] == '\0') {
    return false;
  }
  int w = snprintf(buf, buf_size, "meshcore/%s/%s/serial/%s",
                   iata, device, commands ? "commands" : "responses");
  if (w <= 0 || (size_t)w >= buf_size) {
    buf[0] = '\0';
    return false;
  }
  return true;
}

// Current private control plane for the Echo Observer-Probe:
//   probe/v1/{PUBKEY}/cmd   (Echo -> Observer)
//   probe/v1/{PUBKEY}/rsp   (Observer -> Echo)
//
// Outside the meshcore/ tree, which public subscribers read. 77 chars, well
// inside the 128-byte caller buffers (the MQTT library truncates SILENTLY at
// 127, so headroom matters more than it looks).
//
// There is deliberately NO IATA segment. IATA is node-mutable — the broker even
// counts changes as abuse — so keying the mailbox on it would let a node
// relocate its own command topic and have Echo's commands vanish with no error
// at either end. The pubkey is the only segment carrying authorization weight,
// and the broker binds it to the authenticated identity.
//
// Consequence worth stating plainly: the legacy builder above refuses to build
// when IATA is unset or "XXX", so `set mqtt.iata XXX` used to take a node off
// the tasking channel. That side effect does NOT carry over here. The explicit
// controls are `probe off` and the probe.topic switch — see MQTTBridge.
static inline bool mqttBuildProbeTopic(const char* device, bool commands,
                                       char* buf, size_t buf_size) {
  if (!buf || buf_size == 0) return false;
  buf[0] = '\0';
  // Keep the device half of the legacy guard: without it an unnamed device
  // yields "probe/v1//cmd", an empty path segment that is a perfectly legal
  // MQTT topic and would subscribe the node to a channel nobody publishes to.
  if (!device || device[0] == '\0') return false;
  int w = snprintf(buf, buf_size, "probe/v1/%s/%s", device, commands ? "cmd" : "rsp");
  if (w <= 0 || (size_t)w >= buf_size) {
    buf[0] = '\0';
    return false;
  }
  return true;
}

// The relay channel: frames the controller built for THIS node to key onto the air
// verbatim.
//
// A separate tree from probe/v1 deliberately, at both ends. The broker gates relay with
// its own default-off switch and its own ACL, so an operator can let a controller task a
// node without also letting it transmit through that node's radio. Keeping the trees
// apart is what makes that distinction reach the wire: if relay frames rode probe/v1 the
// broker could not tell the two apart and the separate gate would be decorative.
//
// No rsp direction. A relayed frame's answer is an ordinary mesh reply that this node
// already uplinks as an observer, so a relay response topic would duplicate a channel
// that exists.
static inline bool mqttBuildRelayTopic(const char* device, char* buf, size_t buf_size) {
  if (!buf || buf_size == 0) return false;
  buf[0] = '\0';
  if (!device || device[0] == '\0') return false;   // see the empty-segment guard above
  int w = snprintf(buf, buf_size, "relay/v1/%s/tx", device);
  if (w <= 0 || (size_t)w >= buf_size) {
    buf[0] = '\0';
    return false;
  }
  return true;
}

static inline bool mqttBuildPublicationTopic(MQTTTopicRouteStyle style, int type,
                                             const char* custom_template,
                                             const char* iata, const char* device,
                                             const char* token,
                                             char* buf, size_t buf_size) {
  if (!buf || buf_size == 0) return false;
  buf[0] = '\0';

  const char* type_name = mqttPublicationTypeName(type);
  if (!type_name) return false;

  switch (style) {
    case MQTT_ROUTE_MESHCORE:
      if (!mqttIataValid(iata) || strcmp(iata, "XXX") == 0 || !device || device[0] == '\0') {
        return false;
      }
      return mqttWriteTopic(buf, buf_size, "meshcore/%s/%s/%s", iata, device, type_name);

    case MQTT_ROUTE_MESHRANK:
      // Raw is deliberately withheld: highest-volume topic, and the broker does
      // not consume it. observer-firmware still sends it — keep this on merge.
      if (type == MQTT_PUBLICATION_RAW || !token || token[0] == '\0' ||
          !device || device[0] == '\0') {
        return false;
      }
      return mqttWriteTopic(buf, buf_size, "meshrank/uplink/%s/%s/%s",
                            token, device, type_name);

    case MQTT_ROUTE_CUSTOM:
      return mqttSubstituteTopic(custom_template, iata, device, token, type_name,
                                 buf, buf_size);

    default:
      return false;
  }
}

