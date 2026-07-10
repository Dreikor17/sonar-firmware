#pragma once

#include <MeshCore.h>
#include <helpers/StaticPoolPacketManager.h>

// Fork-owned (not upstream-tracked). Observer builds capture every received packet
// to MQTT, but RX processing needs a free pool packet first — Dispatcher::checkRecv()
// discards the received bytes before logRx() when allocNew() fails. Under duty-cycle
// throttling the outbound queue can park the entire pool waiting on TX budget, which
// starves RX allocation and silently caps MQTT capture at the TX rate (each completed
// TX frees exactly one packet for exactly one more RX).
//
// This manager sheds *retransmissions* instead: once the free pool drops below the
// reserve, outbound packets are refused (freed straight back to the pool) so RX
// allocation — and therefore capture — continues at full rate. The node was already
// dropping traffic in that state; this chooses to drop repeats it has no TX budget
// for anyway, rather than capture.
class RxReservePacketManager : public StaticPoolPacketManager {
  int _rx_reserve;
public:
  RxReservePacketManager(int pool_size, int rx_reserve)
    : StaticPoolPacketManager(pool_size), _rx_reserve(rx_reserve) {}

  void queueOutbound(mesh::Packet* packet, uint8_t priority, uint32_t scheduled_for) override {
    if (getFreeCount() < _rx_reserve) {
      MESH_DEBUG_PRINTLN("RxReservePacketManager: pool below RX reserve, shedding outbound");
      free(packet);
      return;
    }
    StaticPoolPacketManager::queueOutbound(packet, priority, scheduled_for);
  }
};

// The packet manager for an app build: observer builds reserve a quarter of the pool
// for RX so MQTT capture survives duty-cycle throttling; non-observer builds keep the
// upstream pool behavior unchanged.
inline mesh::PacketManager* createObserverPacketManager(int pool_size) {
#ifdef WITH_MQTT_BRIDGE
  return new RxReservePacketManager(pool_size, pool_size / 4);
#else
  return new StaticPoolPacketManager(pool_size);
#endif
}
