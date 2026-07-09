# Restoring accidentally-reverted upstream features

## Background

On 2026-03-20, commit `22eb9b87` — *Revert "Merge remote-tracking branch 'origin/dev' into mqtt-bridge-implementation"* — reverted an entire upstream merge to escape a bad merge state, deleting 860 lines across 66 files. That was not intentional feature removal; it wholesale dropped a batch of upstream progress. When upstream was later re-merged, some collateral came back (MicroNMEA `claim()/release()`, the GAT562 board) but several upstream features were never reconciled and remained missing.

This branch restores them. They are **pure upstream code the fork accidentally dropped**, so restoring re-aligns the fork with upstream and *reduces* the future merge-conflict surface rather than adding to it.

## Phase 1 — duty-cycle enforcement (done on this branch)

Restored the token-bucket duty-cycle enforcement and its cluster:

- `src/Dispatcher.{h,cpp}` — restored upstream's `updateTxBudget()`, `tx_budget_ms`,
  `duty_cycle_window_ms`, `getRemainingTxBudget()`, `getDutyCycleWindowMs()`, and the
  windowed `checkSend()`/`loop()` budget logic. The fork's MQTT **radio watchdog** was
  re-applied on top as pure additions (behind `#ifdef WITH_MQTT_BRIDGE`).
- `src/helpers/StaticPoolPacketManager.{h,cpp}` — restored `getOutboundTotal()` and the
  `0xFFFFFFFF` count-all sentinel in `countBefore()`.
- `src/helpers/StatsFormatHelper.h` — restored the `getOutboundTotal()` call; kept the
  fork's `formatRadioDiag` template.

Net effect: these files now diverge from upstream by **watchdog additions only (0 deletions)**
instead of rewriting upstream's TX logic.

### Why this is safe (no reinterpretation of stored settings)

`getAirtimeBudgetFactor()` changed *meaning* between fork and upstream, but the resulting
duty cycle is the **same formula**:
- Fork: `next_tx = t · factor` → duty ≈ `1/(1+factor)`
- Upstream: `duty = 1/(1+factor)` enforced over a rolling window

So a device's stored `airtime_factor` (a `NodePrefs` field, unchanged) keeps its meaning.
The only behavioral difference is upstream enforces it over a 1-hour window (allowing
short bursts) instead of rigid per-packet spacing — a strict improvement, and the
mechanism that keeps EU 868 MHz nodes under the legally-mandated duty cycle.

### Must be validated on-device before merge

This touches core TX timing. Confirm on hardware:
- Normal traffic still flows (repeater forwards, observer uplinks).
- Sustained TX is throttled to the configured duty cycle (watch `get` airtime/queue stats;
  verify `next_tx_time` spacing under load).
- The observer radio watchdog still recovers a stuck radio (`radio_watchdog_minutes`).

## Phase 2 — CAD and FEM RX gain (NOT done; needs care + device testing)

Still missing at HEAD, also dropped by `22eb9b87`, still present upstream:

- **`cad_enabled`** — hardware Channel Activity Detection (listen-before-talk) before TX.
  The `Dispatcher`/`Radio` interface (`setCADEnabled`/`getCADEnabled`) is restored by
  Phase 1, so CAD currently stays **off by default** (unchanged behavior). To make it
  configurable again, restore:
  - `NodePrefs.cad_enabled` field, its CLI get/set, and its persistence in
    `CommonCLI.cpp` (`loadPrefsInt`/`savePrefs`). **Offset care:** this branch's
    `/com_prefs` layout is carefully managed — add `cad_enabled` following the same
    append-and-size-guard pattern used for `rx_boosted_gain`/`flood_max_*`, and add a
    host-side round-trip test (see `scratchpad/migtest`).
  - The `MyMesh::getCADEnabled()` override returning `_prefs.cad_enabled`.
  - `RadioLibWrappers::setCADEnabled()` override so the hardware CAD is actually driven
    (the fork's wrapper currently doesn't override it).
- **`radio_fem_rxgain`** — LoRa front-end-module RX gain. Restore `NodePrefs.radio_fem_rxgain`
  + CLI + persistence (same offset care), plus the per-board FEM wiring reverted across
  ~20 `variants/*/target.cpp` and the `heltec_tracker_v2/LoRaFEMControl.{cpp,h}` files.
  This is board-specific and only affects FEM-equipped hardware.

Phase 2 is lower urgency than duty-cycle enforcement (CAD/FEM are capability gaps, not a
compliance regression) and is best done as its own change with per-board hardware testing.
