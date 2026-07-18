# Stability, Testability, and Upstream-Merge Handoff

## Purpose

This document is the plan of record for refining the fork-owned WebConfig and
MQTT observer code after the initial policy extraction and host-test work. The
goal is to improve runtime stability, long-uptime confidence, and serviceability
without broad rewrites of upstream-heavy files or creating unnecessary merge
conflicts.

The order is deliberate: cheap CI and persistence guardrails land first, then
tests and ownership boundaries needed to make lifecycle work safe, and only
then the cooperative-shutdown refactor. Hardware soak testing validates the
result; it is not the first line of defense for the riskiest change.

## Current Baseline

The current branch has:

- Native tests for MQTT presets, validation, topic templates/routing,
  connection policy, packet-queue policy, payload construction, WebConfig keys,
  and upstream `Utils::toHex` behavior.
- ArduinoJson pinned to 7.4.3 in the native and firmware environments.
- Representative MQTT firmware builds passing for a constrained non-PSRAM
  Heltec V3 and a PSRAM-equipped T-Beam S3 Supreme.
- WebConfig request/result correlation, failed-batch reboot gating, and a
  process-lifetime HTTP listener that avoids deleting an object still referenced
  by an asynchronous request.
- Pure MQTT policy helpers that reduce decision duplication while leaving the
  production bridge as the integration point.

This is a useful unit-test foundation, but it does not yet validate the MQTT
task/client lifecycle, cross-core state ownership, preference-file migrations,
or long-running heap behavior.

## Constraints

1. MQTT preference-file layouts are fleet-critical. Unknown newer formats must
   not be overwritten, and every supported old layout must remain recoverable.
2. Upstream MeshCore changes are merged regularly. Prefer additive fork-owned
   helpers and small adapters over reorganizing upstream-heavy files.
3. The non-PSRAM profile is the memory-pressure baseline; the PSRAM profile is
   a separate allocation/lifecycle path and must also be tested.
4. Risky lifecycle changes require fast deterministic tests before hardware
   soak testing.
5. Preserve observable behavior unless a behavior change is explicitly named,
   reviewed, and tested.

## Sequenced Work

### Phase 0: Record the pre-change lifecycle characterization

Capture current behavior before changing shutdown mechanics. This provides a
reference for the lifecycle fakes and lets the later state-machine refactor
prove equivalence rather than relying on memory or a multi-hour soak.

Characterize at least:

- Normal `begin() -> connect -> end()` ordering.
- `end()` while disconnected, connecting, connected, publishing, retrying, and
  applying a slot reconfiguration.
- Which callbacks can arrive during and after `end()`.
- Queue disposition and connection/status counters across stop and restart.
- Heap, largest allocatable internal block, task stack high-water mark, and
  client/task counts before start, after start, after stop, and after restart.
- Partial initialization failures: queue allocation, task creation, client
  allocation, and PSRAM-buffer allocation.

Use instrumented hardware logging where necessary, but encode every behavior
that can be represented deterministically into the lifecycle fake tests in
Phase 4. Store representative logs as CI or test artifacts rather than enabling
permanent high-volume production logging.

### Phase 1: Put MQTT/WebConfig firmware smoke builds in PR CI

The regular PR build matrix does not currently compile an MQTT observer target.
Add two required smoke builds for changes touching firmware, variants,
PlatformIO configuration, MQTT/WebConfig helpers, or their tests:

- `Heltec_v3_repeater_observer_mqtt` for the constrained non-PSRAM path.
- `T_Beam_S3_Supreme_SX1262_repeater_observer_mqtt` for the PSRAM path.

Keep the native suite required. Add ASan/UBSan to a separate native job if the
PlatformIO native toolchain supports it reliably. Record static RAM and flash
usage and fail only on reviewed limits with enough headroom to avoid noisy
one-byte regressions.

Acceptance criteria:

- Pull requests cannot merge when native tests or either representative MQTT
  build fails.
- The build log shows ArduinoJson 7.4.3 for both firmware profiles.
- CI checks that every ArduinoJson declaration remains pinned to 7.4.3.
- Build-size output is retained as an artifact or job summary.

### Phase 2: Fix PSRAM restart resource symmetry

PSRAM-backed raw-data and JSON buffers are allocated in the bridge constructor,
freed by `end()`, and not reallocated by a later `begin()` on the same bridge
object. After a restart, raw-data caching remains unavailable and JSON
publication uses task-stack fallback buffers.

Extract symmetric runtime-resource operations, for example:

- `allocateRuntimeBuffers()` called by `begin()` or a shared initialization
  path.
- `releaseRuntimeBuffers()` called by `end()` and initialization rollback.

The operations must be idempotent, handle partial allocation, and preserve the
existing graceful fallback when PSRAM allocation fails. Avoid changing client
or task shutdown behavior in this phase.

Tests and validation:

- Allocation success, partial failure, repeated allocation, and repeated
  release using a narrow allocator fake.
- Multiple `begin()/end()` cycles do not lose the raw-data buffer or permanently
  move JSON serialization onto the task stack.
- Initialization failure releases only resources owned by that attempt.
- Representative PSRAM and non-PSRAM firmware builds pass.
- A short hardware restart loop shows stable free heap and largest free block.

### Phase 3: Add binary MQTT preference migration fixtures

Build deterministic tests around the versioned `/mqtt_prefs` loader before
upstream merges change `CommonCLI`, filesystem behavior, or preference structs.
Use checked-in, non-secret binary fixtures or byte arrays representing each
deployed layout.

Required cases:

- Pre-slot layout.
- Three-slot layout.
- Legacy headerless six-slot layout.
- Shorter version-1 payload with newer fields defaulted.
- Current version round trip.
- Truncated header and truncated payload.
- Invalid magic and implausible payload length.
- Unsupported newer version: run with safe defaults and preserve the original
  file without overwriting it.
- Migration failure or interrupted save leaves a recoverable source file.
- Existing credentials, slot ordering, and publish flags survive migration.

Prefer extracting a fork-owned serializer/decoder seam over host-compiling all
of `CommonCLI`. Keep the production adapter small and retain the frozen-layout
`static_assert`s.

Acceptance criteria:

- All known deployed layouts have a fixture and field-by-field expected result.
- Corrupt input cannot cause an out-of-bounds read or silent overwrite.
- A future `MQTTPrefs` layout change fails tests until its migration and fixture
  are added deliberately.

### Phase 4: Establish ownership and teardown test seams

This phase is the safety net for cooperative shutdown. It must land before the
shutdown state machine.

#### Ownership model

Document one owner for each mutable runtime domain:

- MQTT task: clients, slot connection state, NTP client operations, publish
  counters, and the packet drain path.
- Loop task: CLI execution, preference persistence, WebConfig batch draining,
  and bridge lifecycle requests.
- Producer/radio context: packet staging before queue handoff.
- Async TCP context: request parsing and immutable response handoff only.

Replace cross-core `volatile` handshakes with an appropriate primitive:

- Task notifications or a command queue for one-way lifecycle/reconfigure/NTP
  requests.
- Atomics only for truly independent scalar state.
- Immutable published snapshots for WebConfig, CLI diagnostics, and alerting.
- A mutex only where ownership transfer or snapshot publication cannot express
  the operation cleanly.

In particular, loop/WebConfig code must not directly inspect mutable MQTT slot
objects or client counters. The MQTT task should publish a plain-data status
snapshot.

#### Narrow lifecycle fakes

Introduce interfaces or callbacks for only the dependencies needed to drive the
lifecycle deterministically:

- Clock/timer.
- Task start, stop request, acknowledgment, and timeout.
- MQTT client connect/disconnect and delayed callbacks.
- Queue depth/pop/requeue behavior.
- Runtime allocator and heap measurements.
- OTA coordinator/barrier.

Required teardown-focused tests:

- Stop while connecting, connected, publishing, retrying, renewing a token,
  running NTP, and applying a slot change.
- Callback delivered before stop, during stop, after disconnect, and after the
  stop acknowledgment.
- Duplicate stop, stop before full initialization, and restart after stop.
- Timeout/fallback behavior when the MQTT task or client does not acknowledge.
- No client, queue, buffer, or task access after its owner releases it.
- Current queue and diagnostic behavior is preserved unless a change is
  explicitly approved.

### OTA Teardown Barrier: release-critical scenario

Treat OTA teardown as a first-class test target throughout Phases 0, 2, 4, 5,
and 7. It is not merely another restart case.

The required invariant is: firmware erase/write must not begin until MQTT
shutdown has reached a safe acknowledgment point, and the bridge must not be
restarted while flash writing is active.

Required scenarios:

- OTA requested while MQTT is connecting, publishing, draining retries, or
  handling a callback.
- MQTT stop succeeds and OTA begins only after the teardown barrier.
- MQTT stop times out: OTA aborts safely rather than writing under uncertain
  ownership.
- OTA preflight or download aborts before flashing: the bridge restarts once and
  returns to the prior configured behavior.
- Successful OTA: no bridge restart is attempted before the device reboots.
- Power loss/reset at the platform-supported OTA boundaries retains a bootable
  partition; this portion requires hardware/platform validation.
- Repeated failed OTA attempts do not leak heap, duplicate WiFi callbacks, or
  leave the bridge permanently stopped.

Retain the prior teardown/heap-panic reproduction as a regression artifact if
available. OTA-related lifecycle tests are release gates for any future change
to bridge teardown, OTA sequencing, MQTT client lifetime, or task ownership.

### Phase 5: Implement cooperative MQTT shutdown

With Phase 0 behavior recorded and Phase 4 tests in place, replace direct task
deletion with an explicit lifecycle such as:

`Stopped -> Starting -> Running -> StopRequested -> Stopping -> Stopped`

The exact representation can differ, but it must provide:

- Idempotent start and stop requests.
- A stop request delivered through the established ownership channel.
- Cessation of new connects, publishes, retries, and reconfigurations.
- Ordered client/service shutdown on the MQTT task.
- A completion acknowledgment before the loop task releases queues, buffers, or
  other shared resources.
- A bounded timeout with clear diagnostics and a deliberately reviewed fallback.
- Safe restart after a completed stop.
- An OTA barrier that consumes the same completion acknowledgment.

Do not combine this phase with queue-loop deduplication, broad bridge cleanup,
or unrelated feature changes.

Acceptance criteria:

- All Phase 4 lifecycle tests pass, including delayed/stale callbacks.
- Characterized behavior from Phase 0 is preserved or differences are explicitly
  documented and approved.
- OTA teardown-barrier tests pass.
- Repeated hardware start/stop cycles show no downward heap or largest-block
  trend and no task/client-count growth.

### Phase 6: Expand request, queue, connection, and publication integration tests

After lifecycle ownership is stable, broaden deterministic integration coverage:

- WebConfig POST/result/reboot/stop behavior, including lost responses,
  duplicate request IDs, concurrent clients, partial command failure, and stop
  with an active handler.
- MQTT queue behavior for FreeRTOS and circular-buffer adapters: overflow,
  delayed retry, requeue failure, stale flush, queue ordering, and
  `millis()` rollover.
- Packet succeeds/raw fails and raw succeeds/packet fails.
- Connection backoff, stable reset, breaker probe, WiFi recovery, token renewal,
  and slot reconfiguration callback ordering.
- Topic and payload contracts at the bridge boundary, so enum/cast/adaptation
  mistakes are covered in addition to the pure helper tests.

Once both queue backends are covered by the same behavioral contract, consider
extracting a shared `processQueuedPacket()` that returns an outcome while each
backend retains pop/requeue/dequeue ownership. Do not make queue deduplication a
prerequisite for the stability work.

### Phase 7: Establish uptime, memory, and fault-injection gates

Use hardware soak tests to validate the already-tested design, not to discover
basic lifecycle errors for the first time.

Run at least one constrained non-PSRAM board and one PSRAM board through:

- Stable broker operation.
- Broker unavailable, rejecting authentication, and flapping.
- WiFi loss/recovery and credential changes.
- TLS handshake failures and repeated reconnect backoff.
- Queue saturation and slow broker behavior.
- Repeated slot reconfiguration and full bridge stop/start.
- WebConfig start/save/stop cycles.
- JWT renewal and NTP failure/recovery.
- OTA success, preflight abort, download failure, teardown timeout, and resume.
- At least one test crossing the 32-bit `millis()` rollover boundary, accelerated
  where hardware time injection is available.

Record and threshold:

- Minimum free internal heap.
- Largest free internal block.
- MQTT task stack high-water mark.
- PSRAM free/largest block where available.
- Queue and outbox high-water marks.
- Connect/disconnect/retry/publish counters.
- Watchdog and reset reason.
- Task/client counts across restart cycles.

Recommended gates are a 72-hour fault-injection run followed by a seven-day
stable run. Store machine-readable time series and a concise summary artifact.
Avoid enabling high-volume diagnostic logging in production builds.

## Continuous Upstream-Merge Discipline

Apply these practices throughout every phase:

- Keep fork-owned logic in additive helper files and keep adapters in
  upstream-heavy files small.
- Avoid drive-by formatting, renames, and unrelated cleanup in
  `MQTTBridge.cpp`, `CommonCLI`, and the role-specific `MyMesh` files.
- Use single-purpose commits with messages that describe their full scope.
- Merge upstream frequently enough that conflicts remain attributable.
- Before each upstream merge, record the native-test, representative-build,
  firmware-size, and persistence-fixture baseline.
- After the merge, run native tests, both MQTT smoke builds, preference fixtures,
  and the relevant lifecycle/OTA tests before resolving the merge as complete.
- Review semantic behavior at adapters even when Git reports no textual
  conflict; upstream signature, lifetime, and task-context changes can invalidate
  fork assumptions silently.
- Reuse resolutions only after revalidating them against the new upstream code.
- Extract repeater/room-server WebConfig ownership into a shared fork helper when
  that integration next requires material change; do not perform a standalone
  broad move solely for aesthetics.

## Explicitly Deferred Debt

These items are recognized but are not prerequisites for the sequenced
stability work:

- Shared packet-drain processing between FreeRTOS and circular-buffer backends.
- Repeater/room-server WebConfig integration duplication.
- Moving the WebConfig HTML generator out of the common ESP32 build path.
- The secret-placeholder edge case for a credential exactly equal to the UI
  sentinel.
- Secure setup-AP authentication beyond the currently documented open/optional
  PSK threat model.

Revisit an item when its code is already being changed, when operational data
raises its priority, or when tests make the refactor substantially safer.

## Completion Definition

This roadmap is complete when:

- PR CI protects native logic and both representative firmware memory paths.
- Every deployed MQTT preference layout has a passing migration fixture.
- Runtime resources survive repeated start/stop cycles symmetrically.
- Cross-core ownership is explicit and diagnostics consume immutable snapshots.
- Cooperative shutdown passes deterministic lifecycle and OTA-barrier tests.
- Hardware fault-injection and stable soaks meet reviewed memory, stack, task,
  and reliability thresholds.
- Upstream merges use the same automated gate and do not require broad rewrites
  of fork-owned behavior.
