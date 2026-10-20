# Hardware validation

**Current status: `PHYSICAL_UNCONFIRMED`.** Synthetic sessions, mocked USB transfers, static format recovery and a rendered GUI are software evidence. No physical adapter/vehicle result is established by them.

## Record evidence separately

A useful result states the commit, Linux/kernel versions, adapter model and firmware, observed USB descriptors, test setup, exact operation, expected/actual response, timestamps and cleanup outcome. Keep adapter serial numbers and VINs private; publish redacted traces or synthetic equivalents. Identify what was actually observed and what remains an inference.

An adapter label, chipset assumption or matching USB ID does not demonstrate Toyota compatibility. Record the observed device instead of assuming it behaves like another branded variant.

## Validation sequence

1. **Offline baseline.** Run all core tests, synthetic replay and demo GUI smoke from a clean checkout. Confirm input rejection, cancellation and error cleanup before attaching hardware.
2. **Adapter only, no vehicle.** Inspect USB descriptors without changing device permissions automatically. Establish the actual interfaces/endpoints. Exercise bounded open/identity/version/close behavior, then unplug/replug and repeat. Check that stale results are rejected and interfaces are released on errors and cancellation. Do not load firmware or reset the device as part of discovery.
3. **Bench communication.** Use a controlled, correctly powered bench setup and a known reference peer before a vehicle. Validate channel configuration, filters, framing, timing, fragmented responses, timeouts, cancellation and disconnect recovery. Compare captured traffic with the expected request bytes. A successful version query alone does not complete this stage.
4. **Stationary vehicle, read-only scope.** Agree the exact vehicle, adapter, power arrangement and allowed requests before testing. Begin with a single explicitly supported identification/read operation. Confirm ECU addressing, response correlation and decoded values against an independent reference. Preserve failures as well as successes. No road testing or unattended operation.
5. **Expand coverage deliberately.** Validate one ECU/protocol/operation at a time, including unsupported requests, negative responses, session loss and stop behavior. A result applies to the tested combination, not all Toyota/Lexus vehicles or all adapters.

Writes, active tests, coding, customization, DTC clearing and ECU programming are outside this sequence. They need a separate reviewed implementation and validation plan, explicit authorization and recovery provisions. Do not infer their safety from read-only success.

## Completion criteria

A physical claim requires a reproducible result for the exact operation plus the associated failure/cleanup checks. Maintain distinct labels for synthetic, bench and vehicle evidence. Keep `PHYSICAL_UNCONFIRMED` on untested paths even when adjacent paths pass.

See [JLR transport](jlr-native.md), [channel formats](jlr-channels.md), [offline replay](offline-diagnostics.md) and the [feature matrix](full-port.md). Report sensitive findings as described in [Security](../SECURITY.md).
