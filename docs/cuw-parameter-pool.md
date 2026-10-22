# Native CUW Control parameter pool

`ControlParameterPool2026.issue(engine, controller, catalog_sources)` models the
constructor-created `CParameter` array owned by one loaded Control module
runtime. Its capacity comes from the engine's configured
`CommonDefinitions2026.num_cpu_maxnum`; input catalog bytes are copied into an
immutable, bounded snapshot. The pool starts with real constructor-empty
parameters.

`load_steps_for` follows the fixed native caller plans for `get_cid`, `prepare`,
`write`, and `change_gateway`. It reads its source-issued CONTROL context itself,
retains each successful matrix/row mutation immediately, and yields after each
selected slot so the caller can run its interleaved preflight. Missing files,
missing key columns, and failed `SetKeys` preserve the native distinctions and
sanitized `TCUWControlCommPhase.dll:RVA...` failure locations.

Slots and pools are registry-authenticated. Slot parameter reads return a
defensive `NativeParameter2026` copy; `selected_binding` delegates to the narrow
shared issuer in `programming_2026_common.py` and never selects a new row from the
outer engine FILE or CPU. `close()` models source detach and is idempotent.

This is a static source model. It does not execute OEM code or establish vehicle
or physical programming support.
