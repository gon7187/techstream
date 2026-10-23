# Enhanced native readiness

`ReadinessSession(profile, exchange, ecu, pid_lengths, ...)` reconstructs the
original `GetReadinessCode_DT.Execute` path. `readiness()` selects the chosen
Freeze84 records with `record[78] & 0x20`; `data_list(signal_keys)` evaluates an
explicit list of the same selected definitions, including original advertised
PIDs above `0x87`. Both use the selected original PhyData24 conversion. This is
separate from standard OBD Mode 01 readiness bits.

`pid_lengths` and optional `did_lengths` are caller-observed native
`GetEnableIdList` lengths. Local definitions do not establish ECU support.
`native_support` is returned independently of the value: the native routine
still requests the signal when the support flag is false. Values come only from
the injected exchange; no adapter is opened.

The original implementation requires exactly one selected function `0x6B`
frame, patches request byte 1 with Freeze byte `0x4F`, validates the response SID,
and removes the **full request length** before extracting signal bits. Replies
are cached per patched request for one operation. Wrong-length signal status
`0xA0040202` omits that signal; an empty result returns `0x90040501`. Other errors
propagate. Cancellation, total exchange count and wall-clock deadline apply to
support requests and value requests, including an exchange that raises.

Reports retain the original signal key/name, PID, independent support flag,
neutral native DWORD at Freeze `+0x34`, selected-frame provenance, original unit
key and resolved default Unit12 label (or explicit unresolved unit). No completion
labels are inferred from numeric values. Human display selectors and pattern
labels are handled separately by the native display reconstruction.

Native proof: original `GetReadinessCode_DT.dll` Execute `0x1820`, support helper
`0x1050`, output `0x19D0`; `CommandCommon.dll` `GetEcuDataP3` `0x21CA0` and
`SetFrzFrmDat` `0x224D0`. Private reproducible evidence is in
`analysis/evidence/no-car-8/`; `readiness-corpus.json` covers all 12 regional
v12/v18 CARB profiles, 120 enhanced-readiness signals and 2,424 selected fields
on advertised PIDs above `0x87`, using authored synthetic replies. This proves
source-backed offline evaluation, not physical ECU behavior.

This closes the selected enhanced-readiness consumer contract only. It does not
close the broader OBD support, monitor, compound-value, or caller-integration
review; those remain separate coverage obligations.

Run `python -m unittest discover -s tests -p test_readiness.py`.
