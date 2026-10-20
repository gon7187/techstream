# CUW2026 P4/P5 calibration getters

The three exact 2026 identities are implemented by
`scripts/programming_2026_p5_getters.py`. No CUW12/18 filename dispatch or vendor
code execution participates.

| Module | Export RVA | Native body |
| --- | --- | --- |
| TCUWP4P5CanCIDGetter.dll | 1180 | 1270, P5 virtual slot1730, P4 slot1a10/support1fb0 |
| TCUWP5CanCIDGetter.dll | 1fe0 | 19f0, exchange16f0, parser1510 |
| TCUWP5CanCIDGetterWithSetBS.dll | 1fb0 | 19b0, exchange16d0, parser1510 |

`bind_native_context` authenticates the module, validates the immutable actual
native parameter binding against the imported CUW and resolves the actual native
communication address provider. It does not accept manual attachments or
observations. Getter parameter selection remains the shared native global CPU0
selection; selected metadata may reference another CPU. The shared calibration
and parameter producers own these distinct indices. No keys are read or emitted
by these getter exports.

`run_native_context` executes the primitive sequence through `NativeRuntime2026`
and `CanDiag2026`. P5 uses `22f181`, locks and the native pending limits
`0xb4/0x159a`. Mixed P4/P5 first queries P5, requires at least one retained CID,
then uses a second P4 address with one filter spanning support `0900` and CID
`0904`. P4 support requires six response payload bytes and bit0x30 in byte2. Its
probe timeout9/16 becomes native error3, rather than a driver error.
Plain P5 preserves two/three-byte native address records; mixed and SetBS always
read two-byte IDs. SetBS sets1 before address iteration and restores0 before
disconnecting, including empty address vectors and faults.

Native count/DataSize checks and sixteen-byte ANSI CID records are preserved.
P5 sanitation removes a record only if it contains no `!` anywhere and byte10 is
`#`; this is assembly verified. Timeout9/16 is swallowed only for the exact
selected `RequestCANIDAllowingTimeout`, only in the two standalone P5 getters.
Each P5 receive and mixed P4 CID receive observes native callback12. The mixed
P4 support probe does not observe it. Cancellation inside the native wire try
maps to9999; the explicit entry callback retains its distinct early-return path.
Partial vectors survive native failures. Address associations are updated only
for the first34 CID slots; the CID vector itself can extend further.

The exported return is a vector pointer. `native_return` is therefore `None`,
while `bool_out` and `native_result` expose the distinct native out-parameter7.
Neither field means flashing completed. Native failures return false with the
source error/driver fields; a cancelled mixed secondary query can return true
with the already collected P5 vector. Host cancellation, deadlines and provider
contract faults propagate after cleanup, without manufacturing a native return.

The host enforces finite deadlines/call budgets, at most256 address records and
4096 CID entries. These are host limits. The host also releases filters when the
native cancellation branch omits its explicit stop; this is resource hygiene,
not a claim about Windows driver leakage. Failed releases remain owned by the
runtime and cannot produce a successful report.

Run:

```sh
python -m unittest discover -s tests -p test_programming_2026_p5_getters.py -v
```

Checks cover all three exports from authored imported CUW through actual native
parameter/calibration/address producers and the typed J2534 adapter, plus typed
native faults, host cancellation, cleanup failure, pending replies, parser
bounds, partial vectors, the34-slot cap and BS restoration. Source hashes and
check transcripts are private under `analysis/evidence/no-car-85` and
`runtime/no-car-85`. The normal importer/factory composition is additionally checked by the private
`runtime/no-car-85/verify_factory.py` harness using the actual PE bytes only for
identity validation. No vehicle or vendor DLL execution is needed for these
checks. Hardware behavior remains unverified.
