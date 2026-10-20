# Toyota native command codecs

`scripts/toyota.py` reconstructs bounded parts of Techstream 18's native command
consumers. It is separate from the standard OBD helpers in `diagnostics.py`.
Status: **PHYSICAL_UNCONFIRMED**. No Windows DLL was executed and no vehicle or
adapter was contacted. The tests contain authored synthetic byte sequences.

The API starts **after database selection**: a request template must come from the
selected vehicle/ECU/function record. It does not guess that Toyota uses any
particular UDS, KWP or OBD service, address or session. A byte sequence in a test
is not a supported vehicle request. Patching a request does not authorize sending
it. There is no transport or write/active-test entry point in this module.

## Implemented contract

| API | Recovered behavior | Boundary |
| --- | --- | --- |
| `VariableTable(payload, count).get(reference)` | DDB variable directory entries are `<I offset, H size>`, followed by byte storage; references are one-based, zero means empty | Caller supplies an already decompressed section; validates every nonempty range |
| `CommandFrame.from_record(row, variables)` | Communication row offsets +2/+4/+6 reference send/mask/check bytes | First word and selection/exception logic are not reinterpreted; empty sentinel rows remain empty |
| `frame.check_reply(reply)` | Ordinary native receive requires nonempty data and `reply[0] == (request[0] \| 0x40)` | 255-byte ordinary receive/send boundary; no negative-response service guessing |
| `frame.check_mask(reply)` | Separate native CID mask operation checks `(reply[i] & mask[i]) == check[i]` | Iterates mask length; extra check bytes remain retained; insufficient input is rejected |
| `parse_kwp_dtc_reply(request, reply)` | At most 8 receive bytes; two-byte big-endian codes; first zero code stops processing; chunks of at least 7 bytes request continuation | Returns integer codes, continuation/zero flags and ignored tail; does not orchestrate retries or infer current/history status |
| `mask_comm_error(code, flags)` | Three native statuses can become success through exact caller-provided bits | Does not invent meanings for native transport statuses or default to masking errors |
| `freeze_request_p3(template, freeze_row, number)` | Replaces request indices 1 and 2 with Freeze row +0x4f and frame number | 84-byte Freeze row; service and remaining template retained |
| `freeze_request_p5(template, dtc, record_number=None)` | Writes 24-bit DTC big-endian at indices 2..4; overload writes nonzero record number at index 5 | Service/subfunction remain database-selected; not a claim of generic UDS service equivalence |
| `freeze_payload_p3(frame, reply)` | Skips exactly the send-list length and requires at least one remaining byte | Returns raw values, not a guessed PID conversion |
| `vin_payload_can(frame, reply)` | Uses first multi-receive result; strips three prefix bytes; drops zero bytes only at original remaining indices 0..2 | Returns raw bytes; no decoding, 17-character validity assertion, ECU selection or frame aggregation |
| `data_list_request(template, pid, protocol)` | Protocol values 0x14/0x15/0x34 patch indices 1..2 with a big-endian word; other values patch index 1 with a byte | Caller supplies the already selected native protocol and corresponding PID field |
| `pid_support_p3(freeze_row, available_bytes)` | Support mode 1=true, 2=false, invalid mode=status 0xa0040004; mode 0 checks data bit position then PidBit reference | Returns `None` when additional PidBit evaluation is required, never treats missing support information as true |

Native directory/list lengths are unsigned 16-bit; descriptor bytes preserve that
range. Ordinary receive is byte-sized; extended receive/session/address machinery
is not implemented. `ToyotaCodecError.code` preserves native result values for
recovered failure branches. Python adds bounds checks where native code could
read past lists; invalid Python integer ranges raise `ValueError`.

### Using an already decoded DDB

This reads a user's local database without loading a vendor executable. The
public repository does not include the database. This demonstrates descriptor
resolution only; choosing the first row does not select a vehicle command:

```python
from pathlib import Path
from scripts.diagnostic_db import read_database
from scripts.toyota import CommandFrame, VariableTable

database = read_database(Path("/path/to/Techstream_DB_NA/Toyota.ddb"))
section = database.sections[0]
variables = VariableTable(section.payload, section.count)
frames = [
    CommandFrame.from_record(row, variables)
    for row in database.sections[17].rows(8)
]
```

A native support decision takes the selected PID's `CPidList::GetDataLength`
result, **not** the length of a response including service/header bytes. In mode
0, `available_bytes * 8 <= uint16(freeze_row[0x40:0x42])` is unsupported. Otherwise
a zero PidBit reference at +0x3a means supported; nonzero means unresolved here.

For Data List, native `CCmdCommPidData` obtains a byte PID from its selected ECU
record +0x27 for ordinary protocols, or a word at +0x22 for 0x14/0x15/0x34. Its
protocol value comes from the ECU-category record +0x48. Do not substitute a
standard J2534 protocol enum. Extended templates are selected by native function
0xca, ordinary templates by 0x6b; this module does not implement that database
function/ECU/exception join.

## Native evidence ledger

Addresses below are **RVAs**, with image base `0x10000000`. Evidence is static
instruction/data-flow analysis of local original artifacts under
`artifacts/extracted/techstream-18-application/Techstream_Bin/`. Saved annotated
`CommandCommon.dll.asm` is under `analysis/evidence/fullport-scaling/`; existing
feature traces are under `analysis/evidence/fullport-features/`. These private
artifacts are excluded from the public source repository. Hashes and addresses
allow an owner of the same release to reproduce the checks with `objdump`.

| Original binary | SHA-256 |
| --- | --- |
| `CommandCommon.dll` | `07547a9e47378d37c3ef7d96c2f33f6c62c4151626d98d3f3ff03b7c74909de7` |
| `KgpDataCtrl.dll` | `e5235bc0c241c6a450fe461031eed0915675032b1db994bd54d98818fac88aa9` |
| `GetDiagCode.dll` | `3acbefef4d119c9928227fabb6a0bcb91cf6497d3e45afc88ca99ef00b088f68` |
| `GetFrzFrmDat.dll` | `7977c82f353d553e4b9af493e623e3c628d072b83ffb5b7095faa8e5446bd8d9` |
| `GetVIN_CAN_DT.dll` | `ba6037c99037f1149a3d9543254b4fae6a7721dd977da25efb0cfbdf4d07bdd3` |
| `GetVIN_DT.dll` | `cdac732101d59bc213e49d5550238e37fdc56f8a0f049b206d58e2effaa924a3` |
| `KGP_CommFrameCtrl.dll` | `8fd7cfa4c73d7f433cae77c03f6dcba11af2f44fab15b0cac1f1edee4bb906ca` |

- KgpDataCtrl `CDbVariableTable` consumer RVA `0x50293`: reference zero returns
  empty; nonzero subtracts one, scales by directory width. Width getter
  `0x50486` returns 6; `0x50451` sets storage base after count*6 bytes. At
  `0x50338..0x50377`, reads 16-bit size at entry+4, 32-bit relative offset at
  entry+0 and adds storage base.
- KgpDataCtrl `CDbCommFrameResRecords::SetRecVariableData` RVA `0x10ace`, specific
  field reads `0x10cce`, `0x10d13`, `0x10d55`: row+2/+4/+6. `GetSendFrame` RVA
  `0x10e10` returns pointer/word-length pair for a signed-short row index.
  `GetReceiveMask`/`GetReceiveCheck` are `0x10e7c`/`0x10ee8`. CommandCommon
  `CCommFrameData::SetCommFrame` RVA `0x6a930` loads DB record 0x111 and copies
  these three lists, keeping the service bytes supplied by the database.
- CommandCommon `CCommCachePlus::CommFrameSendReceive` RVA `0x5d190`: receive
  capacity is byte at object+0x28; `0x5d358..0x5d373` checks nonzero length and
  response SID OR 0x40, otherwise returns `0xa0040201`. A separate function
  `CCmdCommCidData::RcvFrmMaskCheck` RVA `0x168f0`, loop
  `0x16942..0x16975`, masks the received byte and compares to the **unmasked**
  check byte. It does not require the two DB lists to be equal in length.
- `GetDiagCode::Execute` RVA `0x1010` calls CommandCommon `InitDiagCode` at
  `0x120f` and `GetKwpDiagCode` at `0x125e`. CommandCommon implementation RVA
  `0x75810` resolves function-frame DB 0x112, communication settings 0x11d,
  frame 0x111. `GetSendFrame` at `0x759f1` proves no universal hardcoded
  request SID. `0x75a87` passes receive capacity 8; `0x75ad7..0x75ae5` checks
  positive SID; length 1 returns `0xa0040202` at `0x75cb5`. Pair count is
  floor((length-1)/2) at `0x75b0c..0x75b1b`; `CreateDiagCode` at RVA `0x793c0`
  puts first byte in AH and second in AL. Zero result branches directly to
  exit `0x75be6`; lengths below 7 finish, otherwise another receive begins.
  Single-chunk API exposes that decision without reproducing live retry state.
- CommandCommon `MaskCommError` RVA `0x79bb0`: `0x91010009` uses flag bit 1,
  `0x90020321` uses bit 2, `0x90020323` uses bit 4. Other errors remain intact.
  The DTC loop also has an earlier direct return for `0x90020323`; the helper
  alone is not a model of the entire receive/retry state machine.
- `GetFrzFrmDat::Execute` RVA `0x12ac` calls support check; at `0x12e7` calls
  `CCmdEcuData::GetFrzFrmDatP3`, CommandCommon RVA `0x22b10`. Row+0x4f is read
  at `0x22bbc`; template count >=3 is checked at `0x22c81`; indices 1/2 are
  patched at `0x22cd6..0x22ceb`. At `0x22d5c..0x22d6f`, raw reply length minus
  send-list length must be >=1. Subsequent conversion remains outside this codec.
  Function variant `GetFrzFrmDatP3Func` RVA `0x233e0` has matching patch logic.
- CommandCommon `CGetFrzFrmDatP5Base::SetDTCToSndFrame` RVA `0x82ee0` validates
  DTC <=0xffffff and writes bytes at indices 2,3,4; overload at `0x82f60`
  validates nonzero record byte, writes index 5 and calls the first helper.
  Native code lacks list-length checks there; Python rejects short templates.
- CommandCommon `CCmdCommPidData::GetPidData` RVA `0x1b880`: selects extended
  branch for protocol 0x14/0x15/0x34 at `0x1bba5..0x1bbbd`, checks template
  length >=3, writes high/low word bytes at `0x1bc13..0x1bc37`. Ordinary
  branch checks length >=2, writes PID byte at `0x1bcdf..0x1bcee`.
- CommandCommon `CCommCachePlus::CheckSupportPid` RVA `0x5e660`: support mode
  branch at `0x5e6ed..0x5e718`; byte-length/bit-position comparison at
  `0x5e71d..0x5e749`; reference zero shortcut at `0x5e757..0x5e764`. Nonzero
  PidBit reference resolves DB 0x208 and invokes `CheckSupportBit` at `0x5e82f`.
  Freeze-specific `CheckSupportFrzPid` RVA `0x5eed0` repeats these early gates.
- `GetVIN_CAN_DT::Execute` RVA `0x1010` selects function 0x86, invokes multi-
  receive at `0x115d`, consumes first result at `0x11a7..0x11c1`; requires
  length >=3 (`0xa0040202` otherwise). Prefix strip at `0x1243`; zero filter
  at `0x129c..0x12a6`; local buffer initialized to 255 zero bytes at `0x12dd`.
  `GetVIN_DT` additionally queries function 0x8b for a result count at byte 2
  and aggregates function 0x86 multi-results. That aggregation path is **not**
  exposed by `vin_payload_can`, which must receive only the CAN variant's first
  native result. Neither path proves a universal request like `22 F1 90`.

## Local original-data cross-check

All 2,657 communication descriptors resolved through all 3,025 variable entries
in each original NA/JP/EU `Toyota.ddb`. Each contains two empty request sentinel
rows and 1,857 descriptors with unequal mask/check lengths. This is why descriptor
loading preserves those lists independently; only the explicit mask operation
requires enough check bytes. This validates directory/reference decoding, not
vehicle selection or physical response behavior.

| Local database | SHA-256 |
| --- | --- |
| NA | `63ee18391421a7b02996eef282bc8ea3251889981d9cf9e1722e89f4952cb19e` |
| JP | `0440d1f062eb3ba687d9e67fa2d4f964fff730a53fd9d7a4adc62e9c31321a86` |
| EU | `284041de59b6932e2ab1e5b299bb22f7f006463760379566fabc46c7107b309b` |

## Error, support and physical boundaries

The recovered general reply check rejects a `7f` reply when it does not match
the selected positive SID. This module does **not** label its third byte as a
specific negative response code, infer response-pending behavior, or retry a
negative response. The native controller's `Receive` at RVA `0x15170` delegates
through backend vtable+0x10; the detailed backend mapping to 0x90020321/323 was
not traced. Those statuses must remain distinct from raw wire data.

The DTC integer parser does not interpret pending/permanent/history flags, map
code labels, or join Freeze support. `GetKwpDiagCode` has multiple shipped
variants; this is one traced path, not proof of Phase 4/5 completeness. VIN
character validation, Data List polling/signal conversion, PidBit rule language,
full ECU/function/exception selection, transport timeouts, bus/session setup,
cancellation and retry orchestration remain open. The existing scaling and DDB
modules can consume raw values independently; no unproven integration is hidden
inside these codecs.

Validate authored checks with:

```bash
python -m unittest discover -s tests -p test_toyota.py -v
ruff check scripts/toyota.py tests/test_toyota.py
pyright scripts/toyota.py tests/test_toyota.py
```
