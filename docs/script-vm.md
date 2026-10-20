# CSDF object inspection and bounded evaluation

`python -m scripts.script_vm PATH` inspects an explicitly supplied raw CSDF object. `--steps` reads a bare instruction stream. Both emit JSON, preserve payloads as hex and reject truncated records and trailing object bytes. No original DLL or script library is loaded. Input is bounded to 16 MiB.

The recovered object layout is: variable count `u16le`, identifier count `u16le`, identifiers (`u8` byte length, name bytes, `u16le` ID), library count `u8`, libraries (`u8` length, name bytes), step count `u16le`, steps (`u8` opcode, `u8` payload length, payload). There is no magic signature in this reader. Names remain bytes because a source encoding has not been established. A successful parse demonstrates structural consistency, not that an arbitrary file is CSDF. The shipped `.srp`/`.srplst` resources use a separate recovered encrypted XML/CSV path described below; they are not this raw object layout.

`parse_object(bytes)` returns `ScriptObject`; `parse_steps(bytes)` returns `Step` objects. Inspection reports opcode, byte offset, payload, known operation, little-endian target/function operand and function argument count where the original consumer establishes them. Unknown opcodes remain visible as `unsupported`. Too-short known operands fail before interpretation. Extra operand bytes are preserved because exact lengths are not enforced by the recovered consumer.

| Opcode | Recovered dispatch | Evaluation |
| --- | --- | --- |
| `11/12/13/15` | push raw bytes with type tags `1/2/3/4` | supported, no guessed conversion to Python numbers |
| `20` | pop data | supported, underflow rejected |
| `30` | ExecuteOpr, first payload byte | byte operators, store and array references supported below |
| `40` | CtrlFunc, u16 function operand + u8 argument count | inspected; evaluation rejected |
| `41` | CtrlJamp, absolute u16 step index | supported |
| `42` | CtrlCall, absolute u16 step index | supported, saves `(pc+1)&65535` |
| `43` | CtrlRet | supported, underflow rejected |
| `44` | CtrlExit | supported, returns raw typed stack |
| `45` | CtrlJampCondition | pop and resolve value; jump when its first byte is zero, otherwise advance |

`evaluate(script, max_steps=10000, max_bytes=16*1024*1024)` is a side-effect-free subset for synthetic experiments. It rejects unsupported operations, invalid program counters and instruction-budget exhaustion. Aggregate retained payload bytes across the data stack and variables are checked after every instruction, including jumps/returns; shared references count conservatively. Concatenation checks the remaining aggregate allowance before allocating its result. `max_bytes` must be an integer from 1 to 16 MiB; each data/call stack is also capped at 4096 entries to bound empty-value and recursive-call growth. These are explicit safety limits, not claims about original native stack capacity. It supports checked variable references (tag 4), indexed byte references (tag 5), whole-value store and indexed store with zero-filled growth. Reading an unassigned variable fails; the original constructor does not initialize its type tag, so native undefined state is not emulated. It does not call libraries, reproduce native stack capacity/error codes, or execute diagnostic commands. This API cannot activate an ECU test or run a vendor utility. Physical behavior is `PHYSICAL_UNCONFIRMED`.

Evidence is static x86 code, not observed vendor execution. `CSDFScript.dll` SHA-256 `62669f257c9a45fa0373a4929e239d557c7dd4dfefc72425a7f7bd240144f01b`: LoadObjectFile RVA `0x65b0` reads the counts/tables at `0x6647`, `0x66c7`, `0x67fc`, `0x688b`; WriteStepData `0x5b70` and ReadStepData `0x5e20` establish the record. ExecuteStep `0x7e00`, selector table `0x807c`, jump table `0x8048` establish dispatch and payload decoding. CtrlExit/Ret/Call/Jamp are `0x7360/0x7370/0x7390/0x73c0`. Image base is `0x10000000`.

`CSDFCommonDLL.dll` SHA-256 `479fcd1d6b6019c1e267e53752ef986750be025ea6d716613538e761c4e5d785`: Open RVA `0x2b10` with the object's `0x2000` flag does not consume an object prefix; Read `0x2cf0` delegates to ReadFile `0x2d20`, whose unbuffered path `0x2e2c` passes the requested bytes directly to the Win32 file read. This supports the raw object layout, and does not establish how utility packages produce such objects.

Synthetic regression checks: `python -m unittest discover -s tests -p test_script_vm.py -v`. They cover tables, every truncation of a sample object, operand sizes, typed raw stack, call/return, jump bounds, unsupported evaluation and infinite-loop budget. No proprietary scripts are required or distributed.

## Recovered byte operators

Operator payload codes `11/12` add/subtract unsigned bytes modulo 256. `21/22` shift left/right with the x86 count masked by 31; the result is an unsigned byte. `23/24` perform AND/OR. `43/44/45/46` compare unsigned bytes using `<`, `>`, `<=`, `>=`. Operands must resolve to nonempty type-1 values; only their first byte is used. Every result is type 1 with one byte. There is no multiplication/division/XOR dispatch in this recovered table, so those operations are not invented.

Codes `41/42` compare the entire resolved byte arrays for equality/inequality if their type tags match. The native mismatch branch returns false for **both** operations; the evaluator preserves this unusual rule. `01` stores the resolved top value into the next stack value, which must be a variable/index reference. `32` combines a variable reference with a scalar byte index; reads past the stored value produce zero. Native `Resize` zero-fills indexed store growth. `31` (CtrlConnect) concatenates the resolved left bytes followed by right bytes and produces tag 3; output is bounded to 16 MiB. Its append call is CSDFScript RVA `0x7271`, invoking CSDFCommonDLL RVA `0x1510` (AppendData `0x1070`).

Proof: ExecuteOpr RVA `0x7c90`, selector `0x7d54` and table `0x7d3c`; byte operators `0x7980` with selector/table `0x7c58/0x7c2c`; equality `0x77a0`; dereference `0x6b40`, scalar conversion `0x6c60`; store `0x7500`; array reference `0x6f10`. `CSDFCommonDLL::Resize` RVA `0x1270` zero-fills growth before copying the old content. Private REA corroboration: `ev_0ab0db4ef69bbb42f0246f61197706d86798ff3fdfe1c9a0fe959a16f5623456` (conditional jump), `ev_2ce4e8ed77a74102a38a791457e895f4a1d627a8cd30bbd679fa9cd85794e6d3` (unsigned byte arithmetic).

## Read-only utility resources

`decode_utility_resource(ciphertext, key)` decrypts AES-ECB with strict PKCS#7 padding and reads a four-byte opaque header followed by BOM-prefixed UTF-16LE XML. `UtilityResource.root` provides the XML tree; `.inspect()` reports root/tag counts and function names, IDs and block attributes. It never interprets `<ACTION>`, `<COMM>`, `<CALLFUNC>` or other executable instructions. `decode_utility_list(ciphertext, key)` decrypts SRPLST ASCII CSV and returns its four raw fields per row without assigning unproven field meanings.

The only extra system dependency is **libcrypto** (OpenSSL EVP), accessed with Python `ctypes`. Keys stay in process memory; no external decoder is launched and no key is put in process arguments. No crypto package or vendor library is imported. `utility_resource_key(library_bytes)` accepts only the exact local vendor DLL SHA below and extracts the resource key from its established location; no key is embedded in source, docs or tests. Other releases need separately proven key locations.

CLI examples using locally supplied files:

```sh
python -m scripts.script_vm PRIVATE.srp --utility-library /private/IT3UtilityNeoNK.dll
python -m scripts.script_vm PRIVATE.srplst --utility-list --utility-library /private/IT3UtilityNeoNK.dll
```

XML document/entity declarations, malformed XML, invalid padding, wrong sizes and unknown key libraries fail. Decoding is bounded to 16 MiB. Synthetic encrypted fixtures use a public test key and contain only authored text. Private corpus verification decoded all 18 Techstream 18 SRP files to `<UTILITY>` XML and the one SRPLST to 19 four-field CSV rows, with zero errors. No original plaintext is distributed.

Static seam: `IT3UtilityNeoCtrlNK.dll`, SHA-256 `478df6d2bf27b0ca8df31fd7d02d43231f6e25a103de6fa61b421c93432bf0e7`, Script_GetScriptData RVA `0x40c0`: file reader `0x42f0`, decode callback invocation `0x41b3`, subsequent UTF-16 word swapping `0x420a`. `IT3UtilityNeoNK.dll`, SHA-256 `1953edf8821af8c7df612c383c756b87febb3ce7ba055744305ca5db4c2f37a6`: callback binding `0x13f76/0x13f81`, no-op callback `0x2870`, decode wrapper `0x13fd0`, padding cleanup `0x23fe0`, ECB block loop `0x23f00`, AES key expansion `0x24050`. The resource key location is RVA/file offset `0x3a7d4`, length 32. This is resource decoding; activation and licensing code is neither changed nor emulated. The decrypted XML engine is separate from CSDF object evaluation; executing those XML utilities requires recovery of its function/event/communication semantics.
