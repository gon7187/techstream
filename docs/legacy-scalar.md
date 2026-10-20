# Legacy 12 scalar conversion

`scripts.legacy_scalar.convert_legacy_scalar` implements the five-argument
legacy-12 `CommandAPI._ConvertData@20` ABI in native Python. It never loads the
DLL. Legacy 18's `_ConvertData@28` is a different export and is not this API.

The caller supplies selector (signal byte +0x3c), raw DWORD (MultiData +8),
`LegacyConversionTable` (signal +0x40), precision (signal byte +0x3d), and the
fifth argument (signal byte +0x16). The fifth argument is not the conversion
table's flag byte: only literal 1 overrides that flag, and only in the regular
numeric lanes. The selector dispatch truncates to its low byte.

Display text must already have passed through the caller's UTF-16LE-to-ACP
normalization. The mandatory `codepage` identifies that conversion explicitly;
the scalar provider preserves narrow bytes and stops at the first NUL. It does
not guess ACP from Linux locale. DTC output is ASCII; `%c` preserves a raw byte,
including bytes invalid as standalone characters in that ACP. Lookup NULL or
empty text yields `-No Data-`. A range display with NULL text would fault inside
native `strcpy`; the Python implementation raises `LegacyScalarError`.

| Selectors | Export behavior |
| --- | --- |
| 1, 20, 22 | Linear conversion, first matching display value, no-data fallback |
| 2, 21, 23 | Linear integer conversion, decimal formatting (21/23 alias 2) |
| 3 | Uppercase hexadecimal, minimum width from precision |
| 4 | Raw low-byte character; NUL returns empty bytes |
| 5 | P/C/B/U from bits 14–15 and four uppercase hex digits from bits 0–13 |
| 6 | Original reciprocal piecewise conversion, clamp below zero |
| 7, 8 | Reverse 10/12 bits in byte order, final bit is sign magnitude |
| 9, 10, 11 | Reverse 10/8/16 bits in byte order, unsigned |
| 12, 14, 15, 16, 17, 18 | `-TypeErr-` (these are original dispatch entries) |
| 13 | Linear numeric result or signed/unsigned threshold display 0/1 |
| 19 | Unsigned linear conversion, packed minutes/seconds, low-byte clamp 59 |
| 24 | Raw <=3000: raw/2; otherwise raw*8-22500; unsigned range labels |
| 25 | Sign-bit-dependent magnitude/offset path; decimal formatting |

Arithmetic follows the x86 helpers: unsigned input and gates, signed 64-bit
multiply/divide for linear paths, DWORD wrap before final int32 formatting,
truncation toward zero, and masked shift counts. Bit reversal uses wrapped
32-bit multiplication and signed IDIV; division overflow raises an error.
Zero and one divisors bypass linear division; zero bypasses bit-reversal IDIV.
Signed flag 1 extends the selected sign bit, flag 3 applies sign magnitude.

Decimal formatting reproduces the source's integer algorithm, not floating
point formatting: precision zero uses `%d`; positive precision emits an explicit
space or minus prefix, integer part, decimal point, and zero-padded remainder.
The optional `decimal_point` is exactly one byte: the first byte of native
`localeconv()->decimal_point`. Its default `b"."` is an **authored host C-locale
policy**, not a discovery of the original Windows process locale. Exact process
parity requires supplying the captured native byte. Neither codepage nor Linux
locale determines it. Multibyte strings and empty context are rejected; callers
must explicitly select the native first byte. A NUL byte truncates the generated
format; a percent byte retains the native generated-format escape behavior.
Precision powers through 10^18 are exact; `_ftol` returns int64 but the caller
uses EAX, then signed-divides that low DWORD by ten. Consequently precision nine
and higher deliberately do not behave like ordinary fixed-point division.
Out-of-int64 `_ftol` produces the masked x87 indefinite INT64_MIN, whose low DWORD
is zero; the original substitutes divisor one. INT32_MIN negation wraps and can
produce a double minus in decimal output. No rounding or float approximation is
introduced.

Output excludes the C terminator. Results requiring 256 or more bytes raise
`LegacyScalarError`: the original buffer would overrun, so there is no defined
native byte result to preserve. Unknown selectors retain `-TypeErr-`.

## Static evidence and validation

Private evidence remains outside publishable files. The legacy-12 export is at
RVA 0x4330; its jump table is at 0x46b8/0x46dc. Formatting is at 0x4960,
minute/second formatting at 0x4b90/0x4bb0. Helpers are at 0xa8792, 0xa87b5,
0xa883a, 0xa88b0, 0xa8cd6, 0xa8d95, 0xa8de6, 0xa8dfc, 0xa8e4c,
0xa8f32, 0xa8f66, and 0xa904a. The public implementation includes no copied OEM
source or data records. Static assembly resolves incorrect decompiler argument
recovery, particularly CString formatting and the `_ftol` low-DWORD return.

Run `python -m unittest tests.test_legacy_scalar`. The authored controls cover
all 25 selector slots, signed modes and override scope, byte/NUL behavior,
codepage validation, duplicate labels, thresholds, DWORD wrapping, bit reversal,
IDIV overflow, CRT precision truncation, and buffer limits. They establish native
source-bound behavior; they are not a claim of DLL execution or vehicle parity.
