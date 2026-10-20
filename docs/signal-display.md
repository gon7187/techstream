# Native signal display

`render_signal(raw, selector=..., sign_mode=..., bits=..., multiplier=...,
 divisor=..., offset=..., precision=..., patterns=..., minimum_raw=...,
 maximum_raw=...)` reconstructs the original `CommandAPI.dll` exported
`ConvertData` (`0x5F70`). It returns `raw`, `value`, `display`, `kind`, `status`.
An integer numeric `value` retains native decimal scaling; its engineering
number is `value / 10**precision`. Float selectors already return engineering
numbers. Symbolic/hex/character/DTC/time output has `value=None`.

The actual dispatch is explicit:

| Selectors | Original behavior |
|---|---|
| 1,20,22 | First exact pattern match against affine converted integer; missing label gives `-No Data-`, unresolved |
| 2,6..11,21,23 | Numeric conversion and fixed decimals;21/23 force arithmetic selector2 |
| 3,31 | Uppercase hexadecimal with precision as minimum width |
| 4,32 | Low-byte character |
| 5 | Native P/C/B/U DTC text |
| 19 | Packed quotient/remainder time, seconds capped at59 |
| 12,25,26,30,34 | Numeric path;25 has native sign-bit/offset branch,26 negates |
| 13,24,27,33 | Numeric result plus optional pattern0/1 threshold label; missing label falls back to numeric |
| 28,29 | IEEE754 float32/float64 and native invalid ranges |
| Other | `-TypeErr-`, unresolved; never an invented number |

`patterns` contains ordered `(value,label,low,high)` tuples. The recovered path
compares `value`; it does not infer bit masks from the other fields. Native
threshold comparison uses the two original metadata endpoints in its original
order, including signed conversion and selector27 negation. A missing threshold
endpoint remains unresolved. A missing symbolic definition is never silently
presented as a measurement.

Selector29 requires explicitly correlated `raw_words=(low,high)`. Arbitrary
extended records are not substituted for that pair. Float invalid bounds are
literal `CheckValidData` comparisons (`0x6CF0`), covering native integer-range
limits and IEEE nonfinite values. Missing values remain `None`; zero and all-one
raw values are not general-purpose unavailable sentinels. Fixed-decimal formatting preserves native low32 negation and signed quotient/remainder, including the unusual INT_MIN and precision-overflow outputs. Precision is the original unsigned byte.

`CCmdEcuData.SetFrzFrmDat` (`CommandCommon.dll 0x224D0`) selects original
PhyData24, Unit12 and PatDisp24 records. Freeze word`+70` selects the pattern
family; PatDisp DWORD`+0` is the original localized label and DWORD`+4` its match
value. `CCmdFrzFrmDat.GetString` (`CommandDataLib.dll 0xA7DE0`) independently
confirms exact first-match lookup and NULL for no match. Exception overlays use
the recovered PatDisp key `(u16+12,u32+4)`, exception`+16`, flag`+23`.

Private original decompilations and instruction listings are retained under
`analysis/evidence/no-car-8/display-*`; no vendor DLL or vehicle code is executed.
Run `python -m unittest discover -s tests -p test_signal_display.py`.
