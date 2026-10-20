# Native language and help resources

`TextResources.load(path, namespace=..., expected_sha256=...)` reads a supplied
DDB language pool without loading a vendor executable. `management` and `legacy`
select kind 4; `viewer` selects kind 5. These namespaces have independent IDs.
The source SHA-256, decoded section SHA-256, section-relative byte offset, stored
byte length and UTF-16LE encoding accompany each returned `ResourceText`.
`resolve(id)` requires a positive DWORD ID. `translate(ids)` preserves native
order and duplicates and enforces an aggregate output budget.

The original numeric translation operation is `GetTrslationStr_DT.dll` (that is
its actual spelling), which forwards DWORD IDs to `GetDbStringData`. This does
not establish that an arbitrary UI field selects that language namespace.

`ViewerHelpResources.load(viewer_path, language_path, ...)` binds an actual
kind-3 Viewer database to an explicitly selected kind-5 V-language file. Native
HelpInfo section 2 has 12-byte rows: string reference at DWORD 0, help key at
DWORD 4 and row kind at WORD 8. `resolve(help_id, kind=1)` returns the last
matching row's text and both files' provenance, or `None` when no row matches.
Native ordinary help uses kind 1. The separate active-test details consumer
uses kinds 2, 3 and 4. They are distinct lookups, not interchangeable labels.

Stored source text is decoded as Unicode. The Windows implementation converts
its UTF-16 pool using `CP_ACP` before passing C strings to its UI. This module
retains the source Unicode rather than guessing the user's Windows ANSI code
page. Like the native `-1` conversion length, presentation ends at the first
wide NUL. Original string bounds and byte lengths remain in provenance.
Malformed UTF-16, unbounded indexes, missing language references, wrong database
kinds, changed expected hashes, non-regular files and cancellation fail visibly.
No translated text, proprietary tables or key material are bundled.

The downstream mapping from every active Init caution/help/prohibition/info/
comment field to its GUI display consumer is still under static review. Consumers must not resolve those raw IDs against `M_English.ddb` merely
because their values fall within that file's index range. A native caution dialog for ECU functions and separate help clients use the
Viewer help broker; the active Init field-to-consumer joins must be established
before claiming complete instruction presentation.

Host limits are 64 MiB per supplied file/decoded section, 250,000 language or
help rows, 4,096 IDs per translation request and 16 MiB of UTF-8 text per
translation result. Help keys must retain their native ascending contiguous
index order; malformed noncontiguous groups are rejected instead of being
silently collected into a different lookup. These are explicit host limits.

`instruction_texts({"caution": ..., "help": ..., "prohibition": ..., "info": ...,
"comment": ...})` provides an authored backend composition with explicit
`absent`, `missing` and `resolved` outcomes and fresh resource reports. It treats
zero references as absent. This convenience composition selects help kind 1;
it does not establish native dialog visibility, ordering or field dispatch.

The Linux instruction presentation policy deliberately exposes the five typed
Init references through this proven kind-1 broker. Each result labels that
choice as `presentation_policy: "host-init-kind1"` and the unproved Windows
consumer dispatch as `native_dialog_dispatch: "unresolved"`. This presents
source-backed instructions without claiming the Windows dialog lifecycle.
`create_text_examples()` returns two authored files (`Viewer.ddb` and
`V_Example.ddb`) for UI checks; IDs 1–5 cover the five roles. It contains no
vendor content. Native help groups above 32,767 rows fail before their signed
16-bit count could wrap.

`create_active_text_examples()` extends the production authored active examples
with these Viewer/V files in all three demo regions and actual Init reference
fields. It updates ECU identities in the recordings and the file manifest.
Legacy examples expose all five roles; P5 and Routine retain their native absent
comment field. The examples exercise selected profiles, Init, text lookup and
captured execution together.

`active_details(help_id)` implements the native active selection details broker.
Pass the selected list item's `control_value`, which the native list/API bridge
carries as the help key. The three `outputs` preserve the native function's
buffer order: help kinds 2, 4, 3. Missing kinds return `resource: null`; existing
empty source strings remain resolved empty strings. Each present resource has
its own kind and source provenance. This is the recovered active selection
consumer, distinct from the authored five-role Init presentation policy. The
supplied example includes all three details for help key 2.

`UtilityTextResources.load(u_language_path, symbols_path, utility_group=...)`
implements the native TY2 numeric UI-ID broker. The caller must provide its
actual selected utility group. `UtilityResID_NK.rsd` supplies records of DWORD
group, DWORD resource ID, WORD byte length and UTF-16 symbol bytes. Common group
20000 and the selected group populate one map in file order; later matching IDs
replace earlier entries. TY2 constructs the key using each UTF-16 low byte.

The mapped string selects UtilityDB type `0x601`, stored in kind-6 U-language
section 1. Its 164-byte rows contain primary/secondary wide keys at 0/80 and the
section-0 string ID at 160. K1 returns the first matching primary-key row's text.
This lookup uses the selected U-language file; it never indexes `M_English` or
substitutes an English file. The supplied 12/18 `UtilityDB.dll` and
`GetUtilityString_DT.dll` are byte-identical, independently of DDB version.

`resolve(resource_id)` returns a fresh dictionary with `status`, `text`, selected
group, RSD SHA and record offset, mapped key, U-row offset and the full source
Unicode resource report. Missing symbols/keys return an empty native text with
`missing_symbol`/`missing_key`, rather than a fabricated translation. Invalid
source files, hashes, references and cancellation raise before presentation.
The explicit Linux presentation retains source Unicode; native Windows ACP,
best-fit conversion and language-specific normalization are not claimed. All
supplied original keys are checked as ASCII; non-ASCII key domains require an
observed Windows encoding and currently fail visibly. Numeric resource IDs do
not determine locale. Native selected-language configuration supplies the file;
no automatic language fallback has been established.

Host limits remain 64 MiB per file and aggregate decoded database, 250,000 source
rows, 32,767 rows per contiguous primary group, and 128 stored symbol bytes.
Regular-file reads are pinned through the shared reader; FIFOs/devices fail.
`create_utility_text_examples()` returns authored U-language/RSD bytes for the
source-proven Door group 4934 and IDs `0x94b5..0x94bc`, plus the common
group-20000 acknowledgement ID `0x1043`, without proprietary text.
A production utility controller can supply its recovered IDs to this resolver;
GTK integration must render the returned text and retain its provenance.
