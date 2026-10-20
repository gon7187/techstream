# Whole-engine cleanup

`scripts.cuw_engine_cleanup` implements the resource-disposal path independently
of phase success and `CUWEngine2026.close()`. The concrete retry controller enters
it after its source-defined resume wait. The factory requires the engine's actual
issued worker; a caller cannot supply a callback reporting cleanup success.

The order is disconnect, clear/signal a pending retry decision, stop the owned
worker, release collection references, release sixteen target slots, release the
auxiliary and selected targets, reset engine globals, clear J2534 state, reset
retained vectors and recovery state, reset worker/retry globals, release buffers,
and clear the history block. The J2534 prefix uses `disconnect()`; the later
`clear()` remains a separate operation. Neither is a phase success result.

Collection references are compared by object identity. The exclusion scan uses
the **count** of nonempty names as its prefix length, including sparse-slot cases.
It does not search every named slot or globally deduplicate pointer deletion.
Selected target aliases survive the sixteen-slot pass and are released once at
the selected-target step. Ordinary engine close remains a different lifecycle.
Actual delta admission supplies the table, collection and auxiliary pointer
aliases. A group reset retains its removed current delta in the native `1c58`
owner until the worker has exited; other removed group members are disposed at
the reset. The native pointer-map entries retain their identity independently
of whether their FILE resource has already been disposed.

Native CID stop joins the actual outer/child job before a fresh worker is issued.
The same cleanup object, FILE resources, history and vector objects survive this
rebind. A failed dependent rebind restores the previous worker and retains the
original exception; the engine transaction authenticates the reverse handoff.

Faults propagate with their original exception identity. There is no rollback of
native mutations: a failure in the initial disconnect retains all targets; a
failure in the later device clear retains earlier target/global resets and leaves
later vectors/history intact. Reentry while cleanup runs is rejected. Repeating
a completed host cleanup is inert. Duplicate nonselected native pointer deletion
is rejected instead of attempting to emulate native use-after-free.

Recovery reset mutates the actual persistence state in place, including the
native inactive empty calibration tuple. It does not delete recovery files and
does not call the cache-deletion entry. Persistence validation rejects saving this
inactive tuple until a fresh source binding exists.

The source implementation, assembly and hashes remain private under `analysis/`
and `runtime/`. Public tests use authored calibration bytes and primitive results;
reading an authenticated PE for identity verification never executes that PE.

## Acceptance boundary

Resource algorithms and private helpers are not sufficient evidence of complete
native engine coverage. In particular, the native started/unstarted worker
thread branches and remaining nested statistics/buffer producers need actual
engine ownership and consumer tests. Empty aggregate initialization or manually
seeded cleanup state alone does not establish those producer joins. Separate
native engine and CONTROL J2534 views use the source-issued interface pair.
Cleanup disposes the engine view; the peer retains its native flags until its
own import/clear. Shared physical release generations prevent a second close.
The initial native field-log dump also needs its actual callback consumer. The
USB-copy virtual clear is resolved and its reset fields are represented, but an
actual USB-copy producer has not been joined to this aggregate.
G2 and G3 must remain open until those joins and independent source review pass.

The focused checks exercise actual sixteen-file recovery input, source-issued FILE selection
inside the owned worker phase, captured retry input, real J2534
primitive disposal, logged recovery callbacks after a 300 MiB large source has
closed, fault/cancellation chronology, and ordinary close followed by a fresh
source binding. The collection exclusion cases separately test pointer rules;
actual direct delta and listed delta reset checks additionally exercise the
source-issued collection/auxiliary/selected aliases and retained `1c58` owner.
Actual family count/percentage owners are reset only after device clear; a clear
fault preserves their previous values until a successful cleanup retry.

Run the focused contract checks with:

```sh
python -m unittest discover -s tests -p test_cuw_engine_cleanup.py -v
```
