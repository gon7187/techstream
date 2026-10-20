# Recorder byte buffer

`NativeRecorderRing` implements bounded recorder storage without opening a device.
Construct it with the exact allocation, packet byte size, phase and packets per
block. A packet is a little-endian unsigned 32-bit source timestamp followed by
its payload. No time conversion, interpolation or resampling is performed.

`write(bytes)` and `read(size)` preserve separate unread accounting and retained
history. `append(timestamp, payload)` combines a complete packet write with its
consumer read; an allocation is never silently enlarged. The oldest cursor uses
an inclusive collision boundary. Consequently, filling an allocation exactly
can advance the oldest cursor before the next write. The write cursor can equal
capacity. `written` saturates and is separate from the current oldest-to-write
span exposed by `packet_bytes()`.

`seek_timestamp(target, floor=...)` returns the native rounded source timestamp
and block byte offset. `select(left, right)` selects through the complete ending
block. Native unsigned comparison and lookup boundaries are retained, including
behavior across timestamp wrap; callers must not substitute interpolated values.
`select_positions` supports already recovered native byte offsets.

`serialize(0)` writes the full allocation and native image header.
`serialize(1)` writes the selected region normalized to offset zero. Explicit
`set_complement` / `calc_complement` state modifies the first timestamp of the
last selected block when nonpositive, or appends that block with its adjusted
first timestamp when positive. Addition wraps at 32 bits. A positive complement
can make the serialized image larger than the original allocation; its native
header retains the original capacity and selected-region free byte count.

Host validation rejects requests that would dereference outside the allocation,
exceed the fixed byte budget, or expose an uninitialized native complement tail.
Unused allocation bytes begin as zeroes. Serial results and returned images are
immutable copies; later writes cannot mutate a saved capture. Cancellation
checks occur before each feed record, preserving the completed prefix.

The runnable checks use authored literal packets and independent bytewise cursor
controls: `python -m unittest discover -s tests -p test_recorder_buffer.py -v`.
Physical adapter and vehicle operation remain unverified.

For a live stream written through `append`, `packet_slot(position)` recovers the
native generator cache slot from its next-slot cursor and complete retained
packet positions. This supports phase 1 with two equal-sized frame slots even
when the oldest slot has advanced at a collision. The raw serial header does not
encode that slot cursor; consumers must retain proven live routing separately.

The standalone `max_bytes` budget bounds allocation and serialized image bytes;
the native ring envelope adds 38 bytes. Snapshot and container readers separately
bound their complete encoded payloads. A caller exporting through those readers
must reserve room for that envelope and surrounding metadata rather than treating
the image-byte budget as an encoded-file budget.
For native batch production, call `append(..., consume=False)` for every produced
packet, then `read(packet_size)` as the consumer drains the captured batch. Packet
cursor accounting still advances on production; unread free space is restored
only by those explicit reads. The default `consume=True` behavior is unchanged.

Select the primitive's `native_source` explicitly when reproducing an original
consumer: the default `"x86"` retains its canonical direction-word return on an
interior failed time scan. The SH3 recorder's corresponding exits return an
incoming register with no defined timestamp provenance. With `native_source="sh3"`
those exits raise an explicit unknown-seek error. Defined time lookups, raw packet
bytes and first/last missing-time sentinels keep their native behavior. No host
clock, fabricated timestamp or guessed register value fills the gap.
