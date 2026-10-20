import ctypes as C
import struct
import threading
import unittest
from unittest.mock import Mock, patch

from scripts.jlr import JLRClient, USBLocation, USBTransport, probe_adapter
from scripts.mongoose_protocol import decode_frames, encode_frame

LOCATION = USBLocation("1-2", 1, 3, 0x86, 4)


class FakeUSB:
    """Exercise the actual ctypes wrapper with controllable USB return values."""

    def __init__(self):
        self.devices = (C.c_void_p * 2)(123, None)
        self.lib = Mock()
        for name in (
            "init",
            "claim_interface",
            "release_interface",
            "set_interface_alt_setting",
            "control_transfer",
            "bulk_transfer",
        ):
            getattr(self.lib, "libusb_" + name).return_value = 0
        self.lib.libusb_init.side_effect = self.init
        self.lib.libusb_get_device_list.side_effect = self.device_list
        self.lib.libusb_get_device_descriptor.side_effect = self.descriptor
        self.lib.libusb_open.side_effect = self.open
        self.lib.libusb_get_bus_number.return_value = 1
        self.lib.libusb_get_device_address.return_value = 3
        self.lib.libusb_error_name.return_value = b"FAKE_USB_ERROR"

    @staticmethod
    def init(output):
        C.cast(output, C.POINTER(C.c_void_p))[0] = 456
        return 0

    def device_list(self, context, output):
        C.cast(output, C.POINTER(C.POINTER(C.c_void_p)))[0] = self.devices
        return 1

    @staticmethod
    def descriptor(device, output):
        data = bytearray(18)
        struct.pack_into("<HH", data, 8, 0x18E1, 0x0104)
        C.memmove(output, bytes(data), 18)
        return 0

    @staticmethod
    def open(device, output):
        C.cast(output, C.POINTER(C.c_void_p))[0] = 789
        return 0

    def transport(self):
        with (
            patch("scripts.jlr.C.CDLL", return_value=self.lib),
            patch("scripts.jlr.ctypes.util.find_library", return_value="fake"),
        ):
            return USBTransport(LOCATION)


class USBTransportTests(unittest.TestCase):
    def test_claim_and_alt_failures_release_every_successful_claim(self):
        for operation in ("claim_interface", "set_interface_alt_setting"):
            usb = FakeUSB()
            getattr(usb.lib, "libusb_" + operation).side_effect = [0, -6]
            with self.subTest(operation=operation), self.assertRaises(OSError):
                usb.transport()
            released = [
                args.args[1] for args in usb.lib.libusb_release_interface.call_args_list
            ]
            self.assertEqual(
                released, [0] if operation == "claim_interface" else [1, 0]
            )
            usb.lib.libusb_close.assert_called_once()
            usb.lib.libusb_exit.assert_called_once()
            usb.lib.libusb_control_transfer.assert_not_called()

    def test_open_timeout_still_attempts_vendor_close(self):
        usb = FakeUSB()
        usb.lib.libusb_control_transfer.side_effect = [-7, 0]
        with self.assertRaises(OSError):
            usb.transport()
        self.assertEqual(
            [c.args[3] for c in usb.lib.libusb_control_transfer.call_args_list], [1, 0]
        )
        self.assertEqual(usb.lib.libusb_release_interface.call_count, 2)
        usb.lib.libusb_close.assert_called_once()
        usb.lib.libusb_exit.assert_called_once()

    def test_close_error_keeps_releasing_resources_and_close_is_idempotent(self):
        usb = FakeUSB()
        transport = usb.transport()
        usb.lib.libusb_control_transfer.return_value = -4
        with self.assertRaises(OSError):
            transport.close()
        self.assertEqual(usb.lib.libusb_release_interface.call_count, 2)
        self.assertFalse(transport.handle)
        self.assertFalse(transport.context)
        transport.close()
        usb.lib.libusb_close.assert_called_once()
        usb.lib.libusb_exit.assert_called_once()

    def test_short_write_rejected_and_partial_timeout_read_preserved(self):
        usb = FakeUSB()
        transport = usb.transport()
        try:

            def transfer(handle, endpoint, buffer, size, transferred, timeout):
                C.cast(transferred, C.POINTER(C.c_int))[0] = 3
                if endpoint == LOCATION.input_endpoint:
                    C.memmove(buffer, b"abc", 3)
                    return -7
                return 0

            usb.lib.libusb_bulk_transfer.side_effect = transfer
            with self.assertRaises(OSError):
                transport.write(b"abcd")
            self.assertEqual(transport.read(100), b"abc")
        finally:
            transport.close()

    def test_cancelled_probe_closes_usb_without_sending_protocol_request(self):
        transport = Mock()
        cancel = threading.Event()
        cancel.set()
        with (
            patch("scripts.jlr.USBTransport", return_value=transport),
            self.assertRaises(InterruptedError),
        ):
            probe_adapter(LOCATION, cancel)
        transport.close.assert_called_once()
        transport.write.assert_not_called()

    def test_protocol_status_timeout_and_late_reply(self):
        transport = Mock()
        transport.read.return_value = encode_frame(
            struct.pack("<6HII", 0, 1, 0x8003, 1, 0, 0, 0x20A, 0)
        )
        with self.assertRaisesRegex(OSError, "0x20a"):
            JLRClient(transport).transact(1, 3)
        with self.assertRaises(TimeoutError):
            JLRClient(transport).transact(1, 3, timeout=0)
        stale = struct.pack("<6HII", 0, 1, 0x8003, 255, 0, 0, 0, 0)
        fresh = struct.pack("<6HII", 0, 1, 0x8003, 1, 0, 0, 0, 0)
        transport.read.side_effect = [encode_frame(stale), encode_frame(fresh)]
        client = JLRClient(transport)
        self.assertEqual(client.transact(1, 3), fresh)
        self.assertEqual(list(client.events), [stale])

    def test_full_identity_probe_order_and_bounds(self):
        transport = Mock()
        pending = []
        opcodes = []

        def write(frame):
            payload = decode_frames(frame)[0]
            target, source, opcode, sequence = struct.unpack_from("<4H", payload)
            opcodes.append(opcode)
            header = struct.pack(
                "<6HII", source, target, opcode | 0x8000, sequence, 0, 0, 0, 0
            )
            if opcode == 0x100:
                reply = header[:12]
            elif opcode == 0x109:
                reply = header + bytes(160)
            elif opcode == 0x0C:
                reply = header + bytes(4) + struct.pack("<I", 42)
            else:
                reply = header + bytes(4) + b"SERIAL\0"
            pending.append(encode_frame(reply))

        transport.write.side_effect = write
        transport.read.side_effect = lambda timeout: pending.pop(0)
        result = JLRClient(transport).probe()
        self.assertEqual(opcodes, [0x100, 0x109, 0x0C, 0x0C, 0x13])
        self.assertEqual(result["serial_text"], "SERIAL")
        self.assertEqual(result["firmware_raw"], 42)
        self.assertEqual(len(result["boards"]), 8)


if __name__ == "__main__":
    unittest.main()
