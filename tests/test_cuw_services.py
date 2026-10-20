# Independent synthetic service payloads and low-level browser/window primitives.
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from scripts.cuw_services import (
    BrowserSnapshot,
    CalibrationID,
    CompletionNotice,
    DOMElement,
    EuroRequest,
    NoticeConfig,
    NoticeEvent,
    ProaceRequest,
    RKSAccess,
    RKSData,
    ServiceClient,
    ServiceError,
    ServiceHTTPResponse,
    TISRequest,
    build_service_request,
    import_repro_key,
    parse_service_response,
    rks_xml,
)


class ServiceTests(unittest.TestCase):
    def test_rks_native_xml_and_signature(self):
        data = RKSData("1", "GTS", "18", "LICENSE", "VIN", "Dealer", "PAIR", "SEED")
        xml = rks_xml(data)
        self.assertIn(b"<ReproKeyRequest>", xml)
        self.assertIn(b"<LicenseKey>LICENSE</LicenseKey>", xml)
        self.assertEqual(
            import_repro_key(
                b"<Signature>" + b"A" * 512 + b"</Signature>", source="synthetic"
            ).value,
            "A" * 512,
        )

    def test_rks_stored_empty_fields_are_native_valid(self):
        data = RKSData(*([""] * 8))
        xml = rks_xml(data)
        root = ET.fromstring(xml)
        self.assertIn(b"<X-Version></X-Version>", xml)
        self.assertIn(b"<LicenseKey></LicenseKey>", xml)
        self.assertNotIn(b" />", xml)
        self.assertEqual(len(list(root)), 6)
        self.assertEqual(root.findtext("TerminalInfo/LicenseKey"), "")
        self.assertEqual(root.findtext("RequesterKind"), "")
        access = RKSAccess()
        access.set_data(data)
        self.assertEqual(access.xml(), xml)

    def test_tis_native_operation(self):
        data = TISRequest(
            18, "session", "18.0", "VIN", "date", "EN", "GTS", "Dealer", "D1"
        )
        request = build_service_request(
            "tis-check", data, endpoint="https://example.invalid/service"
        )
        self.assertEqual(request.action, "http://www.openuri.org/getHealthCheckResults")
        self.assertIn(b"ReprogramCheck-CUW", request.body)


URL = "https://example.invalid/service"
DATA = RKSData(
    "1", "GTS", "18", "PRIVATE_LICENSE", "VIN", "Dealer", "PAIR", "PRIVATE_SEED"
)
TIS = TISRequest(18, "session", "18.0", "VIN", "date", "EN", "GTS", "Dealer", "D1")
NS = "http://www.openuri.org/"


def tis_reply(name="getHealthCheckResults", content="message"):
    return (
        f'<{name}Response xmlns="{NS}"><{name}Result><MilMessages><MilMessage>'
        "<MessageId>I1</MessageId><Title>Title</Title><MessageContentType>TEXT</MessageContentType>"
        f"<Message>{content}</Message></MilMessage></MilMessages></{name}Result></{name}Response>"
    ).encode()


def euro_reply(name="OnlineCheck", message="OnlineCheck message OK."):
    return (
        f'<{name}Result xmlns="{NS}"><MilMessages><MilMessage><Message>{message}</Message>'
        f"</MilMessage></MilMessages></{name}Result>"
    ).encode()


def unlock_reply(code="000000", value="REMOTE_VALUE"):
    return (
        f"<milmessage><repairing-requests><requests><unlocking-content><return-code>"
        f"<level>1</level><value>{code}</value><comment>synthetic</comment></return-code>"
        f"<unlocking-value>{value}</unlocking-value></unlocking-content></requests>"
        "</repairing-requests></milmessage>"
    ).encode()


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class HTTP:
    def __init__(self, response=None, error=None, close_error=None):
        self.response = response or ServiceHTTPResponse(
            200, tis_reply(), "synthetic:server"
        )
        self.error, self.close_error = error, close_error
        self.requests = []
        self.closed = False

    def exchange(self, request, *, timeout, cancelled):
        assert 0 < timeout <= 600
        assert not cancelled()
        self.requests.append(request)
        if self.error:
            raise self.error
        return self.response

    def close(self):
        self.closed = True
        if self.close_error:
            raise self.close_error


UNSET = object()


class Web:
    def __init__(self, clock, *, fault=0):
        self.clock, self.fault = clock, fault
        self.calls = []
        self.closed = []
        self.url = URL
        self.value = ""
        self.result = UNSET
        self.duplicate = False
        self.busy = False
        self.ready = 4
        self.wrong_window = False
        self.close_error = False
        self.readback_bad = False
        self.wait_cancel: Callable[[], None] | None = None

    def call(self, name, cancelled):
        self.calls.append(name)
        if cancelled():
            raise InterruptedError("fake browser cancelled")
        if len(self.calls) == self.fault:
            raise OSError("fake browser primitive failed")

    def create_window(self, *, timeout, cancelled):
        self.call("create", cancelled)
        return "owned-browser"

    def navigate(self, window, url, *, timeout, cancelled):
        self.call("navigate", cancelled)
        self.url = url

    def snapshot(self, window, *, timeout, cancelled):
        self.call("snapshot", cancelled)
        fields = [DOMElement("textarea", name="ReproKeyRequest", value=self.value)]
        if self.duplicate:
            fields.append(fields[0])
        if self.result is not UNSET:
            assert self.result is None or isinstance(self.result, str)
            fields.append(
                DOMElement(
                    "input", element_id="result_code", value=self.result, kind="hidden"
                )
            )
        return BrowserSnapshot(
            "foreign" if self.wrong_window else window,
            self.url,
            self.busy,
            self.ready,
            tuple(fields),
        )

    def set_value(self, window, tag, name, value, *, timeout, cancelled):
        self.call("set-value", cancelled)
        assert (tag, name) == ("textarea", "ReproKeyRequest")
        assert ET.fromstring(value).tag == "ReproKeyRequest"
        self.value = "wrong" if self.readback_bad else value

    def wait(self, seconds, *, cancelled):
        self.call("wait", cancelled)
        self.clock.now += seconds
        if self.wait_cancel:
            self.wait_cancel()

    def close(self, window, *, timeout):
        assert timeout == 5
        self.closed.append(window)
        if self.close_error:
            raise OSError("fake close failed")


class Host:
    def __init__(self, clock, events=(), *, fault=0):
        self.clock, self.events, self.fault = clock, list(events), fault
        self.calls = []
        self.colors = []
        self.sounds = []
        self.closed = []
        self.close_error = False

    def call(self, name, cancelled):
        self.calls.append(name)
        if cancelled():
            raise InterruptedError("fake host cancelled")
        if len(self.calls) == self.fault:
            raise OSError("fake host failed")

    def cursor(self, *, timeout, cancelled):
        self.call("cursor", cancelled)
        return (100, 200)

    def create_window(self, title, message, *, fullscreen, topmost, timeout, cancelled):
        self.call("create", cancelled)
        assert fullscreen and topmost
        return "notice"

    def render(self, window, color, title, message, *, timeout, cancelled):
        self.call("render", cancelled)
        self.colors.append((color, self.clock.now))

    def beep(self, mode, frequency, duration_ms, *, timeout, cancelled):
        self.call("beep", cancelled)
        self.sounds.append((mode, frequency, duration_ms))
        if mode == 1:
            self.clock.now += duration_ms / 1000

    def poll_event(self, window, *, timeout, cancelled):
        self.call("poll", cancelled)
        self.clock.now += timeout
        return self.events.pop(0) if self.events else None

    def close(self, window, *, timeout):
        self.closed.append(window)
        if self.close_error:
            raise OSError("fake window close failed")


class NativeMarshallingTests(unittest.TestCase):
    def test_tis_versions_empty_id_rules_and_user_tables(self):
        old = (CalibrationID(1, ""), CalibrationID(73, ""), CalibrationID(5, "ID5"))
        for version in (12, 18):
            data = replace(
                TIS,
                product_version=version,
                user_type=0 if version == 12 else "Literal <User>",
                old_calibrations=old,
            )
            request = build_service_request("tis-check", data, endpoint=URL)
            root = ET.fromstring(request.body)
            entries = root.findall(f".//{{{NS}}}CalibrationDataType")
            self.assertEqual(len(entries), 0 if version == 12 else 2)
            self.assertIn(
                b"US Dealer" if version == 12 else b"Literal &lt;User&gt;", request.body
            )
        european = replace(TIS, product_version=12, european_user=True, user_type=101)
        self.assertIn(
            b"Independent Repairer",
            build_service_request("tis-check", european, endpoint=URL).body,
        )
        with self.assertRaises(ValueError):
            build_service_request(
                "tis-check", replace(TIS, user_type=101), endpoint=URL
            )

    def test_tis_save_exact_fields_and_input_escaping(self):
        data = replace(
            TIS,
            dealer_code="D<&",
            new_calibrations=(CalibrationID(7, "NEW"),),
            flash_success=True,
        )
        request = build_service_request("tis-save", data, endpoint=URL)
        self.assertEqual(request.action, NS + "saveEcuProgram")
        self.assertIn(b"<IsFlashSuccess>true</IsFlashSuccess>", request.body)
        self.assertIn(b"D&lt;&amp;", request.body)
        self.assertEqual(dict(request.connector_properties)["Timeout"], "30000")
        self.assertEqual(dict(request.connector_properties)["ConnectTimeout"], "\x04")
        with self.assertRaises(ValueError):
            build_service_request(
                "tis-save",
                replace(data, old_calibrations=(CalibrationID(-1, "bad"),)),
                endpoint=URL,
            )

    def test_euro_online_save_and_proace_wire_shapes(self):
        for version in (12, 18):
            data = EuroRequest(
                version,
                "GTS",
                "Dealer",
                "date",
                100,
                "VIN",
                "time",
                (CalibrationID(1, "OLD"),),
                (CalibrationID(2, "NEW"),),
            )
            online = build_service_request("euro-online", data, endpoint=URL)
            self.assertEqual(online.action, NS + "OnlineCheck")
            self.assertNotIn(b"DealerCode", online.body)
            saved = build_service_request("euro-save", data, endpoint=URL)
            self.assertIn(b"<UserType>Authorized Repairer</UserType>", saved.body)
            self.assertIn(b"<CalibrationEvent>", saved.body)
            proace = ProaceRequest(
                version,
                "EN",
                "GUID",
                "date",
                "R1",
                "SW",
                "HW",
                "VIN",
                "A",
                ("1", "2"),
                ("FRAME1", "FRAME2"),
                "PRIVATE_SEED",
            )
            request = build_service_request("euro-key", proace, endpoint=URL)
            self.assertEqual(request.action, NS + "GetKeyForUnlockECUForPSA")
            self.assertIn(b"<proace_request>", request.body)
            self.assertIn(b"<unlock-seed>PRIVATE_SEED</unlock-seed>", request.body)
            self.assertIn(b"<unlock-request />", request.body)
            self.assertNotIn("PRIVATE_SEED", repr(request))
            empty = build_service_request(
                "euro-key", replace(proace, unlock_seed=""), endpoint=URL
            )
            self.assertIn(b"<unlock-seed />", empty.body)

    def test_tis_messages_and_operation_namespace_correlation(self):
        result = parse_service_response("tis-check", tis_reply(), source="synthetic")
        self.assertEqual(result.native_status, 1)
        self.assertEqual(result.messages[0].message_id, "I1")
        self.assertEqual(result.messages[0].message, "message")
        for payload in (
            tis_reply("saveEcuProgram"),
            tis_reply().replace(NS.encode(), b"https://wrong.invalid/"),
            tis_reply().replace(b"<Title>Title</Title>", b""),
            tis_reply(content="X" * 2501),
        ):
            with self.assertRaises(ValueError):
                parse_service_response("tis-check", payload, source="synthetic")

    def test_euro_exact_sentinels_and_server_key_value(self):
        for operation, name, message in [
            ("euro-online", "OnlineCheck", "OnlineCheck message OK."),
            ("euro-save", "saveEcuProgram", "Message received OK."),
        ]:
            self.assertEqual(
                parse_service_response(
                    operation, euro_reply(name, message), source="synthetic"
                ).native_status,
                1,
            )
            self.assertEqual(
                parse_service_response(
                    operation, euro_reply(name, "no"), source="synthetic"
                ).native_status,
                50,
            )
        result = parse_service_response("euro-key", unlock_reply(), source="synthetic")
        self.assertEqual(result.native_status, 1)
        assert result.unlock is not None
        self.assertEqual(result.unlock.value, "REMOTE_VALUE")
        denied = parse_service_response(
            "euro-key", unlock_reply("999999"), source="synthetic"
        )
        self.assertEqual(denied.native_status, 50)
        assert denied.unlock is not None
        self.assertIsNone(denied.unlock.value)
        for payload in (
            unlock_reply(value=""),
            unlock_reply(value="X" * 25),
            unlock_reply().replace(b"<level>1</level>", b""),
        ):
            with self.assertRaises(ValueError):
                parse_service_response("euro-key", payload, source="synthetic")

    def test_xml_security_depth_size_and_duplicate_fields(self):
        for payload in (
            b'<!DOCTYPE x [<!ENTITY x "a">]><x>&x;</x>',
            ("<!DOCTYPE x><x/>").encode("utf-16"),
            b"<x>" * 34 + b"</x>" * 34,
            b"x" * (1024 * 1024 + 1),
            tis_reply().replace(
                b"<Title>Title</Title>", b"<Title>A</Title><Title>B</Title>"
            ),
        ):
            with self.assertRaises(ValueError):
                parse_service_response("tis-check", payload, source="synthetic")
        for endpoint in (
            "https://user:password@example.invalid/",
            "https://example.invalid/#fragment",
            "file:///tmp/x",
            "https://exa mple.invalid/",
            "https://example.invalid/%0aInjected",
            "https://example.invalid%2eattacker.invalid/",
        ):
            with self.assertRaises(ValueError):
                build_service_request("tis-check", TIS, endpoint=endpoint)


class ServiceLifecycleTests(unittest.TestCase):
    def test_actual_marshalling_through_low_level_exchange(self):
        io = HTTP()
        client = ServiceClient(io)
        self.assertFalse(io.requests)
        result = client.run("tis-check", TIS, endpoint=URL)
        self.assertEqual(result.native_status, 1)
        self.assertIn(b"<milInput>", io.requests[0].body)
        self.assertEqual(client.state, "result")
        self.assertTrue(io.closed)
        with self.assertRaises(RuntimeError):
            client.run("tis-check", TIS, endpoint=URL)

    def test_faults_cleanup_and_primary_error(self):
        for error in (
            OSError("transport"),
            TimeoutError("timeout"),
            InterruptedError("cancel"),
        ):
            io = HTTP(error=error, close_error=OSError("cleanup"))
            client = ServiceClient(io)
            with self.assertRaises(type(error)) as raised:
                client.run("tis-check", TIS, endpoint=URL)
            self.assertIs(raised.exception, error)
            self.assertTrue(io.closed)
            self.assertEqual(client.state, "uncertain")
            self.assertIn("cleanup", raised.exception.__notes__[0])
        io = HTTP(close_error=OSError("cleanup"))
        client = ServiceClient(io)
        with self.assertRaises(OSError):
            client.run("tis-check", TIS, endpoint=URL)
        self.assertEqual(client.state, "uncertain")

    def test_cancel_before_exchange_and_during_blocked_primitive(self):
        io = HTTP()
        with self.assertRaises(InterruptedError):
            ServiceClient(io, cancelled=lambda: True).run(
                "tis-check", TIS, endpoint=URL
            )
        self.assertFalse(io.requests)
        self.assertTrue(io.closed)
        clock = Clock()

        class WaitingHTTP(HTTP):
            def exchange(self, request, *, timeout, cancelled):
                clock.now += timeout + 1
                self.assert_stopped = cancelled()
                raise TimeoutError("bounded fake lost reply")

        io = WaitingHTTP()
        with self.assertRaises(TimeoutError):
            ServiceClient(io, clock=clock).run("tis-check", TIS, endpoint=URL)
        self.assertTrue(io.assert_stopped)
        self.assertTrue(io.closed)

    def test_soap_fault_and_failed_http_cannot_become_success(self):
        fault = b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>Server</faultcode><faultstring>Denied</faultstring></s:Fault></s:Body></s:Envelope>'
        result = ServiceClient(HTTP(ServiceHTTPResponse(500, fault, "synthetic"))).run(
            "tis-check", TIS, endpoint=URL
        )
        self.assertEqual(result.native_status, 3)
        for status in (401, 403, 500):
            io = HTTP(ServiceHTTPResponse(status, tis_reply(), "synthetic"))
            with self.assertRaises(ServiceError):
                ServiceClient(io).run("tis-check", TIS, endpoint=URL)
            self.assertTrue(io.closed)


class RKSTests(unittest.TestCase):
    def access(self, **options):
        clock = Clock()
        browser = Web(clock)
        access = RKSAccess(browser, clock=clock, **options)
        access.set_data(DATA)
        return access, browser, clock

    def test_wrapper_store_export_import_and_preserve_existing_source(self):
        access = RKSAccess()
        with self.assertRaises(ServiceError) as error:
            access.xml()
        self.assertEqual(error.exception.status, 1)
        access.set_data(DATA)
        with tempfile.TemporaryDirectory() as directory:
            export = Path(directory) / "nested" / "request.xml"
            access.export_data(export)
            original = export.read_bytes()
            self.assertTrue(
                original.startswith(b'<?xml version="1.0" encoding="UTF-8"?>\r\n')
            )
            self.assertEqual(os.stat(export).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                access.export_data(export)
            self.assertEqual(export.read_bytes(), original)
            keyfile = Path(directory) / "key.xml"
            keyfile.write_bytes(b"<Signature>" + b"K" * 512 + b"</Signature>")
            key = access.import_key(keyfile)
            self.assertEqual(key.value, "K" * 512)
            self.assertNotIn("K" * 512, repr(key))
            self.assertEqual(
                keyfile.read_bytes(), b"<Signature>" + b"K" * 512 + b"</Signature>"
            )
            with self.assertRaises(ServiceError) as error:
                access.import_key(Path(directory) / "missing")
            self.assertEqual(error.exception.status, 7)
        with self.assertRaises(ValueError):
            access.import_key("/dev/null")

    def test_signature_native_statuses_and_no_fabricated_key(self):
        for payload, status in [
            (b"<wrong/>", 8),
            (b"<Signature>x</Signature>", 9),
            (b"<Signature>" + b"!" * 512 + b"</Signature>", 10),
            (b"<Signature>" + b"A" * 512 + b"<x/></Signature>", 8),
        ]:
            with self.assertRaises(ServiceError) as error:
                import_repro_key(payload, source="synthetic")
            self.assertEqual(error.exception.status, status)

    def test_browser_handoff_exact_paste_and_watching_status(self):
        access, browser, _ = self.access()
        self.assertFalse(browser.calls)
        self.assertEqual(access.request(URL), "owned-browser")
        self.assertEqual(browser.value.encode(), rks_xml(DATA))
        self.assertEqual(access.state, "awaiting-result")
        self.assertEqual(access.watch().native_status, 12)
        browser.result = None
        self.assertEqual(access.watch().native_status, 11)
        browser.result = "not-zero"
        self.assertEqual(access.watch().native_status, 12)
        browser.result = "0"
        self.assertEqual(access.watch().native_status, 0)
        self.assertEqual(access.state, "approved")
        browser.result = "other"
        self.assertEqual(access.watch().native_status, 12)
        self.assertEqual(access.state, "awaiting-result")
        with self.assertRaises(RuntimeError):
            access.set_data(DATA)
        access.close()
        access.close()
        self.assertEqual(browser.closed, ["owned-browser"])

    def test_every_request_primitive_fault_closes_only_owned_window(self):
        for fault in range(1, 6):
            with self.subTest(fault=fault):
                access, browser, _ = self.access()
                browser.fault = fault
                with self.assertRaises(OSError):
                    access.request(URL)
                self.assertEqual(
                    browser.closed, [] if fault == 1 else ["owned-browser"]
                )
                self.assertEqual(access.state, "uncertain")

    def test_url_dom_identity_duplicate_readback_and_stale_result_fail_closed(self):
        for option in ("wrong_window", "duplicate", "readback_bad", "stale"):
            access, browser, _ = self.access()
            if option == "stale":
                browser.result = "0"
            else:
                setattr(browser, option, True)
            with self.assertRaises(ServiceError):
                access.request(URL)
            self.assertEqual(browser.closed, ["owned-browser"])
        access, browser, _ = self.access()
        access.request(URL)
        browser.url = "https://example.invalid.attacker.invalid/result"
        with self.assertRaises(ServiceError):
            access.watch()
        self.assertEqual(browser.closed, ["owned-browser"])

    def test_wait_cancellation_deadline_and_close_retry(self):
        access, browser, _ = self.access(timeout=0.2)
        browser.busy = True
        with self.assertRaises(TimeoutError):
            access.request(URL)
        self.assertEqual(browser.closed, ["owned-browser"])
        stopped = False
        access, browser, _ = self.access(cancelled=lambda: stopped)
        browser.busy = True

        def stop():
            nonlocal stopped
            stopped = True

        browser.wait_cancel = stop
        with self.assertRaises(InterruptedError):
            access.request(URL)
        self.assertEqual(browser.closed, ["owned-browser"])
        access, browser, _ = self.access()
        browser.fault, browser.close_error = 2, True
        with self.assertRaises(OSError) as error:
            access.request(URL)
        self.assertIn("cleanup", error.exception.__notes__[0])
        self.assertEqual(access.window, "owned-browser")
        browser.close_error = False
        access.close()
        self.assertIsNone(access.window)

    def test_watch_cancellation_and_invalid_clock_release_owned_window(self):
        stopped = False
        access, browser, _ = self.access(cancelled=lambda: stopped)
        access.request(URL)
        stopped = True
        with self.assertRaises(InterruptedError):
            access.watch()
        self.assertEqual(browser.closed, ["owned-browser"])
        access, browser, _ = self.access()
        access.request(URL)
        access.clock = lambda: float("nan")
        with self.assertRaises(ValueError):
            access.watch()
        self.assertEqual(browser.closed, ["owned-browser"])


class NoticeTests(unittest.TestCase):
    CONFIG = NoticeConfig("Done", "Local completion", 0x112233, 0xAABBCC, 100, 2)

    def test_all_native_dismiss_events_and_exact_cursor_threshold(self):
        for kind in ("key", "left-click", "right-click", "close"):
            clock = Clock()
            host = Host(clock, [NoticeEvent("notice", kind)])
            notice = CompletionNotice(host, clock=clock)
            self.assertFalse(host.calls)
            self.assertEqual(notice.run(self.CONFIG), kind)
            self.assertEqual(host.colors[0][0], self.CONFIG.color2)
            self.assertEqual(host.closed, ["notice"])
            self.assertEqual(notice.state, "dismissed")
        clock = Clock()
        host = Host(
            clock,
            [
                NoticeEvent("notice", "move", 150, 250),
                NoticeEvent("notice", "move", 151, 200),
            ],
        )
        self.assertEqual(CompletionNotice(host, clock=clock).run(self.CONFIG), "move")
        self.assertEqual(host.calls.count("poll"), 2)

    def test_color_pulses_and_native_sound(self):
        for mode in (0, 1, 2):
            clock = Clock()
            host = Host(clock, [None] * 6 + [NoticeEvent("notice", "key")])
            CompletionNotice(host, clock=clock).run(
                replace(self.CONFIG, sound_mode=mode)
            )
            self.assertGreaterEqual(len(host.colors), 2)
            self.assertEqual(
                [color for color, _ in host.colors[:2]],
                [self.CONFIG.color2, self.CONFIG.color1],
            )
            if mode < 2:
                self.assertEqual(host.sounds[0], (mode, 1728, 100))
            else:
                self.assertFalse(host.sounds)
            if mode == 1:
                self.assertLess(host.colors[1][1], 0.15)

    def test_each_primitive_failure_cleanup_foreign_events_and_timeout(self):
        for fault in range(1, 6):
            clock = Clock()
            host = Host(clock, [NoticeEvent("notice", "key")], fault=fault)
            notice = CompletionNotice(host, clock=clock)
            config = replace(self.CONFIG, sound_mode=0)
            with self.assertRaises(OSError):
                notice.run(config)
            self.assertEqual(host.closed, [] if fault <= 2 else ["notice"])
            self.assertEqual(notice.state, "uncertain")
        clock = Clock()
        host = Host(clock, [NoticeEvent("foreign", "key")])
        with self.assertRaises(ValueError):
            CompletionNotice(host, clock=clock).run(self.CONFIG)
        self.assertEqual(host.closed, ["notice"])
        clock = Clock()
        host = Host(clock)
        with self.assertRaises(TimeoutError):
            CompletionNotice(host, clock=clock, timeout=0.1).run(self.CONFIG)
        self.assertEqual(host.closed, ["notice"])

    def test_cancel_cleanup_errors_and_invalid_configuration(self):
        clock = Clock()
        host = Host(clock)
        with self.assertRaises(InterruptedError):
            CompletionNotice(host, clock=clock, cancelled=lambda: True).run(self.CONFIG)
        self.assertFalse(host.calls)
        host = Host(clock, [NoticeEvent("notice", "key")])
        host.close_error = True
        notice = CompletionNotice(host, clock=clock)
        with self.assertRaises(OSError):
            notice.run(self.CONFIG)
        self.assertEqual(notice.state, "uncertain")
        self.assertEqual(notice.window, "notice")
        host.close_error = False
        notice.close()
        self.assertIsNone(notice.window)
        for config in (
            replace(self.CONFIG, interval_ms=0),
            replace(self.CONFIG, color1=-1),
        ):
            with self.assertRaises(ValueError):
                CompletionNotice(Host(clock), clock=clock).run(config)


if __name__ == "__main__":
    unittest.main()
