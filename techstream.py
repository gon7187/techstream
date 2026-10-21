"""Native resource workbench, offline diagnostic sessions and JLR USB probe."""

import argparse
import hashlib
import json
import math
import os
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("GdkPixbuf", "2.0")
# GI namespaces are supplied by runtime introspection.
from gi.repository import (
    Adw,  # type: ignore[reportAttributeAccessIssue]
    Gdk,  # type: ignore[reportAttributeAccessIssue]
    GdkPixbuf,  # type: ignore[reportAttributeAccessIssue]
    Gio,  # type: ignore[reportAttributeAccessIssue]
    GLib,  # type: ignore[reportAttributeAccessIssue]
    GObject,  # type: ignore[reportAttributeAccessIssue]
    Gtk,  # type: ignore[reportAttributeAccessIssue]
    Pango,  # type: ignore[reportAttributeAccessIssue]
)

from scripts.active_replay import (
    ActiveReplay,
    create_signed_active_examples,
)
from scripts.calibration_catalog import (
    CalibrationCatalog,
    SelectionContext,
    inspect_module,
    parse_address,
)
from scripts.cuw_services import RKSAccess, RKSData
from scripts.database_resources import RamReplay, create_ram_examples
from scripts.demo import create_demo
from scripts.demo_calibration import create_calibration_examples
from scripts.diagnostic_db import DiagnosticCatalog
from scripts.jlr import discover_jlr, probe_adapter
from scripts.local_files import read_regular
from scripts.monitor_replay import load_monitor_recording
from scripts.native_procedures import (
    create_example_files,
    open_utility,
    replay_script,
    replay_utility,
)
from scripts.native_replay import replay_profile
from scripts.offline_tools import (
    WORKFLOWS,
    copy_native,
    create_examples,
    example_snapshot,
    inspect_path,
    run_example,
)
from scripts.pid_catalog import DEFAULT_ROOT
from scripts.plot import sample_chart
from scripts.profiles import VehicleCatalog
from scripts.programming_replay import (
    create_programming_examples,
    load_programming_replay,
)
from scripts.recorder_replay import (
    create_recorder_examples,
    replay_recorder,
    save_recorder_dm,
)
from scripts.script_vm import parse_object
from scripts.service_replay import ServiceReplay, create_demo_service_capture
from scripts.session_cli import parse_pids, replay_session, save_report
from scripts.snapshot import TableFile
from scripts.snapshot import dumps as dump_snapshot
from scripts.snapshot import parse as parse_snapshot
from scripts.support import correspondence_rows, word
from scripts.text_resources import (
    UtilityTextResources,
    ViewerHelpResources,
    create_active_text_examples,
    create_utility_group_text_examples,
)
from scripts.toyota_workflows import create_example_files as create_workflow_examples
from scripts.toyota_workflows import replay_workflow
from scripts.utility import native_utility_screen, replay_native_utility
from scripts.workbench import (
    CatalogIndex,
    catalog_roots,
    export_csv,
    load_saved,
    measurement_text,
    save_saved,
    usb_devices,
)

PROJECT = Path(__file__).resolve().parent
REGIONS = {"NA": "Северная Америка", "EU": "Европа", "JP": "Япония"}
DOCUMENTS = {
    "Начало работы": "getting-started.md",
    "Воспроизведение сеанса": "offline-diagnostics.md",
    "Проверка оборудования": "hardware-validation.md",
    "Протокол Mongoose": "mongoose-protocol.md",
    "MongoosePro JLR: USB": "jlr-native.md",
    "Базы систем и ошибок": "ddb-format.md",
    "Выбор автомобиля": "vehicle-selection.md",
    "Процедуры обслуживания": "utility-runtime.md",
    "Сценарии и библиотеки": "script-libraries.md",
    "Снимки данных": "snapshot-format.md",
    "Подготовка калибровок": "programming.md",
    "Этапы программирования по записи": "programming-replay.md",
    "Активные тесты по записи": "active-replay.md",
    "Сервисные обращения по записи": "service-replay.md",
    "Бортовой регистратор": "drive-recorder.md",
    "Воспроизведение регистратора": "recorder-replay.md",
    "Протокол Toyota": "toyota-session.md",
    "Каналы MongoosePro JLR": "jlr-channels.md",
    "Записи выбранной системы": "native-replay.md",
    "Журнал связи": "communication-log.md",
    "Готовность по базе": "readiness.md",
    "Таблицы калибровки": "calibration-catalog.md",
    "Граница полного порта": "full-port.md",
}
CSS = b"""
.sidebar { background: #192635; color: #e1e8f0; }
.sidebar row { color: #d1dbe6; border-radius: 8px; margin: 3px 10px; }
.sidebar row.active { background: #345574; color: white; }
.sidebar row:hover { background: #2a4056; }
.brand { font-size: 25px; font-weight: 800; letter-spacing: -0.5px; }
.sidebar .dim-label { color: #b1c1d1; opacity: 1; }
.workspace-title { font-size: 26px; font-weight: 750; }
.group-title { font-size: 21px; font-weight: 700; }
.group-list row { padding: 9px 10px; border-radius: 6px; margin: 2px 5px; }
.group-list row:selected { background: alpha(@accent_bg_color, 0.15); }
.group-list row:selected label { color: @window_fg_color; }
.status-pill { background: alpha(@warning_color, 0.13); color: @warning_color; border-radius: 14px; padding: 5px 12px; }
.source-path { font-size: 11px; }
.table-footer { padding: 10px 14px; border-top: 1px solid alpha(@window_fg_color, 0.10); }
.docs { padding: 16px; }
"""


def label(text="", css="", **kwargs):
    widget = Gtk.Label(label=text, xalign=0, **kwargs)
    if css:
        widget.add_css_class(css)
    return widget


def box(vertical=True, spacing=12, margin=0):
    widget = Gtk.Box(
        orientation=Gtk.Orientation.VERTICAL
        if vertical
        else Gtk.Orientation.HORIZONTAL,
        spacing=spacing,
    )
    for edge in ("top", "bottom", "start", "end"):
        getattr(widget, f"set_margin_{edge}")(margin)
    return widget


class Parameter(GObject.Object):
    def __init__(self, record):
        super().__init__()
        self.record = record


class Catalog(Adw.Application):
    def __init__(
        self,
        root: Path,
        smoke_test: bool,
        state_path: Path,
        demo=False,
        replay_path=None,
        smoke_compact=False,
    ):
        super().__init__(
            application_id="local.techstream.Workbench",
            flags=Gio.ApplicationFlags.NON_UNIQUE,
        )
        self.root = root
        self.demo = demo
        self.replay_path = replay_path
        self.smoke_test = smoke_test
        self.smoke_compact = bool(smoke_compact)
        self.state_path = state_path
        self.exit_code = 0
        self.index: CatalogIndex | None = None
        self.selected_group: str | None = None
        self.records: list[dict[str, str]] = []
        self.saved: dict[str, list[str]] = {}
        self.saved_error = ""
        self.generation = 0
        self.closed = False
        self.saved_only = False
        self.changing_saved = False
        self.smoke_stage = 0
        self.diagnostics = None
        self.diagnostic_database = None
        self.diagnostic_generation = 0
        self.diagnostics_loading = False
        self.adapter_busy = False
        self.adapter_result = None
        self.adapter_cancel = threading.Event()
        self.adapter_thread = None
        self.session_busy = False
        self.session_report = None
        self.session_source = None
        self.session_cancel = threading.Event()
        self.session_thread = None
        self.offline_busy = False
        self.offline_report = None
        self.offline_source = None
        self.offline_sources: tuple[Path, ...] = ()
        self.offline_cancel = threading.Event()
        self.offline_thread = None
        self.vehicle_catalog = None
        self.vehicle_generation = 0
        self.vehicle_thread = None
        self.vehicle_loading = False
        self.utility_ui = None
        self.active_session = None
        self.active_sources: tuple[Path, ...] = ()
        self.active_tests: tuple[dict, ...] = ()
        self.active_initial = None
        try:
            self.saved = load_saved(state_path)
        except (OSError, ValueError, UnicodeError) as exc:
            self.saved_error = str(exc)
        self.connect("activate", self.activate_window)
        self.connect("shutdown", self.on_shutdown)

    def on_shutdown(self, *_args):
        self.closed = True
        self.adapter_cancel.set()
        self.session_cancel.set()
        self.offline_cancel.set()
        if self.adapter_thread is not None:
            self.adapter_thread.join()
        if self.session_thread is not None:
            self.session_thread.join()
        if self.offline_thread is not None:
            self.offline_thread.join()
        if self.vehicle_thread is not None:
            self.vehicle_thread.join()

    def activate_window(self, *_args):
        if hasattr(self, "window"):
            self.window.present()
            return
        provider = Gtk.CssProvider()
        provider.load_from_data(CSS)
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )
        self.window = Adw.ApplicationWindow(
            application=self, title="Techstream", default_width=1340, default_height=820
        )
        self.window.set_size_request(580, 500)
        if self.smoke_compact:
            # The compact variant drives the same flow in the collapsed layout.
            self.window.set_default_size(900, 700)
        self.toast_overlay = Adw.ToastOverlay()
        self.window.set_content(self.toast_overlay)
        self.nav_buttons = []
        self.layout = Adw.OverlaySplitView(
            min_sidebar_width=210,
            max_sidebar_width=210,
            sidebar_width_unit=Adw.LengthUnit.PX,
        )
        self.toast_overlay.set_child(self.layout)
        self.layout.set_sidebar(self.build_sidebar())
        self.pages = Gtk.Stack(hexpand=True, vexpand=True)
        self.layout.set_content(self.pages)
        self.pages.add_named(self.build_catalog(), "catalog")
        self.pages.add_named(self.build_adapter(), "adapter")
        self.pages.add_named(self.build_docs(), "docs")
        self.pages.add_named(self.build_diagnostics(), "diagnostics")
        self.pages.add_named(self.build_session(), "session")
        self.pages.add_named(self.build_offline(), "offline")
        self.pages.add_named(self.build_vehicle(), "vehicle")
        self.pages.add_named(self.build_programming(), "programming")
        compact = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 1100px"))
        for split in (self.layout, self.catalog_split):
            compact.add_setter(split, "collapsed", True)
        for button in [*self.nav_buttons, self.groups_button]:
            compact.add_setter(button, "visible", True)
        self.window.add_breakpoint(compact)
        self.breakpoint_focus = None
        self.layout.connect("notify::collapsed", self.remember_breakpoint_focus)
        self.window.connect("notify::focus-widget", self.restore_breakpoint_focus)
        self.pages.connect("notify::visible-child-name", self.clear_breakpoint_focus)
        for name, callback, keys in (
            ("search", lambda *_: self.focus_search(False), ["<Primary>f"]),
            ("groups", lambda *_: self.focus_search(True), ["<Primary>g"]),
            ("export", self.export_dialog, ["<Primary>e"]),
            ("reload", lambda *_: self.load_catalog(), ["<Primary>r"]),
            ("quit", lambda *_: self.quit(), ["<Primary>q"]),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)
            self.set_accels_for_action(f"app.{name}", keys)
        self.configure_sources(self.root)
        self.select_navigation(self.navigation.get_row_at_index(0))
        self.window.present()
        self.load_catalog()
        if self.replay_path is not None and not self.smoke_test:
            self.select_navigation(self.navigation.get_row_at_index(5))
            self.start_session(self.replay_path)
        if self.saved_error:
            self.toast(
                f"Не удалось прочитать избранное: {self.state_path}. Файл сохранён."
            )
        if self.smoke_test:
            GLib.timeout_add_seconds(30, self.smoke_timeout)

    def build_sidebar(self):
        sidebar = box(spacing=0)
        sidebar.set_size_request(210, -1)
        sidebar.add_css_class("sidebar")
        brand = box(margin=24, spacing=3)
        brand.append(label("Techstream", "brand"))
        brand.append(label("Toyota / Lexus", "dim-label"))
        sidebar.append(brand)
        self.navigation = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.navigation.add_css_class("navigation-sidebar")
        for title, icon in (
            ("Параметры", "view-list-symbolic"),
            ("Избранное", "starred-symbolic"),
            ("Адаптер", "network-wired-symbolic"),
            ("Документация", "help-browser-symbolic"),
            ("Системы и ошибки", "dialog-warning-symbolic"),
            ("Сеанс диагностики", "media-playback-start-symbolic"),
            ("Без автомобиля", "document-open-symbolic"),
            ("Автомобиль", "find-location-symbolic"),
            ("Калибровки", "document-send-symbolic"),
        ):
            row = Adw.ActionRow(title=title, activatable=True)
            row.add_prefix(Gtk.Image.new_from_icon_name(icon))
            self.navigation.append(row)
        self.navigation.connect("row-activated", self.navigate)
        sidebar.append(
            Gtk.ScrolledWindow(
                child=self.navigation,
                vexpand=True,
                hscrollbar_policy=Gtk.PolicyType.NEVER,
            )
        )
        footer = box(margin=24, spacing=8)
        footer.set_vexpand(False)
        footer.set_valign(Gtk.Align.END)
        footer.append(label("Офлайн-режим", "heading"))
        footer.append(
            label(
                "Учебные данные\nАвтомобиль не подключён"
                if self.demo
                else "Локальные ресурсы\nБез внешних сервисов",
                "dim-label",
                wrap=True,
            )
        )
        about = Gtk.Button(label="О приложении", halign=Gtk.Align.START)
        about.add_css_class("flat")
        about.connect("clicked", self.show_about)
        footer.append(about)
        sidebar.append(footer)
        return sidebar

    def header(self, title):
        bar = Adw.HeaderBar()
        bar.set_title_widget(label(title, "heading"))
        navigation = Gtk.Button(
            icon_name="open-menu-symbolic",
            tooltip_text="Разделы приложения",
            visible=False,
        )
        navigation.connect("clicked", lambda *_: self.layout.set_show_sidebar(True))
        self.nav_buttons.append(navigation)
        bar.pack_start(navigation)
        return bar

    def build_catalog(self):
        view = Adw.ToolbarView()
        bar = self.header("Рабочая область")
        self.groups_button = Gtk.Button(
            icon_name="view-list-symbolic",
            tooltip_text="Выбрать группу · Ctrl+G",
            visible=False,
        )
        self.groups_button.connect(
            "clicked", lambda *_: self.catalog_split.set_show_sidebar(True)
        )
        bar.pack_start(self.groups_button)
        status = Gtk.Button(label="Нет соединения")
        status.add_css_class("status-pill")
        status.set_tooltip_text("Состояние адаптера и диагностического соединения")
        status.connect(
            "clicked",
            lambda *_: self.select_navigation(self.navigation.get_row_at_index(2)),
        )
        bar.pack_start(status)
        source = Gtk.Button(
            icon_name="folder-open-symbolic", tooltip_text="Выбрать каталог данных"
        )
        source.connect("clicked", self.open_source)
        bar.pack_end(source)
        view.add_top_bar(bar)
        page = box(spacing=16, margin=22)
        view.set_content(page)
        heading = box(vertical=False, spacing=16)
        titles = box(spacing=5)
        titles.set_hexpand(True)
        self.page_title = label("Параметры", "workspace-title")
        titles.append(self.page_title)
        self.source_summary = label(
            "Чтение локальных данных…", "dim-label", ellipsize=Pango.EllipsizeMode.END
        )
        titles.append(self.source_summary)
        heading.append(titles)
        self.region = Gtk.DropDown(valign=Gtk.Align.CENTER)
        self.region.set_tooltip_text("Регион исходных данных")
        self.region.connect("notify::selected", self.change_region)
        heading.append(self.region)
        page.append(heading)
        banner = Adw.Banner(
            title=(
                "Синтетические учебные данные. Автомобиль не подключён."
                if self.demo
                else "Автомобиль не подключён. Здесь отображаются справочные данные."
            ),
            revealed=True,
        )
        page.append(banner)
        panes = self.catalog_split = Adw.OverlaySplitView(
            vexpand=True,
            min_sidebar_width=220,
            max_sidebar_width=320,
            sidebar_width_unit=Adw.LengthUnit.PX,
            sidebar_width_fraction=0.28,
        )
        page.append(panes)
        groups = box(spacing=10)
        groups.set_size_request(220, -1)
        self.group_search = Gtk.SearchEntry(placeholder_text="Поиск группы…")
        self.group_search.set_tooltip_text("Поиск по имени и пути группы · Ctrl+G")
        self.group_search.connect("search-changed", self.filter_groups)
        groups.append(self.group_search)
        self.group_count = label("", "dim-label")
        groups.append(self.group_count)
        self.group_model = Gtk.StringList.new([])
        self.group_selection = Gtk.SingleSelection(
            model=self.group_model, autoselect=False, can_unselect=True
        )
        factory = Gtk.SignalListItemFactory()
        factory.connect("setup", self.group_setup)
        factory.connect("bind", self.group_bind)
        self.group_view = Gtk.ListView(
            model=self.group_selection, factory=factory, single_click_activate=True
        )
        self.group_view.connect("activate", self.activate_group)
        self.group_view.add_css_class("group-list")
        self.group_selection.connect("notify::selected-item", self.select_group)
        groups.append(
            Gtk.ScrolledWindow(
                child=self.group_view,
                vexpand=True,
                hscrollbar_policy=Gtk.PolicyType.NEVER,
            )
        )
        panes.set_sidebar(groups)
        details = box(spacing=12)
        details.set_margin_start(18)
        titlebar = box(vertical=False)
        group_titles = box(spacing=4)
        group_titles.set_hexpand(True)
        self.group_title = label(
            "Выберите группу", "group-title", ellipsize=Pango.EllipsizeMode.END
        )
        self.group_path = label("", "dim-label", ellipsize=Pango.EllipsizeMode.MIDDLE)
        group_titles.append(self.group_title)
        group_titles.append(self.group_path)
        titlebar.append(group_titles)
        self.favorite = Gtk.ToggleButton(
            icon_name="non-starred-symbolic",
            tooltip_text="Добавить группу в избранное",
            sensitive=False,
            valign=Gtk.Align.CENTER,
        )
        self.favorite.connect("toggled", self.toggle_saved)
        titlebar.append(self.favorite)
        self.source_button = Gtk.Button(
            icon_name="dialog-information-symbolic",
            tooltip_text="Путь и SHA-256 исходного файла",
            sensitive=False,
            valign=Gtk.Align.CENTER,
        )
        self.source_button.connect("clicked", self.show_source)
        titlebar.append(self.source_button)
        details.append(titlebar)
        self.parameter_search = Gtk.SearchEntry(
            placeholder_text="Найти параметр или единицу…", hexpand=True
        )
        self.parameter_search.set_tooltip_text(
            "Поиск по словам, без учёта регистра · Ctrl+F"
        )
        self.parameter_search.connect("search-changed", self.filter_parameters)
        details.append(self.parameter_search)
        tools = box(vertical=False)
        self.all_groups = Gtk.CheckButton(label="Во всех группах", hexpand=True)
        self.all_groups.connect("toggled", self.filter_parameters)
        tools.append(self.all_groups)
        self.export_button = Gtk.Button(
            label="Экспорт CSV",
            tooltip_text="Сохранить все найденные параметры · Ctrl+E",
            sensitive=False,
        )
        self.export_button.connect("clicked", self.export_dialog)
        tools.append(self.export_button)
        details.append(tools)
        self.table_stack = Gtk.Stack(vexpand=True)
        details.append(self.table_stack)
        self.store = Gio.ListStore.new(Parameter)
        self.selection = Gtk.SingleSelection(model=self.store)
        self.table = Gtk.ColumnView(model=self.selection, show_row_separators=True)
        self.table.add_css_class("data-table")
        for title, field, expand in [
            ("Параметр", "name", True),
            ("Единица", "unit", False),
            ("Группа", "group", True),
        ]:
            column_factory = Gtk.SignalListItemFactory()
            column_factory.connect("setup", self.cell_setup)
            column_factory.connect("bind", self.cell_bind, field)
            column = Gtk.ColumnViewColumn.new(title, column_factory)
            column.set_expand(expand)
            column.set_resizable(True)
            column.set_fixed_width(105 if field == "unit" else 220)
            self.table.append_column(column)
        self.table.connect("activate", self.inspect_parameter)
        self.table_stack.add_named(
            Gtk.ScrolledWindow(
                child=self.table, hscrollbar_policy=Gtk.PolicyType.AUTOMATIC
            ),
            "table",
        )
        self.empty = Adw.StatusPage(
            title="Выберите группу",
            description="Выберите группу слева или найдите параметр во всех группах.",
        )
        self.empty.add_css_class("compact")
        self.table_stack.add_named(self.empty, "empty")
        self.loading = Adw.StatusPage(
            title="Чтение каталога",
            description="Файлы проверяются в фоне. Интерфейс остаётся доступным.",
        )
        self.loading.set_child(
            Gtk.Spinner(
                spinning=True,
                halign=Gtk.Align.CENTER,
                width_request=32,
                height_request=32,
            )
        )
        self.table_stack.add_named(self.loading, "loading")
        self.result_count = label("", "dim-label", wrap=True)
        self.result_count.add_css_class("table-footer")
        details.append(self.result_count)
        panes.set_content(details)
        return view

    def build_adapter(self):
        view = Adw.ToolbarView()
        bar = self.header("Адаптер")
        refresh = Gtk.Button(
            icon_name="view-refresh-symbolic", tooltip_text="Повторить осмотр USB"
        )
        refresh.connect("clicked", self.refresh_devices)
        bar.pack_end(refresh)
        view.add_top_bar(bar)
        page = box(margin=28, spacing=20)
        page.append(label("Подключение к автомобилю", "workspace-title"))
        page.append(
            label(
                "Подключите MongoosePro JLR по USB. Проверка адаптера прочитает его версию и серийный номер; автомобиль для этого не нужен.",
                "dim-label",
                wrap=True,
            )
        )
        self.adapter_status = Adw.StatusPage(
            icon_name="network-wired-disconnected-symbolic",
            title="Соединение не установлено",
        )
        page.append(self.adapter_status)
        self.adapter_probe = Gtk.Button(
            label="Проверить адаптер", halign=Gtk.Align.CENTER, sensitive=False
        )
        self.adapter_probe.add_css_class("suggested-action")
        self.adapter_probe.connect("clicked", self.check_adapter)
        page.append(self.adapter_probe)
        self.devices = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.devices.add_css_class("boxed-list")
        page.append(label("USB-устройства", "heading"))
        page.append(self.devices)
        page.append(
            label(
                "Нативное USB-подключение рассчитано на MongoosePro JLR с VID:PID 18e1:0104. SDD V168 — надпись на комплекте, она не определяет чип и прошивку устройства. Совместимость с системами Toyota проверяется отдельно.",
                "dim-label",
                wrap=True,
            )
        )
        view.set_content(
            Gtk.ScrolledWindow(child=page, hscrollbar_policy=Gtk.PolicyType.NEVER)
        )
        return view

    def build_docs(self):
        view = Adw.ToolbarView()
        view.add_top_bar(self.header("Документация"))
        page = box(margin=22)
        page.append(label("Руководства и ограничения", "workspace-title"))
        self.document = Gtk.DropDown.new_from_strings(list(DOCUMENTS))
        self.document.connect("notify::selected", self.read_document)
        page.append(self.document)
        self.doc_view = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
            left_margin=16,
            right_margin=16,
            top_margin=14,
            bottom_margin=14,
            pixels_below_lines=5,
            vexpand=True,
        )
        self.doc_view.add_css_class("docs")
        buffer = self.doc_view.get_buffer()
        buffer.create_tag(
            "heading",
            weight=700,
            scale=1.3,
            pixels_above_lines=14,
            pixels_below_lines=6,
        )
        buffer.create_tag("code", family="monospace", scale=0.9)
        page.append(Gtk.ScrolledWindow(child=self.doc_view, vexpand=True))
        view.set_content(page)
        self.read_document()
        return view

    def build_diagnostics(self):
        view = Adw.ToolbarView()
        view.add_top_bar(self.header("Системы и ошибки"))
        page = box(margin=22, spacing=14)
        page.append(
            label("Справочник диагностических систем", "workspace-title", wrap=True)
        )
        page.append(
            label(
                "Системы из базы выбранного региона. Выбор здесь открывает справочник; наличие блока в автомобиле определяется при диагностическом соединении.",
                "dim-label",
                wrap=True,
            )
        )
        self.system_choice = Gtk.DropDown(enable_search=True, sensitive=False)
        self.system_choice.set_tooltip_text("Выбрать систему и версию протокола")
        self.system_choice.connect("notify::selected", self.choose_diagnostic_system)
        page.append(self.system_choice)
        tools = box(vertical=False)
        self.diagnostic_kind = Gtk.DropDown.new_from_strings(
            [
                "Коды неисправностей",
                "Параметры стоп-кадра",
                "Текстовые состояния",
                "Единицы",
            ]
        )
        self.diagnostic_kind.connect("notify::selected", self.filter_diagnostics)
        tools.append(self.diagnostic_kind)
        self.diagnostic_search = Gtk.SearchEntry(
            placeholder_text="Код или описание…", hexpand=True
        )
        self.diagnostic_search.connect("search-changed", self.filter_diagnostics)
        tools.append(self.diagnostic_search)
        page.append(tools)
        self.diagnostic_status = label(
            "Выберите раздел, чтобы загрузить базы.", "dim-label", wrap=True
        )
        page.append(self.diagnostic_status)
        self.diagnostic_store = Gio.ListStore.new(Parameter)
        table = Gtk.ColumnView(
            model=Gtk.SingleSelection(model=self.diagnostic_store),
            show_row_separators=True,
        )
        for title, field, expand in [
            ("Код / №", "code", False),
            ("Описание", "name", True),
            ("Примечание", "comment", True),
        ]:
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self.cell_setup)
            factory.connect("bind", self.cell_bind, field)
            column = Gtk.ColumnViewColumn.new(title, factory)
            column.set_expand(expand)
            column.set_resizable(True)
            column.set_fixed_width(110 if field == "code" else 300)
            table.append_column(column)
        table.connect("activate", self.inspect_diagnostic)
        page.append(Gtk.ScrolledWindow(child=table, vexpand=True))
        view.set_content(page)
        return view

    def build_session(self):
        view = Adw.ToolbarView()
        view.add_top_bar(self.header("Сеанс диагностики"))
        page = box(margin=22, spacing=16)
        page.append(label("Воспроизведение диагностики", "workspace-title", wrap=True))
        page.append(
            label(
                "Откройте запись обмена или запустите учебный пример. Ответы разбираются локально; подключение к автомобилю не выполняется.",
                "dim-label",
                wrap=True,
            )
        )
        choices = box(vertical=False, spacing=10)
        self.session_mode = Gtk.DropDown.new_from_strings(
            [
                "Обзор систем",
                "График параметров",
                "Калибровки",
                "Мониторы OBD",
                "Поддерживаемые параметры",
                "Чтение параметров",
                "Сведения об автомобиле",
            ]
        )
        self.session_mode.set_hexpand(True)
        choices.append(self.session_mode)
        self.session_samples = Gtk.SpinButton.new_with_range(1, 10000, 1)
        self.session_samples.set_value(12)
        self.session_samples.set_tooltip_text("Число отсчётов для графика")
        self.session_samples.set_sensitive(False)
        self.session_mode.connect("notify::selected", self.session_mode_changed)
        choices.append(self.session_samples)
        page.append(choices)
        self.session_ecu = Gtk.Entry(
            placeholder_text="ЭБУ: имя из записи (пусто — первый в записи)",
            visible=False,
        )
        page.append(self.session_ecu)
        self.session_support_options = box(vertical=False, spacing=8)
        self.session_service = Gtk.DropDown.new_from_strings(
            [
                "01 · текущие параметры",
                "02 · стоп-кадр",
                "05 · датчики O₂ (старые протоколы)",
                "06 · мониторы",
                "09 · сведения",
            ]
        )
        self.session_service.set_hexpand(True)
        self.session_support_options.append(self.session_service)
        self.session_sensor = Gtk.SpinButton.new_with_range(1, 128, 1)
        self.session_sensor.set_tooltip_text(
            "Маска датчика для сервиса 05: 1, 2, 4, 8, 16, 32, 64 или 128"
        )
        self.session_support_options.append(self.session_sensor)
        self.session_support_options.set_visible(False)
        page.append(self.session_support_options)
        self.session_parameter_options = box(vertical=False, spacing=8)
        self.session_pids = Gtk.Entry(
            placeholder_text="PID, hex: 0C,0D (пусто — все поддерживаемые)",
            hexpand=True,
        )
        self.session_parameter_options.append(self.session_pids)
        self.session_freeze = Gtk.CheckButton(label="Стоп-кадр")
        self.session_parameter_options.append(self.session_freeze)
        self.session_parameter_options.set_visible(False)
        page.append(self.session_parameter_options)
        tools = box(vertical=False, spacing=10)
        self.session_example = Gtk.Button(label="Воспроизвести пример")
        self.session_example.add_css_class("suggested-action")
        self.session_example.connect(
            "clicked",
            self.start_example,
        )
        tools.append(self.session_example)
        self.session_open = Gtk.Button(label="Открыть запись")
        self.session_open.connect("clicked", self.open_session)
        tools.append(self.session_open)
        self.session_stop = Gtk.Button(label="Отмена", sensitive=False)
        self.session_stop.connect("clicked", lambda *_: self.session_cancel.set())
        tools.append(self.session_stop)
        page.append(tools)
        self.session_summary = label("Запись не загружена", "heading", wrap=True)
        page.append(self.session_summary)
        self.session_results = box(spacing=18)
        page.append(
            Gtk.ScrolledWindow(
                child=self.session_results,
                vexpand=True,
                hscrollbar_policy=Gtk.PolicyType.NEVER,
            )
        )
        self.session_export = Gtk.Button(
            label="Сохранить отчёт JSON", sensitive=False, halign=Gtk.Align.START
        )
        self.session_export.connect("clicked", self.export_session)
        page.append(self.session_export)
        view.set_content(page)
        return view

    def session_mode_changed(self, *_args):
        mode = self.session_mode.get_selected()
        self.session_samples.set_sensitive(mode == 1 and not self.session_busy)
        self.session_ecu.set_visible(mode != 0)
        self.session_support_options.set_visible(mode == 4)
        self.session_parameter_options.set_visible(mode == 5)

    def build_vehicle(self):
        view = Adw.ToolbarView()
        view.add_top_bar(self.header("Автомобиль"))
        page = box(margin=22)
        page.append(label("Выбор автомобиля и систем", "workspace-title", wrap=True))
        page.append(
            label(
                "Каталог выбранного региона. Модель, год и комплектация определяют перечень систем из базы; наличие блоков на автомобиле ещё не проверено.",
                "dim-label",
                wrap=True,
            )
        )
        self.vehicle_region = Gtk.DropDown()
        self.vehicle_region.set_tooltip_text("Регион каталога автомобилей")
        self.vehicle_region.connect("notify::selected", self.change_vehicle_region)
        page.append(self.vehicle_region)
        self.vehicle_status = label(
            "Откройте раздел, чтобы загрузить каталог.", wrap=True
        )
        page.append(self.vehicle_status)
        self.vehicle_filters = box(spacing=6)
        page.append(self.vehicle_filters)
        self.vehicle_variants = Gtk.DropDown(enable_search=True, sensitive=False)
        self.vehicle_variants.connect("notify::selected", self.choose_vehicle_variant)
        page.append(self.vehicle_variants)
        self.vehicle_options = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.vehicle_options.add_css_class("boxed-list")
        page.append(self.vehicle_options)
        self.vehicle_system_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        self.vehicle_system_list.add_css_class("boxed-list")
        page.append(Gtk.ScrolledWindow(child=self.vehicle_system_list, vexpand=True))
        self.vehicle_reload = Gtk.Button(
            label="Загрузить каталог заново", halign=Gtk.Align.START
        )
        self.vehicle_reload.connect("clicked", lambda *_: self.load_vehicle_catalog())
        page.append(self.vehicle_reload)
        view.set_content(
            Gtk.ScrolledWindow(child=page, hscrollbar_policy=Gtk.PolicyType.NEVER)
        )
        return view

    def change_vehicle_region(self, *_args):
        if not getattr(self, "configuring", True):
            self.region.set_selected(self.vehicle_region.get_selected())
            if self.vehicle_catalog is None:
                self.load_vehicle_catalog()

    def load_vehicle_catalog(self):
        if self.vehicle_loading or self.closed:
            return
        self.vehicle_generation += 1
        generation = self.vehicle_generation
        region = self.root.parent.name.removeprefix("Techstream_Data_")
        root = self.root.parent.parent / f"Techstream_DB_{region}"
        self.vehicle_loading = True
        self.vehicle_reload.set_sensitive(False)
        self.vehicle_status.set_text(
            f"Загрузка каталога: {REGIONS.get(region, region)}…"
        )

        def work():
            try:
                catalog, error = VehicleCatalog(root), ""
            except Exception as exc:  # noqa: BLE001 - background failures must be visible.
                catalog, error = None, str(exc)
            GLib.idle_add(self.vehicle_catalog_ready, generation, catalog, error)

        self.vehicle_thread = threading.Thread(target=work, name="techstream-vehicles")
        self.vehicle_thread.start()

    def vehicle_catalog_ready(self, generation, catalog, error):
        if self.closed or generation != self.vehicle_generation:
            return GLib.SOURCE_REMOVE
        self.vehicle_loading = False
        self.vehicle_reload.set_sensitive(True)
        self.vehicle_catalog = catalog
        self.vehicle_changing = True
        for widget in (
            self.vehicle_filters,
            self.vehicle_options,
            self.vehicle_system_list,
        ):
            while child := widget.get_first_child():
                widget.remove(child)
        self.vehicle_filter_choices = []
        if catalog is None or not catalog.vehicle_definitions:
            self.vehicle_status.set_text(
                f"Каталог автомобилей недоступен: {error or 'в базе нет определений автомобиля'}"
            )
            self.vehicle_variants.set_sensitive(False)
            self.vehicle_changing = False
            return GLib.SOURCE_REMOVE
        for category in catalog.categories:
            row = box(vertical=False, spacing=12)
            title = label(category["name"], hexpand=True)
            row.append(title)
            choice = Gtk.DropDown(enable_search=True, hexpand=True)
            row.append(choice)
            self.vehicle_filter_choices.append((category, choice))
            choice.connect(
                "notify::selected",
                self.filter_vehicles,
                len(self.vehicle_filter_choices) - 1,
            )
            self.vehicle_filters.append(row)
        self.vehicle_changing = False
        self.filter_vehicles(None, None, -1)
        if self.smoke_test and getattr(self, "offline_smoke_phase", "") == "vehicle":
            GLib.idle_add(self.check_vehicle_smoke)
        return GLib.SOURCE_REMOVE

    def filter_vehicles(self, _choice, _param, changed):
        if getattr(self, "vehicle_changing", True) or self.vehicle_catalog is None:
            return
        self.vehicle_changing = True
        candidates = self.vehicle_catalog.selectable_vehicles()
        for index, (category, choice) in enumerate(self.vehicle_filter_choices):
            slot = category["key"] - 1
            values = sorted({row["category_keys"][slot] for row in candidates})
            if index > changed:
                items = [
                    self.vehicle_catalog.collect_items.get(
                        (category["key"], key), {"name": "Не указано", "order": 0}
                    )
                    for key in values
                ]
                ordered = sorted(
                    zip(values, items),
                    key=lambda item: (item[1]["order"], item[1]["name"]),
                )
                choice.vehicle_keys = [item[0] for item in ordered]
                choice.set_model(
                    Gtk.StringList.new([item[1]["name"] for item in ordered])
                )
            if choice.get_selected() < len(choice.vehicle_keys):
                key = choice.vehicle_keys[choice.get_selected()]
                candidates = [
                    row for row in candidates if row["category_keys"][slot] == key
                ]
        self.vehicle_candidates = candidates
        self.vehicle_variants.set_model(
            Gtk.StringList.new(
                [
                    f"Вариант {index + 1} · запись {row['row'] + 1}"
                    for index, row in enumerate(candidates)
                ]
            )
        )
        self.vehicle_variants.set_sensitive(len(candidates) > 1)
        self.vehicle_variants.set_visible(len(candidates) > 1)
        self.vehicle_changing = False
        self.choose_vehicle_variant()

    def choose_vehicle_variant(self, *_args):
        if getattr(self, "vehicle_changing", True):
            return
        self.vehicle_answers = []
        self.resolve_vehicle_selection()

    def resolve_vehicle_selection(self):
        for widget in (self.vehicle_options, self.vehicle_system_list):
            while child := widget.get_first_child():
                widget.remove(child)
        selected = self.vehicle_variants.get_selected()
        if self.vehicle_catalog is None or selected >= len(self.vehicle_candidates):
            self.vehicle_status.set_text("Нет подходящих определений. Измените выбор.")
            return
        try:
            result = self.vehicle_catalog.resolve_vehicle(
                self.vehicle_candidates[selected]["row"], self.vehicle_answers
            )
            if result["status"] == "needs_option":
                self.vehicle_status.set_text(
                    "Уточните комплектацию. Для возврата измените модель или загрузите каталог заново."
                )
                for item in result["choices"]:
                    row = Adw.ActionRow(
                        title=GLib.markup_escape_text(
                            item["name"] or "Вариант без названия"
                        ),
                        activatable=True,
                    )
                    row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
                    row.connect("activated", self.choose_vehicle_option, item["key3"])
                    self.vehicle_options.append(row)
                return
            self.vehicle_selection = result
            systems = self.vehicle_catalog.vehicle_systems(result["vehicle_name_key"])
            self.vehicle_status.set_text(
                f"{result['name']} · систем в базе: {len(systems)}. Наличие блоков на автомобиле не подтверждено."
            )
            for system in systems:
                row = Adw.ActionRow(
                    title=GLib.markup_escape_text(system["name"] or system["file"]),
                    subtitle=GLib.markup_escape_text(system["file"]),
                )
                button = Gtk.Button(label="Открыть", valign=Gtk.Align.CENTER)
                button.connect("clicked", self.open_vehicle_system, system)
                row.add_suffix(button)
                actions = Gtk.MenuButton(label="Действия", valign=Gtk.Align.CENTER)
                popover = Gtk.Popover()
                choices = box(margin=8, spacing=4)
                for title, callback in (
                    ("Показать команды", self.choose_vehicle_function),
                    ("Воспроизвести запись…", self.choose_native_recording),
                    ("Выполнить процедуру…", self.choose_native_procedure),
                    ("Активные тесты по записи…", self.choose_active_recording),
                    ("Процедура Toyota по записи…", self.choose_workflow_recording),
                    ("Прочитать RAM по записи…", self.choose_ram_recording),
                ):
                    action = Gtk.Button(label=title)
                    action.connect(
                        "clicked",
                        lambda button, callback=callback, system=system, popover=popover: (
                            popover.popdown(),
                            callback(button, system),
                        ),
                    )
                    choices.append(action)
                popover.set_child(choices)
                actions.set_popover(popover)
                row.add_suffix(actions)
                self.vehicle_system_list.append(row)
        except (OSError, ValueError) as exc:
            self.vehicle_status.set_text(f"Выбор не завершён: {exc}")

    def choose_vehicle_option(self, _row, key):
        self.vehicle_answers.append(key)
        self.resolve_vehicle_selection()

    def open_vehicle_system(self, _button, system):
        if self.vehicle_catalog is None:
            return
        self.diagnostics_ready(self.diagnostic_generation, self.vehicle_catalog, "")
        index = next(
            (
                index
                for index, item in enumerate(self.vehicle_catalog.systems)
                if item["file"] == system["file"]
            ),
            None,
        )
        if index is None:
            self.vehicle_status.set_text(
                "Файл выбранной системы отсутствует в каталоге."
            )
            return
        self.system_choice.set_selected(index)
        self.select_navigation(self.navigation.get_row_at_index(4))

    def choose_vehicle_function(self, _button, system):
        catalog = self.vehicle_catalog
        if catalog is None:
            return
        try:
            functions = sorted(
                {
                    word(row, 2)
                    for row in correspondence_rows(catalog.management, 18, ())
                    if word(row, 0) == system["category"]
                }
            )
            if not functions:
                raise ValueError("В базе нет команд выбранной системы")
        except ValueError as exc:
            self.toast(str(exc))
            return
        choice = Gtk.DropDown.new_from_strings(
            [f"Функция 0x{value:04X}" for value in functions]
        )
        dialog = Adw.AlertDialog(
            heading="Команды системы",
            body="Выберите функцию из базы. Команды будут только прочитаны; отправка в автомобиль не выполняется.",
        )
        dialog.set_extra_child(choice)
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("open", "Показать команды")
        dialog.connect(
            "response",
            lambda _dialog, response: (
                self.inspect_vehicle_function(system, functions[choice.get_selected()])
                if response == "open"
                else None
            ),
        )
        dialog.present(self.window)

    def inspect_vehicle_function(self, system, function):
        catalog = self.vehicle_catalog
        if catalog is None or self.offline_busy:
            return
        vehicle_key = self.vehicle_selection["vehicle_name_key"]

        def operation():
            profile = catalog.build_profile(
                system["category"], vehicle_name_key=vehicle_key
            )
            records = profile.frame_records(function)
            return {
                "source": "native_database_unverified",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": f"{system['name']} · функция 0x{function:04X} · команд: {len(records)}",
                "result": {
                    "profile": profile.report(),
                    "commands": [
                        {
                            "request_hex": row.frame.request.hex(" "),
                            "receive_mask": row.frame.receive_mask.hex(" "),
                            "receive_check": row.frame.receive_check.hex(" "),
                            "provenance": row.provenance,
                        }
                        for row in records
                    ],
                },
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        sources = tuple(
            catalog.root / name
            for name in ("Toyota.ddb", "M_English.ddb", system["file"])
        )
        self.start_offline(operation=operation, sources=sources)

    def choose_native_recording(self, _button, system):
        catalog = self.vehicle_catalog
        if catalog is None:
            return
        try:
            functions = sorted(
                {
                    word(row, 2)
                    for row in correspondence_rows(catalog.management, 18, ())
                    if word(row, 0) == system["category"]
                }
            )
        except ValueError as exc:
            self.toast(str(exc))
            return
        fields = box(spacing=8)
        mode = Gtk.DropDown.new_from_strings(
            ["Готовность по базе", "Выбранные параметры", "Выбранная команда"]
        )
        fields.append(mode)
        ecu = Gtk.Entry(placeholder_text="ЭБУ: имя из записи (пусто — первый)")
        fields.append(ecu)
        signals = Gtk.Entry(
            placeholder_text="Ключи параметров, hex: 0001,0002", visible=False
        )
        fields.append(signals)
        function = Gtk.DropDown.new_from_strings(
            [f"Функция 0x{value:04X}" for value in functions]
        )
        function.set_visible(False)
        fields.append(function)
        mode.connect(
            "notify::selected",
            lambda *_: (
                signals.set_visible(mode.get_selected() == 1),
                function.set_visible(mode.get_selected() == 2),
            ),
        )
        dialog = Adw.AlertDialog(
            heading="Запись для выбранной системы",
            body="Откройте запись обмена и наблюдений о поддержке параметров. Ответы и длины читаются только из файла; автомобиль не подключается.",
        )
        dialog.set_extra_child(fields)
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("open", "Открыть запись…")

        def response(_dialog, name):
            if name != "open":
                return
            try:
                keys = (
                    tuple(
                        int(value, 16)
                        for value in signals.get_text().replace(",", " ").split()
                    )
                    if mode.get_selected() == 1
                    else ()
                )
                if mode.get_selected() == 2 and not functions:
                    raise ValueError("В базе нет команд выбранной системы")
                operation = ("readiness", "data_list", "command")[mode.get_selected()]
                function_id = functions[function.get_selected()] if functions else None
                chooser = Gtk.FileDialog(
                    title="Открыть запись обмена для выбранной системы"
                )

                def finished(file_dialog, result):
                    try:
                        path = file_dialog.open_finish(result).get_path()
                        if path is None:
                            raise ValueError("Выберите локальный файл")
                        if not self.closed:
                            self.start_native_recording(
                                Path(path),
                                system,
                                operation,
                                ecu.get_text().strip() or None,
                                function_id,
                                keys,
                            )
                    except GLib.Error as exc:
                        self.dialog_error(exc)
                    except (OSError, ValueError) as exc:
                        self.toast(str(exc))

                chooser.open(self.window, None, finished)
            except ValueError as exc:
                self.toast(f"Не удалось выбрать параметры: {exc}")

        dialog.connect("response", response)
        dialog.present(self.window)

    def start_native_recording(
        self,
        path,
        system,
        operation="readiness",
        ecu=None,
        function_id=None,
        signal_keys=(),
    ):
        catalog = self.vehicle_catalog
        if catalog is None or self.offline_busy or self.closed:
            return
        vehicle_key = self.vehicle_selection["vehicle_name_key"]

        def work():
            profile = catalog.build_profile(
                system["category"], vehicle_name_key=vehicle_key
            )
            report = replay_profile(
                profile,
                path,
                operation=operation,
                ecu=ecu,
                function_id=function_id,
                signal_keys=signal_keys,
                cancelled=self.offline_cancel.is_set,
            )
            title = {
                "readiness": "Готовность по базе",
                "data_list": "Чтение параметров",
                "command": "Выбранная команда",
            }[operation]
            report["summary"] = f"{title} · {system['name']} · запись воспроизведена"
            return report

        self.select_navigation(self.navigation.get_row_at_index(6))
        sources = (
            path,
            *(
                catalog.root / name
                for name in ("Toyota.ddb", "M_English.ddb", system["file"])
            ),
        )
        self.start_offline(path, operation=work, sources=sources)

    def utility_dialog(self, screen):
        state: dict = {"event": threading.Event(), "reply": None, "error": ""}
        GLib.idle_add(self.show_utility_screen, screen, state)
        deadline = screen["deadline_monotonic"]
        while not state["event"].wait(
            min(0.05, max(0.001, deadline - time.monotonic()))
        ):
            if time.monotonic() >= deadline:
                state["event"].set()
                GLib.idle_add(self.close_utility_screen)
                raise TimeoutError("Истекло время выполнения процедуры")
            if self.closed or self.offline_cancel.is_set():
                GLib.idle_add(self.close_utility_screen)
                raise InterruptedError("Процедура отменена")
        if self.closed or self.offline_cancel.is_set():
            raise InterruptedError("Процедура отменена")
        if state["error"]:
            raise ValueError(state["error"])
        return state["reply"]

    def choose_native_procedure(self, _button, system):
        if self.vehicle_catalog is None or self.offline_busy:
            return
        selection: dict = {
            "catalog": self.vehicle_catalog,
            "vehicle_key": self.vehicle_selection["vehicle_name_key"],
            "system": system,
            "key_library": None,
            "record_files": {},
        }
        controls = box(spacing=8)
        kind = Gtk.DropDown.new_from_strings(
            ["Сервисная процедура XML", "Диагностический сценарий CSDF"]
        )
        controls.append(kind)
        library = Gtk.Button(label="Библиотека для зашифрованного XML…")
        controls.append(library)
        translations = Gtk.Button(label="Файл перевода подписей XML…")
        controls.append(translations)
        attachment = Gtk.Button(label="Добавить файл данных для сценария…")
        controls.append(attachment)
        status = label("Дополнительные файлы не выбраны.", wrap=True)
        controls.append(status)

        def choose_file(_button, role):
            chooser = Gtk.FileDialog(title="Выбрать локальный файл")

            def finished(dialog, result):
                try:
                    path = dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    if role == "library":
                        selection["key_library"] = Path(path)
                        library.set_label(Path(path).name)
                    elif role == "translations":
                        selection["translation_file"] = Path(path)
                        translations.set_label(Path(path).name)
                    else:
                        name = Gtk.Entry(placeholder_text="Логическое имя записи в hex")
                        prompt = Adw.AlertDialog(
                            heading="Имя файла данных для сценария",
                            body="Введите точные байты логического имени, которое запрашивает сценарий. Кодировка и путь не подставляются автоматически.",
                        )
                        prompt.set_extra_child(name)
                        prompt.add_response("cancel", "Отмена")
                        prompt.add_response("add", "Добавить")

                        def attach(_prompt, response):
                            if response != "add":
                                return
                            try:
                                key = bytes.fromhex(name.get_text())
                                if (
                                    not key
                                    or len(key) > 255
                                    or b"\0" in key
                                    or key in selection["record_files"]
                                ):
                                    raise ValueError(
                                        "Нужно уникальное имя длиной 1–255 байт без NUL"
                                    )
                                selection["record_files"][key] = Path(path)
                                status.set_text(
                                    f"Файлов данных: {len(selection['record_files'])}"
                                )
                            except ValueError as exc:
                                self.toast(str(exc))

                        prompt.connect("response", attach)
                        prompt.present(self.window)
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        library.connect("clicked", choose_file, "library")
        attachment.connect("clicked", choose_file, "record")
        translations.connect("clicked", choose_file, "translations")
        dialog = Adw.AlertDialog(
            heading="Процедура выбранной системы",
            body="Выберите ресурс и запись обмена с явными наблюдениями драйвера и исходными значениями. Выполнение проходит локально; автомобиль не подключается.",
        )
        dialog.set_extra_child(controls)
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("open", "Выбрать ресурс…")

        def response(_dialog, name):
            if name != "open":
                return
            selection["kind"] = "utility" if kind.get_selected() == 0 else "script"
            chooser = Gtk.FileDialog(title="Открыть ресурс процедуры или сценария")

            def finished(file_dialog, result):
                try:
                    path = file_dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    selection["resource"] = Path(path)
                    if not self.closed:
                        self.load_procedure_resource(selection)
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        dialog.connect("response", response)
        dialog.present(self.window)

    @staticmethod
    def procedure_sources(selection, recording=None):
        catalog, system = selection["catalog"], selection["system"]
        paths = [
            selection["resource"],
            *(
                catalog.root / name
                for name in ("Toyota.ddb", "M_English.ddb", system["file"])
            ),
            *selection["record_files"].values(),
        ]
        if selection.get("key_library") is not None:
            paths.append(selection["key_library"])
        if selection.get("translation_file") is not None:
            paths.append(selection["translation_file"])
        if recording is not None:
            paths.append(recording)
        return tuple(paths)

    def load_procedure_resource(self, selection):
        def work():
            if selection["kind"] == "utility":
                result = open_utility(
                    selection["resource"], selection.get("key_library")
                ).inspect()
                functions = result["functions"]
                if not functions:
                    raise ValueError("В ресурсе нет функций процедуры")
            else:
                raw = read_regular(selection["resource"], limit=16 * 1024 * 1024)
                result, functions = parse_object(raw).inspect(), []
            return {
                "_procedure_state": {**selection, "functions": functions},
                "workflow": "procedure_definition",
                "source": "local_file_unverified",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": "Ресурс прочитан. Выберите функцию и запись для выполнения.",
                "result": result,
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(
            selection["resource"],
            operation=work,
            sources=self.procedure_sources(selection),
        )

    def choose_procedure_recording(self, *_args):
        selection = self.procedure_selection
        functions = selection["functions"]
        index = self.procedure_function.get_selected()
        if selection["kind"] == "utility" and index >= len(functions):
            self.toast("Выберите функцию из ресурса")
            return
        function_id = functions[index]["id"] if functions else None
        chooser = Gtk.FileDialog(title="Открыть запись выполнения процедуры")

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                if not self.closed:
                    self.start_procedure_recording(selection, Path(path), function_id)
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def start_procedure_recording(self, selection, recording, function_id=None):
        def work():
            profile = selection["catalog"].build_profile(
                selection["system"]["category"],
                vehicle_name_key=selection["vehicle_key"],
            )
            if selection["kind"] == "utility":
                if not isinstance(function_id, str):
                    raise ValueError("Выберите функцию из ресурса")
                report = replay_utility(
                    profile,
                    selection["resource"],
                    recording,
                    function_id=function_id,
                    dialog=self.utility_dialog,
                    cancelled=self.offline_cancel.is_set,
                    key_library=selection.get("key_library"),
                    translation_file=selection.get("translation_file"),
                    record_files=selection["record_files"] or None,
                )
            else:
                report = replay_script(
                    profile,
                    selection["resource"],
                    recording,
                    cancelled=self.offline_cancel.is_set,
                    record_files=selection["record_files"] or None,
                )
            report["workflow"] = "procedure_replay"
            status = {
                "completed": "Процедура выполнена по записи",
                "partial": "Процедура завершена с неполными данными",
                "failed": "Процедура не завершена",
                "cancelled": "Процедура отменена",
            }.get(report["status"], report["status"])
            report["summary"] = str(status) + (
                f": {report['error']['message']}" if report.get("error") else ""
            )
            return report

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(
            recording,
            operation=work,
            sources=self.procedure_sources(selection, recording),
        )
        if self.offline_busy:
            self.offline_status.set_text("Выполнение процедуры по записи…")

    def close_utility_screen(self):
        ui = self.utility_ui
        self.utility_ui = None
        if ui is not None:
            ui["closing"] = True
            ui["dialog"].close()
        return GLib.SOURCE_REMOVE

    def utility_reply(self, reply):
        ui = self.utility_ui
        if ui is None:
            return
        state = ui.get("request")
        if state is None or state["event"].is_set():
            return
        state["reply"] = reply
        state["event"].set()
        for _key, widget in ui["keys"]:
            widget.set_sensitive(False)
        for _out, _key, widget in ui["radios"]:
            widget.set_sensitive(False)
        for _key, widget in ui["checkboxes"]:
            widget.set_sensitive(False)

    def utility_values(self):
        ui = self.utility_ui
        if ui is None:
            return {}
        values = {out: key for out, key, widget in ui["radios"] if widget.get_active()}
        if ui["checkboxes"]:
            values["selected"] = [
                key for key, widget in ui["checkboxes"] if widget.get_active()
            ]
        return values

    def update_utility_keys(self):
        ui = self.utility_ui
        if ui is None:
            return
        pending = ui["request"]["event"].is_set()
        selected = any(widget.get_active() for _key, widget in ui["checkboxes"])
        for key, button in ui["keys"]:
            enabled = ui["key_enabled"].get(key, False)
            if ui["requires_selection"] and key == "next":
                enabled = selected
            button.set_sensitive(bool(enabled) and not pending)

    def show_utility_screen(self, screen, state):
        try:
            if self.closed or self.offline_cancel.is_set() or state["event"].is_set():
                state["event"].set()
                return GLib.SOURCE_REMOVE
            control_count = len(screen["keys"]) + sum(
                len(group["options"]) for group in screen["radios"]
            )
            control_count += len(screen.get("checkboxes", []))
            texts = [
                screen["title"],
                *(item["text"] for item in screen.get("checkboxes", [])),
                *(area["text"] for area in screen["areas"]),
                *(key["text"] for key in screen["keys"]),
                *(
                    option["text"]
                    for group in screen["radios"]
                    for option in group["options"]
                ),
            ]
            if control_count > 1024 or sum(map(len, texts)) > 256000:
                raise ValueError(
                    "Процедура содержит слишком много элементов или текста для диалога"
                )
            ui = self.utility_ui
            if ui is None:
                dialog = Adw.Dialog(content_width=640, content_height=500)
                view = Adw.ToolbarView()
                bar = Adw.HeaderBar()
                heading = label(wrap=True)
                bar.set_title_widget(heading)
                stop = Gtk.Button(label="Прервать")
                stop.connect("clicked", lambda *_: dialog.close())
                bar.pack_start(stop)
                view.add_top_bar(bar)
                body = box(margin=20)
                view.set_content(
                    Gtk.ScrolledWindow(
                        child=body, hscrollbar_policy=Gtk.PolicyType.NEVER
                    )
                )
                dialog.set_child(view)
                ui = {
                    "dialog": dialog,
                    "heading": heading,
                    "body": body,
                    "instance": None,
                    "closing": False,
                    "keys": [],
                    "radios": [],
                    "checkboxes": [],
                    "key_enabled": {},
                    "requires_selection": False,
                    "request": state,
                    "updating": False,
                }

                def closed(*_args):
                    if not ui["closing"]:
                        self.offline_cancel.set()
                        request = ui.get("request")
                        if request is not None:
                            request["event"].set()
                    if self.utility_ui is ui:
                        self.utility_ui = None
                    if (
                        not self.closed
                        and self.pages.get_visible_child_name() == "offline"
                    ):
                        self.window.set_focus(self.offline_open)

                dialog.connect_after("closed", closed)
                self.utility_ui = ui
                dialog.present(self.window)
            ui["request"] = state
            ui["heading"].set_text(screen["title"])
            ui["updating"] = True
            if ui["instance"] != screen["block_instance"]:
                ui["instance"] = screen["block_instance"]
                ui["progress_origin"] = (
                    GLib.get_monotonic_time() - screen["progress_elapsed_ms"] * 1000
                )
                body = ui["body"]
                while child := body.get_first_child():
                    body.remove(child)
                for area in screen["areas"]:
                    body.append(label(area["text"], wrap=True, selectable=True))
                ui["keys"], ui["radios"], ui["checkboxes"] = [], [], []
                for group in screen["radios"]:
                    first = None
                    for option in group["options"]:
                        choice = Gtk.CheckButton(
                            label=option["text"] or str(option["id"])
                        )
                        if first is not None:
                            choice.set_group(first)
                        else:
                            first = choice
                        ui["radios"].append((group["out"], int(option["id"]), choice))

                        def changed(widget, current=ui):
                            if widget.get_active() and not current["updating"]:
                                self.utility_reply({"display": self.utility_values()})

                        choice.connect("toggled", changed)
                        body.append(choice)
                for item in screen.get("checkboxes", []):
                    choice = Gtk.CheckButton(label=item["text"])
                    choice.set_active(item["selected"])
                    choice.set_sensitive(item["enabled"])
                    choice.connect("toggled", lambda *_: self.update_utility_keys())
                    ui["checkboxes"].append((item["id"], choice))
                    body.append(choice)
                progress = Gtk.ProgressBar(
                    show_text=True, visible=screen["progress"] is not None
                )
                ui["progress"] = progress
                body.append(progress)
                keys = Gtk.FlowBox(
                    selection_mode=Gtk.SelectionMode.NONE,
                    min_children_per_line=1,
                    max_children_per_line=3,
                    row_spacing=8,
                    column_spacing=8,
                )
                for key in screen["keys"]:
                    button = Gtk.Button(label=key["text"] or str(key["id"]))
                    button.connect(
                        "clicked",
                        lambda _button, key_id=key["id"]: self.utility_reply(
                            {"key": key_id, "values": self.utility_values()}
                        ),
                    )
                    ui["keys"].append((key["id"], button))
                    keys.append(button)
                body.append(keys)
            ui["key_enabled"] = {key["id"]: key["enabled"] for key in screen["keys"]}
            ui["requires_selection"] = bool(screen.get("requires_selection", False))
            self.update_utility_keys()
            selected = {group["out"]: group["value"] for group in screen["radios"]}
            for out, key_id, button in ui["radios"]:
                button.set_sensitive(True)
                button.set_active(selected.get(out) == key_id)
            ui["updating"] = False
            if (
                self.smoke_test
                and getattr(self, "offline_smoke_phase", "") == "utility_timeout"
            ):
                self.smoke_idle_screen_seen = True
            if screen["progress"] is not None:
                total = int(screen["progress"]["PROGRESSTIME"])
                interval = int(screen["progress"]["UPDATETIME"])
                if total <= 0 or interval <= 0:
                    raise ValueError("Некорректное время прогресса процедуры")

                def progress_tick():
                    if (
                        self.utility_ui is not ui
                        or ui["request"] is not state
                        or state["event"].is_set()
                    ):
                        return GLib.SOURCE_REMOVE
                    elapsed = max(
                        screen["progress_elapsed_ms"],
                        (GLib.get_monotonic_time() - ui["progress_origin"]) // 1000,
                    )
                    ui["progress"].set_fraction(min(1.0, elapsed / total))
                    ui["progress"].set_text(
                        f"{elapsed / 1000:.1f} / {total / 1000:.1f} с"
                    )
                    if elapsed >= screen["progress_elapsed_ms"] + interval:
                        if self.smoke_test:
                            self.smoke_progress_ticks = (
                                getattr(self, "smoke_progress_ticks", 0) + 1
                            )
                        self.utility_reply({"elapsed_ms": elapsed})
                        return GLib.SOURCE_REMOVE
                    return GLib.SOURCE_CONTINUE

                GLib.timeout_add(min(interval, 100), progress_tick)
            if (
                self.smoke_test
                and ui["keys"]
                and getattr(self, "offline_smoke_phase", "")
                in (
                    "utility_replay",
                    "utility_cancel",
                )
            ):
                GLib.timeout_add(100, self.interact_utility_smoke)
            if self.smoke_test and getattr(self, "offline_smoke_phase", "").startswith(
                "native_utility_"
            ):
                self.smoke_native_utility_screens = (
                    getattr(self, "smoke_native_utility_screens", 0) + 1
                )
                GLib.timeout_add(100, self.interact_native_utility_smoke)
        except Exception as exc:  # noqa: BLE001 - never strand the waiting procedure worker.
            state["error"] = str(exc) or type(exc).__name__
            state["event"].set()
            self.close_utility_screen()
        return GLib.SOURCE_REMOVE

    def choose_ram_recording(self, _button, system):
        if self.vehicle_catalog is None or self.offline_busy:
            return
        selection = {
            "catalog": self.vehicle_catalog,
            "vehicle_key": self.vehicle_selection["vehicle_name_key"],
            "system": system,
        }
        fields = box(spacing=8)
        address = Gtk.Entry(placeholder_text="Адрес RAM, hex")
        length = Gtk.Entry(placeholder_text="Количество байт, десятичное число")
        real = Gtk.CheckButton(label="Непосредственное чтение без кэша")
        for control in (address, length, real):
            fields.append(control)
        prompt = Adw.AlertDialog(
            heading="Чтение RAM по записи",
            body="Введите точный адрес и размер, соответствующие записи. Результат — исходные байты; значения параметров автомобиля не выводятся. Автомобиль не подключается.",
        )
        prompt.set_extra_child(fields)
        prompt.add_response("cancel", "Отмена")
        prompt.add_response("open", "Открыть запись…")

        def response(_prompt, name):
            if name != "open":
                return
            try:
                location, count, direct = (
                    int(address.get_text(), 16),
                    int(length.get_text()),
                    real.get_active(),
                )
                if not 0 <= location <= 0xFFFFFFFF or not 1 <= count <= (
                    32 * 1024 * 1024 if direct else 65535
                ):
                    raise ValueError(
                        "Адрес: 0…FFFFFFFF; размер: 1…65535 байт или до 32 МиБ без кэша"
                    )
            except ValueError as error:
                self.toast(str(error))
                return
            chooser = Gtk.FileDialog(title="Открыть запись чтения RAM")

            def finished(dialog, result):
                try:
                    path = dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    self.load_ram_recording(
                        selection,
                        Path(path),
                        address=location,
                        length=count,
                        real=direct,
                    )
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        prompt.connect("response", response)
        prompt.present(self.window)

    def load_ram_recording(self, selection, path, *, address, length, real=False):
        if self.offline_busy or self.closed:
            return
        catalog, system = selection["catalog"], selection["system"]
        sources = (path,) + tuple(
            catalog.root / name
            for name in ("Toyota.ddb", "M_English.ddb", system["file"])
        )

        def work():
            profile = catalog.build_profile(
                system["category"], vehicle_name_key=selection.get("vehicle_key")
            )
            raw = read_regular(path, limit=16 * 1024 * 1024)
            replay = RamReplay(profile, raw, cancelled=self.offline_cancel.is_set)
            data, failure = b"", None
            try:
                data = replay.reader.read(address, length, real=real)
                replay.assert_complete()
            except Exception as error:  # noqa: BLE001 - retain native partial replies.
                failure = {
                    "type": type(error).__name__,
                    "message": str(error),
                    "native_code": getattr(error, "code", None),
                }
            status = (
                "cancelled"
                if self.offline_cancel.is_set()
                else "failed"
                if failure
                else "ok"
            )
            return {
                "workflow": "ram_replay",
                "source": replay.replay.source,
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "status": status,
                "summary": {
                    "ok": "Исходные байты RAM прочитаны из записи",
                    "failed": "Чтение RAM по записи не завершено",
                    "cancelled": "Чтение RAM отменено",
                }[status],
                "recording_sha256": hashlib.sha256(raw).hexdigest(),
                "database_sha256": profile.database.sha256,
                "management_sha256": catalog.management.sha256,
                "result": {
                    "address": f"{address:08X}",
                    "requested_bytes": length,
                    "direct_read": real,
                    "received_bytes": len(data),
                    "data_hex": data.hex(" "),
                    "events_remaining": replay.replay.remaining,
                    "error": failure,
                    "transactions": [
                        {
                            "address": f"{row.query.frame.address:08X}",
                            "request_hex": row.query.request.hex(" "),
                            "response_hex": row.reply.hex(" "),
                            "native_status": row.status,
                            "provenance": row.query.selected.provenance,
                        }
                        for row in replay.reader.transactions
                    ],
                },
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(path, operation=work, sources=sources)

    def choose_workflow_recording(self, _button, system):
        if self.vehicle_catalog is None or self.offline_busy:
            return
        selection = {
            "catalog": self.vehicle_catalog,
            "vehicle_key": self.vehicle_selection["vehicle_name_key"],
            "system": system,
            "psd_module": None,
        }
        attach = Gtk.Button(label="Модуль PSD, если требуется…")

        def choose_module(*_args):
            chooser = Gtk.FileDialog(title="Выбрать исходный модуль PSD")

            def finished(dialog, result):
                try:
                    path = dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    selection["psd_module"] = Path(path)
                    attach.set_label(Path(path).name)
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        attach.connect("clicked", choose_module)
        prompt = Adw.AlertDialog(
            heading="Процедура Toyota по записи",
            body="Операция и её входные данные читаются из записи для выбранной системы. Выполняются сохранённые команды и ответы. Автомобиль не подключается.",
        )
        prompt.set_extra_child(attach)
        prompt.add_response("cancel", "Отмена")
        prompt.add_response("open", "Открыть запись…")

        def response(_prompt, name):
            if name != "open":
                return
            chooser = Gtk.FileDialog(title="Открыть запись процедуры Toyota")

            def finished(dialog, result):
                try:
                    path = dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    self.load_workflow_recording(selection, Path(path))
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        prompt.connect("response", response)
        prompt.present(self.window)

    def load_workflow_recording(self, selection, path):
        if self.offline_busy or self.closed:
            return
        catalog, system = selection["catalog"], selection["system"]
        sources = (path,) + tuple(
            catalog.root / name
            for name in ("Toyota.ddb", "M_English.ddb", system["file"])
        )
        if selection.get("psd_module") is not None:
            sources += (selection["psd_module"],)

        def work():
            profile = catalog.build_profile(
                system["category"], vehicle_name_key=selection.get("vehicle_key")
            )
            report = replay_workflow(
                profile,
                path,
                cancelled=self.offline_cancel.is_set,
                psd_module=selection.get("psd_module"),
            )
            report["workflow"] = "toyota_workflow"
            report["summary"] = {
                "ok": "Запись процедуры Toyota воспроизведена",
                "cancelled": "Процедура Toyota отменена",
                "failed": "Запись процедуры Toyota не завершена",
            }[str(report["status"])]
            return report

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(path, operation=work, sources=sources)

    def choose_active_recording(self, _button, system):
        if self.vehicle_catalog is None or self.offline_busy:
            return
        selection = {
            "catalog": self.vehicle_catalog,
            "vehicle_key": self.vehicle_selection["vehicle_name_key"],
            "system": system,
            "sa_library": None,
        }
        controls = box(spacing=8)
        key = Gtk.Button(label="Библиотека ключевых данных SA, если требуется…")
        controls.append(key)

        def choose_key(*_args):
            chooser = Gtk.FileDialog(title="Выбрать библиотеку ключевых данных SA")

            def finished(dialog, result):
                try:
                    path = dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    selection["sa_library"] = Path(path)
                    key.set_label(Path(path).name)
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        key.connect("clicked", choose_key)
        for role, title in (
            ("viewer", "База справки Viewer.ddb…"),
            ("help_language", "Языковой файл справки V_*.ddb…"),
        ):
            button = Gtk.Button(label=title)

            def choose_help(_button, role=role, button=button):
                chooser = Gtk.FileDialog(title="Выбрать файл справки")

                def finished(dialog, result):
                    try:
                        path = dialog.open_finish(result).get_path()
                        if path is None:
                            raise ValueError("Выберите локальный файл")
                        selection[role] = Path(path)
                        button.set_label(Path(path).name)
                    except GLib.Error as exc:
                        self.dialog_error(exc)
                    except (OSError, ValueError) as exc:
                        self.toast(str(exc))

                chooser.open(self.window, None, finished)

            button.connect("clicked", choose_help)
            controls.append(button)
        prompt = Adw.AlertDialog(
            heading="Активный тест по записи",
            body="Выберите запись для выбранной системы. Список тестов, исходные значения и доступные действия будут прочитаны из базы и наблюдений записи. Автомобиль не подключается.",
        )
        prompt.set_extra_child(controls)
        prompt.add_response("cancel", "Отмена")
        prompt.add_response("open", "Открыть запись…")

        def response(_prompt, name):
            if name != "open":
                return
            chooser = Gtk.FileDialog(title="Открыть запись активного теста")

            def finished(dialog, result):
                try:
                    path = dialog.open_finish(result).get_path()
                    if path is None:
                        raise ValueError("Выберите локальный файл")
                    if not self.closed:
                        self.load_active_recording(selection, Path(path))
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open(self.window, None, finished)

        prompt.connect("response", response)
        prompt.present(self.window)

    def load_active_recording(self, selection, recording):
        if self.offline_busy or self.closed:
            return
        catalog, system = selection["catalog"], selection["system"]
        sources = (
            recording,
            *(
                catalog.root / name
                for name in ("Toyota.ddb", "M_English.ddb", system["file"])
            ),
        )
        if selection.get("sa_library") is not None:
            sources += (selection["sa_library"],)
        for role in ("viewer", "help_language"):
            if selection.get(role) is not None:
                sources += (selection[role],)
        self.active_selection = selection
        self.active_recording_path = recording
        self.active_tests = ()
        self.active_choice.set_model(Gtk.StringList.new([]))
        self.active_initial = None
        self.active_arguments.set_visible(False)
        previous = self.active_session
        self.active_session = None

        def work():
            if previous is not None:
                previous.close()
            if bool(selection.get("viewer")) != bool(selection.get("help_language")):
                raise ValueError("Для справки выберите оба файла: Viewer.ddb и V_*.ddb")
            profile = catalog.build_profile(
                system["category"], vehicle_name_key=selection.get("vehicle_key")
            )
            session = ActiveReplay.load(
                recording,
                profile,
                cancelled=self.offline_cancel.is_set,
                sa_library=selection.get("sa_library"),
            )
            try:
                tests = session.available_tests()
            except Exception:
                session.close()
                raise
            return {
                "_active_state": (session, sources, tests),
                "workflow": "active_definition",
                "source": session.report()["source"],
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": "Выберите активный тест из наблюдавшегося списка.",
                "result": {"tests": list(tests)},
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(recording, operation=work, sources=sources)

    def initialize_active_test(self, *_args):
        session = self.active_session
        index = self.active_choice.get_selected()
        if session is None or self.offline_busy or index >= len(self.active_tests):
            return
        selected = self.active_tests[index]
        self.active_initial = None
        self.active_arguments.set_visible(False)
        self.active_selected = selected
        sources = self.active_sources

        def work():
            try:
                initial = session.initialize(
                    selected["signal_id"], family=selected["family"]
                )
                if self.active_selection.get("viewer") is not None:
                    broker = ViewerHelpResources.load(
                        self.active_selection["viewer"],
                        self.active_selection["help_language"],
                        cancelled=self.offline_cancel.is_set,
                    )
                    initial["help_resources"] = {
                        "details": broker.active_details(initial["control_value"]),
                        "instructions": broker.instruction_texts(initial["text_ids"]),
                    }
                if self.offline_cancel.is_set():
                    raise InterruptedError("Active initialization cancelled")
            except Exception as error:  # noqa: BLE001 - retain consumed probes and cleanup.
                self.active_session = None
                try:
                    session.close()
                except Exception as cleanup:  # noqa: BLE001
                    error = ExceptionGroup(
                        "Active initialization and cleanup", [error, cleanup]
                    )
                report = session.report()
                report.update(
                    workflow="active_initialization",
                    selected_test=selected,
                    status="cancelled" if self.offline_cancel.is_set() else "failed",
                    summary="Подготовка активного теста не завершена. Для повтора загрузите запись заново.",
                    error={"type": type(error).__name__, "message": str(error)},
                )
                return report
            return {
                "_active_initialization": initial,
                "workflow": "active_initialization",
                "source": session.report()["source"],
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": "Параметры теста прочитаны. Выберите действие или введите значение.",
                "result": initial,
            }

        self.start_offline(sources[0], operation=work, sources=sources)

    def fill_active_inputs(self, initial):
        self.active_initial = initial
        fields = initial["argument_fields"]
        self.active_display_index = self.active_button_index = None
        while child := self.active_arguments.get_first_child():
            self.active_arguments.remove(child)
        self.active_arguments.append(
            label(
                f"{initial['name']} · {initial['unit']} · диапазон {initial['minimum']}…{initial['maximum']}\nИсходное значение: {initial['initial_value']}",
                wrap=True,
            )
        )
        help_resources = initial.get("help_resources")
        if help_resources:
            details = Adw.ExpanderRow(title="Описание активного теста")
            contents = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
            contents.add_css_class("boxed-list")
            for output in help_resources["details"]["outputs"]:
                resource = output["resource"]
                if resource is not None:
                    text = label(resource["text"], wrap=True, selectable=True)
                    text.set_margin_start(12)
                    text.set_margin_end(12)
                    text.set_margin_top(8)
                    text.set_margin_bottom(8)
                    details.add_row(text)
            contents.append(details)
            host = Adw.ExpanderRow(title="Дополнительные подсказки")
            for role, title in (
                ("caution", "Предупреждение"),
                ("help", "Справка"),
                ("prohibition", "Ограничение"),
                ("info", "Информация"),
                ("comment", "Комментарий"),
            ):
                row = help_resources["instructions"][role]
                if row["status"] == "absent":
                    continue
                text = (
                    row["resource"]["text"]
                    if row["resource"]
                    else "Текст не найден в выбранных ресурсах"
                )
                host.add_row(
                    Adw.ActionRow(title=title, subtitle=GLib.markup_escape_text(text))
                )
            contents.append(host)
            self.active_arguments.append(contents)
        elif any(initial.get("text_ids", {}).values()):
            self.active_arguments.append(
                label(
                    "Подсказки этого теста пока недоступны; исходные ссылки сохранены в отчёте.",
                    "dim-label",
                    wrap=True,
                )
            )
        self.active_value = Gtk.Entry(
            text=str(initial["initial_value"]),
            placeholder_text="Значение команды, целое число",
        )
        self.active_value.connect(
            "changed", lambda *_: setattr(self, "active_display_index", None)
        )
        scalar_title = label("Значение команды", wrap=True)
        scalar_title.set_visible(fields["scalar"])
        self.active_value.set_visible(fields["scalar"])
        self.active_arguments.append(scalar_title)
        self.active_arguments.append(self.active_value)
        self.active_auxiliary = Gtk.Entry(
            text="0", placeholder_text="Дополнительный байт команды: 0…255"
        )
        self.active_auxiliary.set_tooltip_text("Дополнительный байт команды: 0…255")
        auxiliary_title = label("Дополнительный байт команды (0…255)", wrap=True)
        auxiliary_title.set_visible(fields["auxiliary"])
        self.active_auxiliary.set_visible(fields["auxiliary"])
        self.active_arguments.append(auxiliary_title)
        self.active_arguments.append(self.active_auxiliary)
        self.active_output_mask = Gtk.Entry(
            text="0", placeholder_text="Маска выходных битов, hex"
        )
        mask_title = label("Маска выходных битов, hex (по умолчанию 0)", wrap=True)
        mask_title.set_visible(fields["output_mask"])
        self.active_output_mask.set_visible(fields["output_mask"])
        self.active_arguments.append(mask_title)
        self.active_arguments.append(self.active_output_mask)
        for row in initial.get("routine_labels", []):
            self.active_arguments.append(label(row["text"], wrap=True))
        self.active_input = Gtk.Entry(
            placeholder_text=f"Байты ввода, hex (при заполнении: {initial.get('input_byte_count', 'по маске теста')} байт)"
        )
        self.active_input.set_visible(fields["bytes"])
        for row in initial.get("routine_inputs", []):
            self.active_arguments.append(label(row["text"], wrap=True))
        self.active_arguments.append(self.active_input)
        choices = Gtk.FlowBox(
            selection_mode=Gtk.SelectionMode.NONE,
            min_children_per_line=1,
            max_children_per_line=3,
            column_spacing=8,
            row_spacing=8,
        )
        self.active_native_buttons = []
        for kind, rows in (
            ("display", initial.get("displays", [])),
            ("routine", initial.get("routine_buttons", [])),
        ):
            for index, row in enumerate(rows):
                button = Gtk.Button(label=row["text"] or f"Действие {row['id']}")
                button.set_sensitive(
                    bool(row["enabled"]) if kind == "display" else True
                )

                def choose(_button, kind=kind, index=index, row=row):
                    if kind == "display":
                        self.active_value.set_text(str(row["press"]))
                        self.active_display_index = index
                    else:
                        self.active_button_index = index
                    self.active_choice_note.set_text(
                        f"Выбрано: {row['text'] or row['id']}"
                    )

                button.connect("clicked", choose)
                self.active_native_buttons.append(button)
                choices.append(button)
        self.active_arguments.append(choices)
        self.active_choice_note = label(
            "Можно ввести значение или выбрать действие из базы.", wrap=True
        )
        self.active_arguments.append(self.active_choice_note)
        self.active_execute = Gtk.Button(
            label="Воспроизвести активный тест", halign=Gtk.Align.START
        )
        self.active_execute.connect("clicked", self.run_active_test)
        self.active_arguments.append(self.active_execute)
        self.active_arguments.set_visible(True)

    def run_active_test(self, *_args):
        session, initial = self.active_session, self.active_initial
        if session is None or initial is None or self.offline_busy or self.closed:
            return
        fields = initial["argument_fields"]
        try:
            value = int(self.active_value.get_text())
            auxiliary = (
                int(self.active_auxiliary.get_text()) if fields["auxiliary"] else 0
            )
            raw = (
                bytes.fromhex(self.active_input.get_text()) if fields["bytes"] else b""
            )
            if not -0x80000000 <= value <= 0x7FFFFFFF or not 0 <= auxiliary <= 255:
                raise ValueError(
                    "Значение должно помещаться в signed32, дополнительный байт — в 0…255"
                )
            if (
                fields["scalar"]
                and not raw
                and not initial["minimum"] <= value <= initial["maximum"]
            ):
                raise ValueError("Значение должно попадать в диапазон выбранного теста")
            count = initial["input_byte_count"]
            if raw and len(raw) != count:
                raise ValueError(f"Требуется {count} байт ввода")
            arguments = {
                "value": value,
                "auxiliary": auxiliary,
                "display_index": self.active_display_index,
                "input_hex": raw.hex(),
                "button_index": self.active_button_index,
            }
            if fields["output_mask"]:
                output_mask = int(self.active_output_mask.get_text(), 16)
                if not 0 <= output_mask <= 0xFFFFFFFF:
                    raise ValueError(
                        "Маска должна попадать в диапазон 00000000…FFFFFFFF"
                    )
                arguments["output_mask"] = output_mask
        except ValueError as exc:
            message = str(exc)
            if "invalid literal" in message or "non-hexadecimal" in message:
                message = "Введите целые числа и корректные байты или маску в hex"
            self.toast(message)
            return
        selected, sources = self.active_selected, self.active_sources
        self.active_session = None

        def work():
            error = None
            try:
                session.run_test(
                    selected["signal_id"], arguments, family=selected["family"]
                )
            except Exception as exc:  # noqa: BLE001 - preserve native failure and recorded cleanup.
                error = exc
            finally:
                try:
                    session.close()
                except Exception as cleanup:  # noqa: BLE001 - a cleanup failure remains visible.
                    error = (
                        ExceptionGroup("Active test and cleanup", [error, cleanup])
                        if error is not None
                        else cleanup
                    )
            report = session.report()
            report["workflow"] = "active_replay"
            report["selected_test"] = selected
            if initial.get("help_resources"):
                report["help_resources"] = initial["help_resources"]
            report["status"] = (
                "cancelled"
                if self.offline_cancel.is_set()
                else "failed"
                if error is not None
                else "completed"
            )
            report["summary"] = {
                "completed": "Запись активного теста воспроизведена",
                "cancelled": "Активный тест отменён",
                "failed": "Запись активного теста не завершена",
            }[report["status"]]
            if error is not None:
                report["error"] = {"type": type(error).__name__, "message": str(error)}
            return report

        self.active_execute.set_sensitive(False)
        self.start_offline(sources[0], operation=work, sources=sources)

    def build_programming(self):
        view = Adw.ToolbarView()
        view.add_top_bar(self.header("Программирование по записи"))
        page = box(margin=22, spacing=12)
        page.append(
            label("Калибровка и записанные этапы", "workspace-title", wrap=True)
        )
        page.append(
            label(
                "Выберите калибровку CUW, запись этапа, таблицы выбора и исходные библиотеки. Выполнение использует только сохранённые действия и ответы. Автомобиль не подключается; библиотеки не запускаются.",
                "dim-label",
                wrap=True,
            )
        )
        self.programming_paths: dict[str, tuple[Path, ...]] = {
            "cuw": (),
            "context": (),
            "catalog": (),
            "modules": (),
            "attachments": (),
        }
        self.programming_session = None
        self.programming_session_sources: tuple[Path, ...] = ()
        self.programming_form = box(spacing=12)
        self.programming_attachment_entries = []
        self.programming_labels = {}
        for role, title in (
            ("cuw", "Калибровка CUW"),
            ("context", "Запись этапа программирования"),
            ("catalog", "Таблицы выбора INI"),
            ("modules", "Исходные библиотеки DLL"),
            ("attachments", "Добавить вложения, если требуются"),
        ):
            row = box(vertical=False, spacing=12)
            button = Gtk.Button(label=title + "…", hexpand=True)
            button.connect("clicked", self.choose_programming_files, role)
            row.append(button)
            self.programming_labels[role] = label("Не выбрано", wrap=True, hexpand=True)
            self.programming_labels[role].set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            row.append(self.programming_labels[role])
            if role == "attachments":
                clear = Gtk.Button(label="Очистить")
                clear.connect(
                    "clicked", lambda *_: self.set_programming_files("attachments", ())
                )
                row.append(clear)
            self.programming_form.append(row)
            if role == "attachments":
                self.programming_attachment_rows = Gtk.ListBox(
                    selection_mode=Gtk.SelectionMode.NONE
                )
                self.programming_attachment_rows.add_css_class("boxed-list")
                self.programming_attachment_rows.set_visible(False)
                self.programming_form.append(self.programming_attachment_rows)
        self.programming_load = Gtk.Button(
            label="Проверить выбранные файлы", halign=Gtk.Align.START
        )
        self.programming_load.add_css_class("suggested-action")
        self.programming_load.connect("clicked", self.load_programming_selection)
        self.programming_load.set_sensitive(False)
        self.programming_form.append(self.programming_load)
        self.programming_form.append(Gtk.Separator())
        self.programming_form.append(
            label("Сервисные обращения и уведомления по записи", "title-3", wrap=True)
        )
        self.programming_form.append(
            label(
                "Откройте сохранённое обращение TIS/Euro, окно RKS или уведомление. Проверяются исходный запрос и порядок записанных ответов; результат не подтверждает доступ к сервису или право программирования.",
                "dim-label",
                wrap=True,
            )
        )
        service_open = Gtk.Button(
            label="Открыть сервисную запись…", halign=Gtk.Align.START
        )
        service_open.connect("clicked", self.choose_service_recording)
        self.programming_form.append(service_open)
        self.service_kinds = (
            "tis-check",
            "tis-save",
            "euro-online",
            "euro-save",
            "euro-key",
            "rks",
            "notice",
        )
        self.service_choice = Gtk.DropDown.new_from_strings(
            [
                "Проверка TIS",
                "Отправка TIS",
                "Обращение Euro",
                "Отправка Euro",
                "Запрос ключа Euro",
                "Окно запроса RKS",
                "Уведомление о завершении",
            ]
        )
        self.programming_form.append(self.service_choice)
        service_example = Gtk.Button(
            label="Воспроизвести учебный пример", halign=Gtk.Align.START
        )
        service_example.connect(
            "clicked",
            lambda *_: self.load_service_recording(
                kind=self.service_kinds[self.service_choice.get_selected()]
            ),
        )
        self.programming_form.append(service_example)
        rks_group = Adw.PreferencesGroup()
        self.rks_expander = Adw.ExpanderRow(
            title="Локальный запрос и ответ RKS",
            subtitle="Создать XML-запрос или проверить формат файла ответа",
        )
        self.rks_fields = {}
        for name, title in (
            ("x_version", "Версия формата (X-Version)"),
            ("software_id", "Идентификатор программы"),
            ("software_version", "Версия программы"),
            ("license_key", "Лицензионный ключ"),
            ("vin", "VIN"),
            ("requester_kind", "Категория заявителя (RequesterKind)"),
            ("keypair_id", "Идентификатор пары ключей"),
            ("seed", "Значение Seed"),
        ):
            row = (
                Adw.PasswordEntryRow(title=title)
                if name in ("license_key", "seed")
                else Adw.EntryRow(title=title)
            )
            row.set_tooltip_text(
                {
                    "x_version": "X-Version",
                    "software_id": "SoftwareID",
                    "software_version": "SoftwareVersion",
                    "license_key": "LicenseKey",
                    "vin": "VehicleIdentificationNumber",
                    "requester_kind": "RequesterKind",
                    "keypair_id": "KeypairID",
                    "seed": "SeedValue",
                }[name]
            )
            self.rks_fields[name] = row
            self.rks_expander.add_row(row)
        rks_actions = box(spacing=8, margin=12)
        rks_actions.append(
            label(
                "Поля сохраняются в XML ровно в указанном виде. Формат ответа не подтверждает подлинность ключа или его соответствие автомобилю.",
                wrap=True,
            )
        )
        export = Gtk.Button(label="Сохранить новый XML-запрос…")
        export.connect("clicked", self.choose_rks_destination)
        rks_actions.append(export)
        inspect = Gtk.Button(label="Проверить XML-файл ответа…")
        inspect.connect("clicked", self.choose_rks_key)
        rks_actions.append(inspect)
        self.rks_expander.add_row(rks_actions)
        rks_group.add(self.rks_expander)
        self.programming_form.append(rks_group)
        page.append(self.programming_form)
        page.append(
            label(
                "Запись задаёт точный этап, узел, наблюдавшиеся идентификаторы и порядок действий. Продолжение и автоматические повторы не разрешаются. Для повторного воспроизведения снова проверьте исходные файлы.",
                "dim-label",
                wrap=True,
            )
        )
        view.set_content(
            Gtk.ScrolledWindow(child=page, hscrollbar_policy=Gtk.PolicyType.NEVER)
        )
        return view

    def choose_rks_destination(self, *_args):
        if self.offline_busy or self.closed:
            return
        values = {name: row.get_text() for name, row in self.rks_fields.items()}
        chooser = Gtk.FileDialog(
            title="Сохранить новый запрос RKS", initial_name="ReproKeyRequest.xml"
        )

        def finished(dialog, result):
            try:
                path = dialog.save_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                self.export_rks_request(Path(path), values)
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.save(self.window, None, finished)

    def export_rks_request(self, destination, values):
        if self.offline_busy or self.closed:
            return

        def work():
            access = RKSAccess()
            access.set_data(RKSData(**values))
            # Publish a complete 0600 native export, preserving every existing path.
            with tempfile.TemporaryDirectory(
                prefix=".techstream-rks-", dir=destination.parent
            ) as temporary:
                staged = Path(temporary) / "request.xml"
                access.export_data(staged)
                size = staged.stat().st_size
                os.link(staged, destination)
            return {
                "workflow": "rks_local",
                "source": "local_user_input",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "status": "completed",
                "summary": "XML-запрос RKS сохранён локально.",
                "result": {
                    "file": destination.name,
                    "bytes": size,
                    "existing_files_replaced": False,
                },
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(operation=work)
        self.offline_stop.set_sensitive(False)

    def choose_rks_key(self, *_args):
        if self.offline_busy or self.closed:
            return
        chooser = Gtk.FileDialog(title="Проверить XML-файл ответа RKS")

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                self.inspect_rks_key(Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def inspect_rks_key(self, path):
        if self.offline_busy or self.closed:
            return

        def work():
            key = RKSAccess().import_key(path)
            return {
                "workflow": "rks_local",
                "source": "recorded_unverified",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "status": "completed",
                "summary": "Формат XML-ответа RKS проверен; подлинность ключа не установлена.",
                "result": {
                    "file": path.name,
                    "signature_characters": len(key.value),
                    "verification": "Проверен только формат",
                    "authenticity": "Не установлена",
                    "source_sha256": key.source_sha256,
                },
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(path, operation=work, sources=(path,))

    def choose_service_recording(self, *_args):
        if self.offline_busy or self.closed:
            return
        chooser = Gtk.FileDialog(title="Открыть сервисную запись")

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                if not self.closed:
                    self.load_service_recording(Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def load_service_recording(self, path=None, *, kind=None):
        if self.offline_busy or self.closed:
            return
        if path is None and not isinstance(kind, str):
            raise ValueError("Выберите сервисную запись или учебный пример")
        sources = () if path is None else (path,)

        def work():
            if path is None:
                assert isinstance(kind, str)
                session = ServiceReplay.from_bytes(create_demo_service_capture(kind))
            else:
                session = ServiceReplay.load(path)
            error = None
            try:
                result = session.run(cancelled=self.offline_cancel.is_set)
            except Exception as exc:  # noqa: BLE001 - preserve recorded failure and cleanup.
                error = exc
                result = session.report()
            report = {
                "workflow": "service_replay",
                "source": "authored_synthetic"
                if result["provenance"] == "authored"
                else "recorded_unverified",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "status": "cancelled"
                if self.offline_cancel.is_set()
                else "failed"
                if error
                else "completed",
                "summary": "Сервисная запись воспроизведена"
                if error is None
                else "Сервисная запись не завершена",
                "result": result,
            }
            return report

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(path, operation=work, sources=sources)

    def choose_programming_files(self, _button, role):
        chooser = Gtk.FileDialog(title="Выбрать локальные файлы программирования")
        multiple = role in ("catalog", "modules", "attachments")

        def finished(dialog, result):
            try:
                if multiple:
                    selected = dialog.open_multiple_finish(result)
                    files = [
                        selected.get_item(index)
                        for index in range(selected.get_n_items())
                    ]
                else:
                    files = [dialog.open_finish(result)]
                paths = tuple(
                    Path(file.get_path())
                    for file in files
                    if file.get_path() is not None
                )
                if len(paths) != len(files):
                    raise ValueError("Выберите локальные файлы")
                if not self.closed:
                    if role == "attachments":
                        paths = (*self.programming_paths[role], *paths)
                    self.set_programming_files(role, paths)
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        if multiple:
            chooser.open_multiple(self.window, None, finished)
        else:
            chooser.open(self.window, None, finished)

    def set_programming_files(self, role, paths):
        if self.offline_busy:
            return
        old_paths = self.programming_paths[role]
        old_aliases = (
            [entry.get_text() for entry in self.programming_attachment_entries]
            if role == "attachments"
            else []
        )
        self.programming_paths[role] = tuple(paths)
        if role == "attachments":
            while child := self.programming_attachment_rows.get_first_child():
                self.programming_attachment_rows.remove(child)
            self.programming_attachment_entries = []
            if paths:
                self.programming_attachment_rows.append(
                    label(
                        "Укажите точное имя каждого вложения из записи. Можно добавить один файл повторно под другим именем.",
                        wrap=True,
                    )
                )
            for index, path in enumerate(paths):
                alias = (
                    old_aliases[index]
                    if index < len(old_paths) and old_paths[index] == path
                    else path.name
                )
                entry = Adw.EntryRow(title=path.name, text=alias)
                entry.set_tooltip_text(str(path))
                entry.connect("changed", self.invalidate_programming_selection)
                self.programming_attachment_entries.append(entry)
                self.programming_attachment_rows.append(entry)
            self.programming_attachment_rows.set_visible(bool(paths))
        self.programming_labels[role].set_text(
            ", ".join(path.name for path in paths) or "Не выбрано"
        )
        self.programming_labels[role].set_tooltip_text(
            "\n".join(str(path) for path in paths)
        )
        self.invalidate_programming_selection()
        self.programming_load.set_sensitive(
            all(
                self.programming_paths[role]
                for role in ("cuw", "context", "catalog", "modules")
            )
        )

    def invalidate_programming_selection(self, *_args):
        self.programming_session = None
        self.programming_run.set_sensitive(False)

    def load_programming_selection(self, *_args):
        if self.offline_busy or self.closed:
            return
        selected = dict(self.programming_paths)
        attachment_aliases = tuple(
            entry.get_text() for entry in self.programming_attachment_entries
        )
        if not all(selected[role] for role in ("cuw", "context", "catalog", "modules")):
            self.toast("Выберите калибровку, запись, таблицы и библиотеки")
            return
        sources = tuple(path for paths in selected.values() for path in paths)

        def work():
            if (
                len(sources) > 256
                or sum(path.stat().st_size for path in sources) > 64 * 1024 * 1024
            ):
                raise ValueError("Выберите до 256 файлов, не более 64 МиБ вместе")
            loaded, retained = {}, 0
            for role, paths in selected.items():
                group = {}
                for index, path in enumerate(paths):
                    if self.offline_cancel.is_set():
                        raise InterruptedError("Проверка программирования отменена")
                    name = (
                        attachment_aliases[index]
                        if role == "attachments"
                        else path.name
                    )
                    if not name:
                        raise ValueError(
                            "Укажите точное имя каждого вложения из записи"
                        )
                    if name in group or (
                        role != "attachments"
                        and name.casefold()
                        in {existing.casefold() for existing in group}
                    ):
                        raise ValueError(
                            "Имена внутри одного набора должны различаться"
                        )
                    raw = read_regular(path, limit=64 * 1024 * 1024)
                    retained += len(raw)
                    if retained > 64 * 1024 * 1024:
                        raise ValueError("Выбранные данные превышают 64 МиБ")
                    group[name] = raw
                loaded[role] = group
            session = load_programming_replay(
                next(iter(loaded["cuw"].values())),
                next(iter(loaded["context"].values())),
                loaded["catalog"],
                loaded["modules"],
                attachments=loaded["attachments"],
                cancelled=self.offline_cancel.is_set,
            )
            return {
                "_programming_state": (session, sources),
                "workflow": "programming_definition",
                "source": session.context["source"],
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": "Файлы проверены. Можно воспроизвести только записанный этап.",
                "result": {
                    "operation": session.operation,
                    "node": session.node,
                    "modules": [
                        {
                            "name": module.name,
                            "family": module.family,
                            "build": module.build,
                            "kind": module.kind,
                        }
                        for module in session.modules.values()
                    ],
                    "events": len(session.trace.rows),
                },
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(selected["cuw"][0], operation=work, sources=sources)

    def run_programming_recording(self, *_args):
        session = self.programming_session
        if session is None or self.offline_busy or self.closed:
            return
        sources = self.programming_session_sources
        self.programming_session = None
        self.programming_run.set_sensitive(False)

        def work():
            report = session.run()
            report["workflow"] = "programming_replay"
            report["source"] = session.context["source"]
            report["summary"] = {
                "writer_completed": "Записанный этап передачи выполнен",
                "prepare_completed": "Записанный этап подготовки выполнен",
                "read_completed": "Запись чтения идентификатора воспроизведена",
                "recovery_completed": "Записанный этап восстановления выполнен",
                "probe_completed": "Запись проверки воспроизведена",
                "prepare_retry_completed": "Записанный этап подготовки выполнен",
                "recovery_required": "Запись прервана; продолжение не разрешено",
                "cancelled": "Воспроизведение этапа отменено",
                "failed": "Записанный этап не выполнен",
            }.get(report["state"], report["state"])
            return report

        self.start_offline(sources[0], operation=work, sources=sources)
        if self.offline_busy:
            self.offline_status.set_text(
                "Воспроизведение записанного этапа программирования…"
            )

    def choose_native_utility_file(self, _button, role):
        if self.offline_busy or self.closed:
            return
        chooser = Gtk.FileDialog(title=self.native_utility_titles[role])

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                if not self.closed and not self.offline_busy:
                    self.native_utility_paths[role] = Path(path)
                    self.native_utility_names[role].set_text(Path(path).name)
                    self.native_utility_names[role].set_tooltip_text(path)
                    self.native_utility_run.set_sensitive(
                        all(self.native_utility_paths.values())
                    )
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def run_native_utility_selection(self, *_args):
        if not all(self.native_utility_paths.values()):
            self.toast("Выберите обе библиотеки, запись и два файла языка")
            return
        self.start_native_utility_recording(
            **self.native_utility_paths,
            function_id=(0x1381D, 0x13308, 0x13723, 0x137B8, 0x137EA)[
                self.native_utility_function.get_selected()
            ],
        )

    def start_native_utility_recording(
        self, caller, engine, recording, language, symbols, *, function_id=0x1381D
    ):
        if self.offline_busy or self.closed:
            return

        def work():
            native = replay_native_utility(
                caller,
                engine,
                recording,
                language,
                symbols,
                dialog=self.utility_dialog,
                cancelled=self.offline_cancel.is_set,
                function_id=function_id,
            )
            return {
                "workflow": "native_utility_replay",
                "status": native["status"],
                "source": native["recording"]["source"],
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": (
                    "Нативная процедура завершена по записи"
                    if native["status"] == "completed"
                    else f"Нативная процедура вернула код {native['result']}"
                ),
                "result": native,
            }

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(
            recording,
            operation=work,
            sources=(caller, engine, recording, language, symbols),
        )

    def choose_monitor_recording(self, *_args):
        if self.offline_busy or self.closed:
            return
        chooser = Gtk.FileDialog(title="Открыть запись нативного монитора")

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальную запись")
                if not self.closed:
                    self.start_monitor_recording(Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def start_monitor_recording(self, path, source_root=None):
        if self.offline_busy or self.closed:
            return
        if source_root is None:
            region = self.root.parent.name.removeprefix("Techstream_Data_")
            source_root = self.root.parent.parent / f"Techstream_DB_{region}"

        def work():
            session = load_monitor_recording(
                path, source_root, cancelled=self.offline_cancel.is_set
            )
            report = session.run()
            report["_monitor_state"] = session
            report["summary"] = (
                "Нативные настройки регистратора подготовлены по записи"
                if report.get("result", {}).get("drs_export_available")
                else "Нативный монитор воспроизведён по записи"
            )
            return report

        self.select_navigation(self.navigation.get_row_at_index(6))
        self.start_offline(path, operation=work)

    def export_monitor_capture(self, *_args):
        session = self.monitor_session
        if session is None or self.offline_busy or not self.monitor_output_ids:
            return
        stream = self.monitor_output_ids[self.monitor_output.get_selected()]
        output_format = self.monitor_output_formats.get(stream, "dm")
        chooser = Gtk.FileDialog(
            title="Сохранить настройки DRS"
            if output_format == "drs"
            else "Сохранить нативный снимок DM",
            initial_name=f"{stream}-capture.{output_format}",
        )

        def finished(dialog, result):
            try:
                path = dialog.save_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                self.start_offline_write(
                    lambda: session.save_output(Path(path), stream=stream),
                    "Настройки DRS сохранены."
                    if output_format == "drs"
                    else "Нативный снимок DM сохранён.",
                )
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.save(self.window, None, finished)

    def choose_recorder_recording(self, *_args):
        settings = self.recorder_settings_path
        chooser = Gtk.FileDialog(title="Открыть запись команд регистратора")

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальную запись")
                if not self.closed:
                    self.start_recorder_recording(settings, Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def start_recorder_recording(self, settings, recording):
        if self.offline_busy or self.closed:
            return
        self.select_navigation(self.navigation.get_row_at_index(6))
        self.recorder_settings_path = settings
        self.start_offline(
            recording,
            operation=lambda: replay_recorder(
                settings, recording, cancelled=self.offline_cancel.is_set
            ),
            sources=(settings, recording),
        )
        if self.offline_busy:
            self.offline_status.set_text("Воспроизведение работы регистратора…")

    def export_recorder_capture(self, *_args):
        report, sources = self.offline_report, self.offline_sources
        if report is None or report.get("status") != "completed":
            return
        chooser = Gtk.FileDialog(
            title="Сохранить захваченные данные DM", initial_name="capture.dm"
        )

        def finished(dialog, result):
            try:
                path = dialog.save_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                if not self.closed:
                    self.start_offline_write(
                        lambda: save_recorder_dm(Path(path), report, sources=sources),
                        "Снимок регистратора сохранён в native DM.",
                    )
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.save(self.window, None, finished)

    def build_offline(self):
        view = Adw.ToolbarView()
        view.add_top_bar(self.header("Без автомобиля"))
        page = box(margin=22, spacing=12)
        page.append(label("Файлы и процедуры", "workspace-title", wrap=True))
        page.append(
            label(
                "Открывайте записи, снимки и калибровки. Воспроизводите процедуры по записям связи или запускайте учебные примеры. "
                "Автомобиль и адаптер не подключаются; исходные файлы не изменяются.",
                "dim-label",
                wrap=True,
            )
        )
        self.offline_keys = list(WORKFLOWS)
        self.offline_choice = Gtk.DropDown.new_from_strings(
            [WORKFLOWS[key]["title"] for key in self.offline_keys]
        )
        self.offline_choice.set_tooltip_text("Выберите учебную процедуру")
        self.offline_choice.connect(
            "notify::selected", self.offline_description_changed
        )
        page.append(self.offline_choice)
        self.offline_description = label(wrap=True)
        page.append(self.offline_description)
        self.offline_description_changed()
        tools = Gtk.FlowBox(
            selection_mode=Gtk.SelectionMode.NONE,
            max_children_per_line=4,
            min_children_per_line=1,
            column_spacing=8,
            row_spacing=8,
        )
        self.offline_run = Gtk.Button(label="Выполнить пример")
        self.offline_run.add_css_class("suggested-action")
        self.offline_run.connect("clicked", lambda *_: self.start_offline())
        tools.append(self.offline_run)
        self.offline_open = Gtk.Button(label="Открыть файл…")
        self.offline_open.connect("clicked", self.open_offline)
        tools.append(self.offline_open)
        self.offline_stop = Gtk.Button(label="Отмена", sensitive=False)
        self.offline_stop.connect("clicked", lambda *_: self.offline_cancel.set())
        tools.append(self.offline_stop)
        self.offline_catalog_open = Gtk.Button(label="Параметры калибровки…")
        self.offline_catalog_open.connect("clicked", self.choose_calibration_sources)
        tools.append(self.offline_catalog_open)
        page.append(tools)
        self.offline_catalog_controls = box(spacing=8)
        self.offline_catalog_controls.append(
            label("Выбор калибровки по исходным таблицам", "heading")
        )
        self.calibration_key = Gtk.DropDown(enable_search=True)
        self.offline_catalog_controls.append(self.calibration_key)
        self.calibration_stage = Gtk.DropDown.new_from_strings(
            [
                "Чтение идентификаторов",
                "Подготовка передачи",
                "Передача блоков",
                "Режим шлюза",
            ]
        )
        self.offline_catalog_controls.append(self.calibration_stage)
        context_fields = box(spacing=8)
        self.calibration_cids = Gtk.Entry(
            placeholder_text="Прочитанные CALID через запятую (если требуются)"
        )
        context_fields.append(self.calibration_cids)
        self.calibration_location = Gtk.Entry(
            placeholder_text="LocationID: 8 байт, hex (если требуется)"
        )
        context_fields.append(self.calibration_location)
        self.calibration_diag = Gtk.Entry(
            placeholder_text="Диагностические адреса: 07E0,07E1 (если требуются)"
        )
        context_fields.append(self.calibration_diag)
        self.calibration_previous = Gtk.Entry(
            placeholder_text="Адреса предыдущего чтения: 07E0/07E8 (если требуются)"
        )
        context_fields.append(self.calibration_previous)
        context_details = Gtk.Expander(
            label="Дополнительные сведения для выбора адресов"
        )
        context_details.set_child(context_fields)
        self.offline_catalog_controls.append(context_details)
        self.calibration_plan = Gtk.Button(
            label="Показать план без отправки", halign=Gtk.Align.START
        )
        self.calibration_plan.connect("clicked", self.run_calibration_plan)
        self.offline_catalog_controls.append(self.calibration_plan)
        self.offline_catalog_controls.set_visible(False)
        page.append(self.offline_catalog_controls)
        self.offline_procedure_controls = box(spacing=8)
        self.procedure_function = Gtk.DropDown()
        self.offline_procedure_controls.append(self.procedure_function)
        execute = Gtk.Button(
            label="Открыть запись и выполнить…", halign=Gtk.Align.START
        )
        execute.connect("clicked", self.choose_procedure_recording)
        self.offline_procedure_controls.append(execute)
        self.offline_procedure_controls.set_visible(False)
        page.append(self.offline_procedure_controls)
        self.native_utility_titles = {
            "caller": "Исходный IT3UtilityTY2.dll…",
            "engine": "Исходный UtilityEx2TY.dll…",
            "recording": "Запись вызовов DRIVER / ожиданий…",
            "language": "Выбранный язык U_*.ddb…",
            "symbols": "Исходный UtilityResID_NK.rsd…",
        }
        self.native_utility_paths: dict[str, Path | None] = {
            role: None for role in self.native_utility_titles
        }
        self.native_utility_names = {}
        self.native_utility_form = box(spacing=8)
        self.native_utility_function = Gtk.DropDown.new_from_strings(
            [
                "Очистка истории соединения (DoorClear)",
                "Сброс оценки коротких поездок (EFI61)",
                "Очистка неотправленных данных экстренного вызова (DCM45)",
                "Инициализация MT/CVT/HEV (BSM27)",
                "Инициализация MT/CVT/HEV (BSM28)",
            ]
        )
        self.native_utility_form.append(self.native_utility_function)
        for role, title in self.native_utility_titles.items():
            row = box(vertical=False, spacing=8)
            choose = Gtk.Button(label=title)
            choose.connect("clicked", self.choose_native_utility_file, role)
            row.append(choose)
            selected = label(
                "Не выбрано", ellipsize=Pango.EllipsizeMode.MIDDLE, hexpand=True
            )
            self.native_utility_names[role] = selected
            row.append(selected)
            self.native_utility_form.append(row)
        self.native_utility_run = Gtk.Button(
            label="Воспроизвести выбранную процедуру",
            sensitive=False,
            halign=Gtk.Align.START,
        )
        self.native_utility_run.connect("clicked", self.run_native_utility_selection)
        self.native_utility_form.append(self.native_utility_run)
        self.native_utility_expander = Gtk.Expander(
            label="Нативные процедуры Toyota (TY18)"
        )
        self.native_utility_expander.set_child(self.native_utility_form)
        page.append(self.native_utility_expander)
        self.monitor_session = None
        self.offline_monitor_controls = box(vertical=False, spacing=8)
        monitor_open = Gtk.Button(label="Воспроизвести нативный монитор…", hexpand=True)
        monitor_open.connect("clicked", self.choose_monitor_recording)
        self.offline_monitor_controls.append(monitor_open)
        self.monitor_output_ids = ()
        self.monitor_output_formats = {}
        self.monitor_output_changing = False
        self.monitor_output = Gtk.DropDown(visible=False)
        self.monitor_output.connect("notify::selected", self.change_monitor_output)
        self.offline_monitor_controls.append(self.monitor_output)
        self.monitor_export = Gtk.Button(label="Сохранить снимок DM…", visible=False)
        self.monitor_export.connect("clicked", self.export_monitor_capture)
        self.offline_monitor_controls.append(self.monitor_export)
        page.append(self.offline_monitor_controls)
        self.offline_recorder_controls = box(vertical=False, spacing=8)
        replay = Gtk.Button(label="Воспроизвести работу регистратора…", hexpand=True)
        replay.connect("clicked", self.choose_recorder_recording)
        self.offline_recorder_controls.append(replay)
        self.recorder_export = Gtk.Button(label="Сохранить снимок DM…", hexpand=True)
        self.recorder_export.connect("clicked", self.export_recorder_capture)
        self.offline_recorder_controls.append(self.recorder_export)
        self.offline_recorder_controls.set_visible(False)
        page.append(self.offline_recorder_controls)
        self.offline_programming_controls = box(vertical=False, spacing=8)
        self.programming_run = Gtk.Button(
            label="Выполнить записанный этап", hexpand=True
        )
        self.programming_run.connect("clicked", self.run_programming_recording)
        self.offline_programming_controls.append(self.programming_run)
        reopen = Gtk.Button(label="Выбрать или проверить файлы заново…", hexpand=True)
        reopen.connect(
            "clicked",
            lambda *_: self.select_navigation(self.navigation.get_row_at_index(8)),
        )
        self.offline_programming_controls.append(reopen)
        self.offline_programming_controls.set_visible(False)
        page.append(self.offline_programming_controls)
        self.offline_active_controls = box(spacing=8)
        self.active_choice = Gtk.DropDown()
        self.offline_active_controls.append(self.active_choice)
        self.active_initialize = Gtk.Button(
            label="Прочитать параметры выбранного теста", halign=Gtk.Align.START
        )
        self.active_initialize.connect("clicked", self.initialize_active_test)
        self.offline_active_controls.append(self.active_initialize)
        reload_active = Gtk.Button(label="Загрузить эту запись заново")
        reload_active.connect(
            "clicked",
            lambda *_args: self.load_active_recording(
                self.active_selection, self.active_recording_path
            ),
        )
        self.offline_active_controls.append(reload_active)
        self.active_arguments = box(spacing=8)
        self.active_arguments.set_visible(False)
        self.offline_active_controls.append(self.active_arguments)
        self.offline_active_controls.set_visible(False)
        page.append(self.offline_active_controls)
        self.offline_status = label(
            "Выберите пример или откройте локальный файл.", "heading", wrap=True
        )
        page.append(self.offline_status)
        self.offline_provenance = label(
            "Проверка на автомобиле не выполнена.", "dim-label", wrap=True
        )
        page.append(self.offline_provenance)
        self.offline_buffer = Gtk.DropDown(visible=False)
        self.offline_buffer.set_tooltip_text("Запись параметров внутри файла")
        self.offline_buffer.connect("notify::selected", self.change_offline_buffer)
        page.append(self.offline_buffer)
        self.offline_encoding_controls = box(vertical=False, spacing=8)
        self.offline_encoding = Gtk.Entry(
            placeholder_text="Кодировка текста TSE: cp932, cp1251, utf-8…",
            hexpand=True,
            max_length=64,
        )
        self.offline_encoding_controls.append(self.offline_encoding)
        decode = Gtk.Button(label="Прочитать текст отчёта")
        decode.connect("clicked", self.reload_tse_encoding)
        self.offline_encoding_controls.append(decode)
        self.offline_encoding_controls.set_visible(False)
        page.append(self.offline_encoding_controls)
        self.offline_report_view = Gtk.DropDown(visible=False)
        self.offline_report_view.set_tooltip_text("Раздел сохранённого отчёта")
        self.offline_report_view.connect("notify::selected", self.change_report_view)
        page.append(self.offline_report_view)
        self.offline_dtc_store = Gio.ListStore.new(Parameter)
        dtc_table = Gtk.ColumnView(
            model=Gtk.NoSelection(model=self.offline_dtc_store),
            show_row_separators=True,
        )
        for title, field, width in (
            ("Код", "code", 100),
            ("Описание", "description", 280),
            ("Текущий", "current", 100),
            ("Ожидающий", "pending", 110),
            ("История", "history", 100),
            ("Постоянный", "permanent", 120),
        ):
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self.cell_setup)
            factory.connect("bind", self.cell_bind, field)
            column = Gtk.ColumnViewColumn.new(title, factory)
            column.set_resizable(True)
            column.set_fixed_width(width)
            dtc_table.append_column(column)
        self.offline_dtc_table = Gtk.ScrolledWindow(
            child=dtc_table, min_content_height=140, visible=False
        )
        page.append(self.offline_dtc_table)
        self.offline_parameter_store = Gio.ListStore.new(Parameter)
        parameter_table = Gtk.ColumnView(
            model=Gtk.NoSelection(model=self.offline_parameter_store),
            show_row_separators=True,
        )
        for title, field, width in (
            ("Параметр", "name", 200),
            ("ID", "identifier", 70),
            ("Отображаемое значение", "display", 220),
            ("Единица", "unit", 90),
            ("Исходное значение", "raw", 220),
            ("Исходные флаги", "flags", 120),
        ):
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self.cell_setup)
            factory.connect("bind", self.cell_bind, field)
            column = Gtk.ColumnViewColumn.new(title, factory)
            column.set_resizable(True)
            column.set_fixed_width(width)
            parameter_table.append_column(column)
        self.offline_parameter_table = Gtk.ScrolledWindow(
            child=parameter_table, min_content_height=140, visible=False
        )
        page.append(self.offline_parameter_table)
        self.offline_chart_box = box(spacing=6)
        self.offline_chart_choice = Gtk.DropDown()
        self.offline_chart_choice.connect("notify::selected", self.update_offline_chart)
        self.offline_chart_box.append(self.offline_chart_choice)
        self.offline_picture = Gtk.Picture(can_shrink=True, height_request=160)
        self.offline_picture.set_content_fit(Gtk.ContentFit.CONTAIN)
        self.offline_chart_box.append(self.offline_picture)
        self.offline_time = label(wrap=True, css="dim-label")
        self.offline_chart_box.append(self.offline_time)
        self.offline_chart = Gtk.Expander(
            label="График параметров", expanded=True, visible=False
        )
        self.offline_chart.set_child(self.offline_chart_box)
        page.append(self.offline_chart)
        self.offline_store = Gio.ListStore.new(Parameter)
        table = Gtk.ColumnView(
            model=Gtk.NoSelection(model=self.offline_store), show_row_separators=True
        )
        for title, field, width in (
            ("Показатель", "name", 300),
            ("Результат", "value", 480),
        ):
            factory = Gtk.SignalListItemFactory()
            factory.connect("setup", self.cell_setup)
            factory.connect("bind", self.cell_bind, field)
            column = Gtk.ColumnViewColumn.new(title, factory)
            column.set_expand(True)
            column.set_resizable(True)
            column.set_fixed_width(width)
            table.append_column(column)
        self.offline_table_scroll = Gtk.ScrolledWindow(
            child=table, vexpand=True, min_content_height=140
        )
        page.append(self.offline_table_scroll)
        self.offline_raw = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            wrap_mode=Gtk.WrapMode.WORD_CHAR,
            top_margin=8,
            bottom_margin=8,
            left_margin=8,
            right_margin=8,
        )
        raw = Gtk.Expander(label="Подробности отчёта JSON")
        raw.set_child(
            Gtk.ScrolledWindow(
                child=self.offline_raw, min_content_height=130, max_content_height=200
            )
        )
        page.append(raw)
        self.offline_export = Gtk.Button(
            label="Сохранить отчёт JSON", sensitive=False, halign=Gtk.Align.START
        )
        self.offline_export.connect("clicked", self.export_offline)
        exports = box(vertical=False, spacing=8)
        exports.append(self.offline_export)
        self.offline_copy = Gtk.Button(label="Сохранить копию записи…", sensitive=False)
        self.offline_copy.connect("clicked", self.copy_offline)
        exports.append(self.offline_copy)
        page.append(exports)
        view.set_content(
            Gtk.ScrolledWindow(child=page, hscrollbar_policy=Gtk.PolicyType.NEVER)
        )
        return view

    def offline_description_changed(self, *_args):
        key = self.offline_keys[self.offline_choice.get_selected()]
        self.offline_description.set_text(WORKFLOWS[key]["description"])

    def choose_calibration_sources(self, *_args):
        plain = Gtk.CheckButton(label="Обычные CSV/INI без штатного кодирования")
        dialog = Adw.AlertDialog(
            heading="Параметры калибровки",
            body="Выберите исходные таблицы CSV/INI и нужные DLL. Из библиотек читаются только имена функций и версия; код не запускается. Совместимость с автомобилем не подтверждается.",
        )
        dialog.set_extra_child(plain)
        dialog.add_response("cancel", "Отмена")
        dialog.add_response("open", "Выбрать файлы…")

        def response(_dialog, name):
            if name != "open":
                return
            encoded = not plain.get_active()
            chooser = Gtk.FileDialog(title="Выбрать таблицы параметров и библиотеки")

            def finished(file_dialog, result):
                try:
                    files = file_dialog.open_multiple_finish(result)
                    paths = [
                        files.get_item(index).get_path()
                        for index in range(files.get_n_items())
                    ]
                    if not paths or any(path is None for path in paths):
                        raise ValueError("Выберите локальные файлы")
                    if not self.closed:
                        self.load_calibration_sources(
                            tuple(Path(path) for path in paths), encoded=encoded
                        )
                except GLib.Error as exc:
                    self.dialog_error(exc)
                except (OSError, ValueError) as exc:
                    self.toast(str(exc))

            chooser.open_multiple(self.window, None, finished)

        dialog.connect("response", response)
        dialog.present(self.window)

    def load_calibration_sources(self, paths, *, encoded=True):
        def work():
            if not 1 <= len(paths) <= 256 or len(
                {path.name.casefold() for path in paths}
            ) != len(paths):
                raise ValueError("Выберите до 256 файлов с различными именами")
            if (
                any(
                    not path.is_file() or path.stat().st_size > 16 * 1024 * 1024
                    for path in paths
                )
                or sum(path.stat().st_size for path in paths) > 64 * 1024 * 1024
            ):
                raise ValueError(
                    "Нужны обычные файлы до 16 МиБ каждый и до 64 МиБ вместе"
                )
            tables, modules, versions = {}, {}, {}
            module_reports = []
            for path in paths:
                if self.offline_cancel.is_set():
                    raise ValueError("Операция отменена")
                if path.suffix.lower() == ".dll":
                    module = inspect_module(path)
                    modules[module["name"]] = module["exports"]
                    versions[module["name"]] = module["version"]
                    module_reports.append(
                        {
                            "name": module["name"],
                            "version": module["version"],
                            "sha256": module["sha256"],
                            "exports": len(module["exports"]),
                        }
                    )
                else:
                    raw = read_regular(path, limit=16 * 1024 * 1024)
                    tables[path.name] = raw
            catalog = CalibrationCatalog.from_tables(tables, encoded=encoded)
            return {
                "_catalog_state": (catalog, modules, versions, paths),
                "workflow": "calibration_catalog",
                "source": "local_file_unverified",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": f"Таблицы калибровки прочитаны · ключей: {len(catalog.keys)} · библиотек: {len(modules)}",
                "result": {
                    "catalog": catalog.report(),
                    "modules": module_reports,
                },
            }

        self.start_offline(operation=work, sources=paths)

    def run_calibration_plan(self, *_args):
        catalog = getattr(self, "calibration_catalog", None)
        if catalog is None or self.calibration_key.get_selected() >= len(catalog.keys):
            self.toast("Выберите исходный ключ калибровки")
            return
        try:
            cids = tuple(
                value.strip()
                for value in self.calibration_cids.get_text().split(",")
                if value.strip()
            )
            location = self.calibration_location.get_text().strip()
            context = SelectionContext(
                cids=cids,
                location_id=bytes.fromhex(location) if location else None,
                diag_ids=tuple(
                    bytes.fromhex(value.strip())
                    for value in self.calibration_diag.get_text().split(",")
                    if value.strip()
                ),
                previous_addresses=tuple(
                    parse_address(value.strip())
                    for value in self.calibration_previous.get_text().split(",")
                    if value.strip()
                ),
            )
            key = catalog.keys[self.calibration_key.get_selected()]
            stage = ("get_cid", "prepare", "write", "gateway")[
                self.calibration_stage.get_selected()
            ]
        except ValueError as exc:
            self.toast(f"Проверьте сведения для выбора адресов: {exc}")
            return
        modules, versions = self.calibration_modules, self.calibration_versions

        def work():
            dispatch = catalog.select(key).dispatch(
                stage, context, modules, module_versions=versions
            )
            return {
                "workflow": "calibration_plan",
                "source": "local_file_unverified",
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": "План выбран по исходным таблицам. Отправка и запуск библиотек не выполнялись.",
                "result": {
                    "key": key,
                    "stage": stage,
                    "plan": dispatch,
                    "vehicle_compatibility_validated": False,
                },
            }

        self.start_offline(operation=work, sources=self.calibration_sources)

    def open_offline(self, *_args):
        chooser = Gtk.FileDialog(
            title="Открыть запись, снимок, калибровку или процедуру"
        )

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                if not self.closed:
                    self.start_offline(Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def start_offline(
        self, path=None, operation=None, sources=(), buffer_index=0, encoding=None
    ):
        if self.offline_busy or self.closed:
            return
        self.close_utility_screen()
        key = self.offline_keys[self.offline_choice.get_selected()]
        self.offline_busy = True
        self.offline_report = None
        self.monitor_session = None
        self.monitor_output_ids = ()
        self.monitor_output_formats = {}
        self.monitor_export.set_visible(False)
        self.monitor_output.set_visible(False)
        self.offline_source = path
        self.offline_sources = tuple(sources) or ((path,) if path is not None else ())
        self.offline_cancel.clear()
        self.offline_store.remove_all()
        self.offline_dtc_store.remove_all()
        self.offline_dtc_table.set_visible(False)
        self.offline_parameter_store.remove_all()
        self.offline_parameter_table.set_visible(False)
        self.offline_chart.set_visible(False)
        self.offline_catalog_was_visible = self.offline_catalog_controls.get_visible()
        self.offline_active_was_visible = self.offline_active_controls.get_visible()
        self.offline_active_controls.set_visible(False)
        self.offline_programming_was_visible = (
            self.offline_programming_controls.get_visible()
        )
        self.offline_programming_controls.set_visible(False)
        self.offline_recorder_was_visible = self.offline_recorder_controls.get_visible()
        self.offline_recorder_controls.set_visible(False)
        self.recorder_export.set_sensitive(False)
        self.offline_procedure_was_visible = (
            self.offline_procedure_controls.get_visible()
        )
        self.offline_catalog_controls.set_visible(False)
        self.offline_procedure_controls.set_visible(False)
        self.offline_buffer.set_visible(False)
        self.offline_tse_was_visible = self.offline_encoding_controls.get_visible()
        self.offline_encoding_controls.set_visible(False)
        self.offline_report_view.set_visible(False)
        self.offline_picture.set_paintable(None)
        self.offline_copy.set_sensitive(False)
        self.offline_raw.get_buffer().set_text("")
        for widget in (
            self.offline_run,
            self.offline_open,
            self.offline_choice,
            self.offline_export,
            self.offline_catalog_open,
            self.offline_monitor_controls,
            self.native_utility_form,
            self.programming_form,
        ):
            widget.set_sensitive(False)
        self.offline_stop.set_sensitive(True)
        self.offline_status.set_text(
            "Выполнение операции…"
            if operation is not None
            else "Чтение файла…"
            if path
            else "Выполнение учебной процедуры…"
        )
        self.offline_provenance.set_text(
            str(path)
            if path
            else ""
            if operation is not None
            else "Учебные данные. Проверка на автомобиле не выполнена."
        )

        def work():
            try:
                if self.offline_cancel.is_set():
                    raise ValueError("Операция отменена")
                for original in self.offline_sources:
                    if not original.is_file():
                        raise ValueError("Выберите обычные локальные файлы")
                if operation is not None:
                    report = operation()
                elif path is not None:
                    if not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
                        raise ValueError("Выберите обычный файл размером до 32 МиБ")
                    report = inspect_path(
                        path, buffer_index=buffer_index, encoding=encoding
                    )
                else:
                    report = run_example(key, cancelled=self.offline_cancel.is_set)
                error = ""
            except Exception as exc:  # noqa: BLE001 - worker failures must restore the UI.
                report, error = None, str(exc) or type(exc).__name__
                code = getattr(exc, "code", None)
                if type(code) is int:
                    error += f" · Код ошибки: {code}"
                    if 0 <= code <= 0xFFFFFFFF:
                        error += f" (0x{code:08X})"
            GLib.idle_add(self.offline_ready, report, error)

        self.offline_thread = threading.Thread(target=work, name="techstream-offline")
        self.offline_thread.start()

    def offline_ready(self, report, error):
        self.offline_busy = False
        if self.closed:
            return GLib.SOURCE_REMOVE
        self.close_utility_screen()
        for widget in (
            self.offline_run,
            self.offline_open,
            self.offline_choice,
            self.offline_catalog_open,
            self.offline_monitor_controls,
            self.native_utility_form,
            self.programming_form,
        ):
            widget.set_sensitive(True)
        self.offline_stop.set_sensitive(False)
        if (
            self.offline_cancel.is_set()
            and report is not None
            and report.get("workflow") in ("active_definition", "active_initialization")
        ):
            # Initialization owns only bounded probes; close never sends a PDU here.
            state = report.pop("_active_state", None)
            session = state[0] if state is not None else self.active_session
            if session is not None:
                session.close()
            self.active_session = None
            report.pop("_active_initialization", None)
            report.update(
                status="cancelled",
                summary="Подготовка активного теста отменена. Загрузите запись заново для повтора.",
            )
        if self.offline_cancel.is_set() and (
            report is None or report.get("status") != "cancelled"
        ):
            report, error = (
                None,
                "Операция отменена. Можно открыть файл или повторить пример.",
            )
        self.active_initialize.set_sensitive(self.active_session is not None)
        if hasattr(self, "active_execute"):
            self.active_execute.set_sensitive(self.active_session is not None)
        if report is None:
            self.offline_status.set_text(error)
            self.offline_encoding_controls.set_visible(self.offline_tse_was_visible)
            self.offline_active_controls.set_visible(self.offline_active_was_visible)
            self.offline_programming_controls.set_visible(
                self.offline_programming_was_visible
            )
            self.offline_catalog_controls.set_visible(self.offline_catalog_was_visible)
            self.offline_recorder_controls.set_visible(
                self.offline_recorder_was_visible
            )
            self.offline_procedure_controls.set_visible(
                self.offline_procedure_was_visible
            )
        else:
            if "_active_state" in report:
                self.active_session, self.active_sources, self.active_tests = (
                    report.pop("_active_state")
                )
                self.active_initial = None
                self.active_arguments.set_visible(False)
                self.active_choice.set_model(
                    Gtk.StringList.new(
                        [
                            f"{row['name'] or row['signal_id']} · {row['family']} · {row['signal_id']}"
                            for row in self.active_tests
                        ]
                    )
                )
            if "_active_initialization" in report:
                self.fill_active_inputs(report.pop("_active_initialization"))
            self.active_initialize.set_sensitive(self.active_session is not None)
            self.offline_active_controls.set_visible(
                report.get("workflow")
                in ("active_definition", "active_initialization", "active_replay")
            )
            if "_programming_state" in report:
                self.programming_session, self.programming_session_sources = report.pop(
                    "_programming_state"
                )
            self.programming_run.set_sensitive(self.programming_session is not None)
            self.offline_programming_controls.set_visible(
                report.get("workflow")
                in ("programming_definition", "programming_replay")
            )
            if "_catalog_state" in report:
                (
                    self.calibration_catalog,
                    self.calibration_modules,
                    self.calibration_versions,
                    self.calibration_sources,
                ) = report.pop("_catalog_state")
            if "_procedure_state" in report:
                self.procedure_selection = report.pop("_procedure_state")
            if "_monitor_state" in report:
                self.monitor_session = report.pop("_monitor_state")
                self.offline_sources = self.monitor_session.sources
                self.monitor_output_changing = True
                self.monitor_output_ids = tuple(self.monitor_session.outputs)
                self.monitor_output_formats = {
                    row["id"]: row.get("format", "dm")
                    for row in report.get("result", {}).get("outputs", [])
                }
                self.monitor_output.set_model(
                    Gtk.StringList.new(
                        [
                            {
                                "monitor": "Монитор",
                                "oscilloscope": "Осциллограф",
                                "recording": "Настройки DRS",
                            }.get(key, key)
                            for key in self.monitor_output_ids
                        ]
                    )
                )
                self.monitor_output.set_selected(0)
                self.monitor_output.set_visible(len(self.monitor_output_ids) > 1)
                self.monitor_output_changing = False
            self.monitor_export.set_visible(
                report.get("workflow") == "monitor_replay"
                and report.get("status") == "completed"
                and self.monitor_session is not None
                and bool(self.monitor_output_ids)
                and (
                    report.get("result", {}).get("dm_export_available", False)
                    or report.get("result", {}).get("drs_export_available", False)
                )
            )
            selected_output = (
                self.monitor_output_ids[0] if self.monitor_output_ids else None
            )
            self.monitor_export.set_label(
                "Сохранить настройки DRS…"
                if self.monitor_output_formats.get(selected_output) == "drs"
                else "Сохранить снимок DM…"
            )
            self.offline_report = report
            self.offline_export.set_sensitive(True)
            self.offline_status.set_text(str(report.get("summary", "Файл прочитан")))
            source = (
                (
                    "Учебная запись обмена; выбранные локальные ресурсы"
                    if "profile" in report
                    else "Учебные данные"
                )
                if report.get("source") == "authored_synthetic"
                else "Локальные ресурсы; происхождение не подтверждено"
            )
            if report.get("source") == "local_user_input":
                source = "Данные, введённые пользователем"
            self.offline_provenance.set_text(
                f"{source}. Проверка на автомобиле не выполнена."
                + (
                    f"\n{self.offline_source}"
                    if self.offline_source is not None
                    else ""
                )
            )
            sections = report.get("result", {}).get("report_views", [])
            self.offline_report_view_changing = True
            self.offline_report_view.set_model(
                Gtk.StringList.new(
                    (["Сводка и запись параметров"] if sections else [])
                    + [self.report_view_title(row) for row in sections]
                )
            )
            self.offline_report_view.set_selected(
                1 if sections and not report["result"].get("available_buffers") else 0
            )
            self.offline_report_view.set_visible(bool(sections))
            self.offline_report_view_changing = False
            is_tse = report.get("result", {}).get("format") == "native-tse"
            self.offline_encoding_controls.set_visible(is_tse)
            if is_tse:
                self.offline_encoding.set_text(
                    report["result"].get("report_encoding") or ""
                )
            self.render_offline(report)
            if report.get("workflow") == "calibration_catalog":
                self.calibration_key.set_model(
                    Gtk.StringList.new(list(self.calibration_catalog.keys))
                )
            if report.get("workflow") == "procedure_definition":
                functions = self.procedure_selection["functions"]
                self.procedure_function.set_model(
                    Gtk.StringList.new(
                        [
                            f"{row['name'] or row['id']} · {row['id']}"
                            for row in functions
                        ]
                    )
                )
                self.procedure_function.set_visible(bool(functions))
            self.offline_procedure_controls.set_visible(
                report.get("workflow") in ("procedure_definition", "procedure_replay")
            )
            self.offline_catalog_controls.set_visible(
                report.get("workflow") in ("calibration_catalog", "calibration_plan")
            )
            result = report.get("result", {})
            is_recorder = report.get("workflow") == "recorder_replay"
            if result.get("format") == "native-drs" and self.offline_source is not None:
                self.recorder_settings_path = self.offline_source
            self.offline_recorder_controls.set_visible(
                is_recorder or result.get("format") == "native-drs"
            )
            self.recorder_export.set_sensitive(
                is_recorder
                and report.get("status") == "completed"
                and result.get("dm_export_available", False)
            )
            buffers = result.get("available_buffers", [])
            self.offline_buffer_changing = True
            self.offline_buffer_indices = [row["index"] for row in buffers]
            self.offline_buffer.set_model(
                Gtk.StringList.new([row["title"] for row in buffers])
            )
            index = result.get("playback_index")
            if index in self.offline_buffer_indices:
                self.offline_buffer.set_selected(
                    self.offline_buffer_indices.index(index)
                )
            self.offline_buffer.set_visible(len(buffers) > 1)
            self.offline_buffer_changing = False
            self.offline_copy.set_sensitive(
                self.offline_source is not None
                and result.get("format")
                in ("native-dm", "native-drs", "native-tse", "native-communication-log")
            )
        if self.smoke_test:
            GLib.idle_add(self.check_offline_smoke)
        return GLib.SOURCE_REMOVE

    def change_offline_buffer(self, *_args):
        if (
            getattr(self, "offline_buffer_changing", True)
            or self.offline_busy
            or self.offline_source is None
        ):
            return
        selected = self.offline_buffer.get_selected()
        if selected < len(self.offline_buffer_indices):
            self.start_offline(
                self.offline_source,
                buffer_index=self.offline_buffer_indices[selected],
                encoding=self.offline_encoding.get_text().strip() or None,
            )

    def reload_tse_encoding(self, *_args):
        if self.offline_busy or self.offline_source is None:
            return
        encoding = self.offline_encoding.get_text().strip()
        if not encoding:
            self.toast("Укажите кодировку, в которой сохранён текст отчёта")
            return
        index = 0
        if self.offline_report is not None:
            index = self.offline_report.get("result", {}).get("playback_index") or 0
        self.start_offline(self.offline_source, buffer_index=index, encoding=encoding)

    def change_monitor_output(self, *_args):
        if (
            self.monitor_output_changing
            or self.offline_busy
            or self.offline_report is None
        ):
            return
        if self.offline_report.get("workflow") != "monitor_replay":
            return
        stream = self.monitor_output_ids[self.monitor_output.get_selected()]
        self.monitor_export.set_label(
            "Сохранить настройки DRS…"
            if self.monitor_output_formats.get(stream, "dm") == "drs"
            else "Сохранить снимок DM…"
        )
        self.offline_store.remove_all()
        self.offline_chart.set_visible(False)
        self.render_offline(self.offline_report)

    def change_report_view(self, *_args):
        if (
            getattr(self, "offline_report_view_changing", True)
            or self.offline_busy
            or self.offline_report is None
        ):
            return
        self.offline_store.remove_all()
        self.offline_table_scroll.get_vadjustment().set_value(0)
        self.offline_chart.set_visible(False)
        self.render_offline(self.offline_report)

    @staticmethod
    def report_view_title(view):
        family = view["family"]
        title = {
            "IniCarInfo": "Исходный выбор автомобиля",
            "ConfCarInfo": "Данные автомобиля",
            "HealthCheck": "Проверка систем",
            "DTCMon": "Коды неисправностей",
            "DTCP5": "Коды неисправностей P5",
            "SysChk": "Проверка системы",
            "MultiPID": "Параметры нескольких систем",
            "FuncName": "Сохранённые функции",
            "TimeStamp": "Метки времени",
            "OpeHis": "История операций",
            "Oscillo": "Осциллограммы",
            "DDRData": "Записи DDR",
            "ErrRep": "Отчёт об ошибке",
            "TMRRep": "Отчёт TMR",
            "ROBCommon": "Общие данные ROB",
            "ROB": "Данные ROB выбранной системы",
            "MILMessage": "Сообщения и подтверждения MIL",
            "CanBus": "Сохранённые сведения CAN",
            "OpeFFD": "Изображения стоп-кадров операций",
            "ImgFFD": "Изображения стоп-кадров",
            "MktMonRam": "Сохранённые снимки памяти",
            "MktMonRamSSR": "Сохранённые снимки памяти SSR",
            "FuelCon": "Сохранённые данные FuelCon",
            "ABSHis": "История ABS",
            "ICSHis": "История ICS",
            "AFO2Sn": "Снимки A/F и O2",
            "PSDHis": "История PSD",
            "PreFFD": "Предварительные стоп-кадры",
            "OpeInope": "Сохранённые данные операций OpeInope",
        }.get(family, family)
        ecu = view.get("ecu_index")
        suffix = " · общий раздел" if ecu is None else f" · индекс ЭБУ {ecu}"
        return f"{title} ({family}){suffix}"

    def render_offline(self, report, *, store=None, include_chart=True):
        store = self.offline_store if store is None else store
        names = {
            "group_name": "Название группы ЭБУ",
            "vehicle": "Данные автомобиля",
            "menu_1": "Меню 1",
            "menu_2": "Меню 2",
            "menu_3": "Меню 3",
            "menu_4": "Меню 4",
            "menu_5": "Меню 5",
            "menu_6": "Меню 6",
            "menu_7": "Меню 7",
            "menu_8": "Меню 8",
            "menu_9": "Меню 9",
            "messages": "Сохранённые сообщения",
            "ddr_attributes": "Атрибуты DDR",
            "ddr_headers": "Параметры записи DDR",
            "history_contents": "Содержимое истории операций",
            "history_headers": "Заголовки истории операций",
            "normal_coefficient_low_byte_raw": "Коэффициент обычной схемы: младший байт (raw)",
            "current_summary_display": "Отображение текущей сводки",
            "current_summary_resource": "Неразрешённый ресурс текущей сводки",
            "current_summary_display_source": "Источник отображения текущей сводки",
            "history_time_information": "Сведения о времени истории",
            "screen": "Экран",
            "text": "Текст",
            "prefix": "Префикс сообщения",
            "suffix": "Суффикс сообщения",
            "caption": "Заголовок",
            "note": "Примечание",
            "log_identifier": "Идентификатор журнала",
            "event_cause": "Причина события",
            "date_text": "Сохранённая строка даты",
            "time_text": "Сохранённая строка времени",
            "tick_count_ms": "Сохранённый счётчик GetTickCount, мс",
            "system_time_raw": "Исходные поля SYSTEMTIME",
            "contact": "Контакты пользователя и организации",
            "user_name": "Имя пользователя",
            "shop_name": "Название организации",
            "dealer_code": "Код дилера",
            "dealer_phone": "Телефон дилера",
            "shop_address": "Адрес организации",
            "shop_email": "Электронная почта организации",
            "shop_url": "Адрес сайта организации",
            "dealer_type_raw": "Исходный тип дилера",
            "default_brand_id_raw": "Исходный идентификатор марки по умолчанию",
            "settings": "Сохранённые настройки",
            "vehicle_brand_id_raw": "Исходный идентификатор марки автомобиля",
            "font_size": "Сохранённый размер шрифта",
            "language_id_raw": "Исходный идентификатор языка",
            "unit_selectors_raw": "Исходные селекторы единиц",
            "vehicle_speed": "Скорость автомобиля",
            "temperature": "Температура",
            "weight": "Масса",
            "air_flow": "Расход воздуха",
            "air_pressure": "Давление воздуха",
            "vapor_pressure": "Давление паров",
            "fuel_pressure": "Давление топлива",
            "additional_selector_raw": "Дополнительное WORD (raw)",
            "hotkeys": "Сохранённые подписи клавиш",
            "record": "Запись",
            "snapshot": "Снимок",
            "saved_file_directory": "Сохранённый каталог файлов",
            "application_product_version": "Версия исходного приложения",
            "communication_tool_version": "Версия исходного средства связи",
            "denso_os_build": "Сборка исходной платформы DENSO",
            "device": "Сохранённые сведения об интерфейсе",
            "firmware_version": "Версия прошивки",
            "dll_version": "Версия DLL",
            "api_version": "Версия API",
            "field": "Поле автомобиля",
            "category_id_raw": "Исходный идентификатор категории",
            "selection_id_raw": "Исходный идентификатор выбора",
            "information_id_raw": "Исходный идентификатор информации",
            "identifiers_raw": "Исходные идентификаторы",
            "identifier_raw": "Исходный идентификатор",
            "group": "Группа выбора",
            "normal_logical_id": "Логический ID в обычной схеме DDR",
            "present_raw": "Исходный DWORD поддержки",
            "value_raw": "Исходный DWORD значения",
            "maximum_recording_count": "Максимальное число записей",
            "specification_number_raw": "Исходный номер спецификации",
            "contents": "Содержимое",
            "strings": "Сохранённые строки",
            "time_info_raw": "Исходное поле времени",
            "display_type_raw": "Исходный тип отображения",
            "current_time": "Сохранённые компоненты текущего времени",
            "year": "Год",
            "month": "Месяц",
            "day": "День",
            "hour": "Час",
            "minute": "Минута",
            "second": "Секунда",
            "metadata_byte_raw": "Исходный байт метаданных",
            "ecu_group_type": "Числовой тип группы ЭБУ",
            "header_values_raw": "Исходные поля заголовка",
            "ecu_identifier_raw": "Исходный идентификатор ЭБУ",
            "block_count": "Число блоков",
            "total_bytes": "Всего байт",
            "blocks": "Блоки",
            "stored_size": "Сохранённый логический размер",
            "storage_bytes": "Размер хранилища, байт",
            "offset": "Смещение в файле",
            "source_path": "Путь поля в исходной записи",
            "metadata_flags_raw": "Исходные флаги метаданных",
            "flags_raw": "Исходные флаги",
            "invalidity_raw": "Исходный байт недействительности",
            "invalidity_check": "Нативная проверка недействительности",
            "invalidity_source_path": "Путь исходного байта недействительности",
            "stored_display": "Сохранённый текст значения",
            "invalid_display_resource": "Неразрешённый нативный ресурс значения",
            "native_channel_suppressed": "Нативный канал подавлен",
            "selector_raw": "Исходный селектор",
            "definition_id_raw": "Исходный идентификатор определения",
            "labels": "Сохранённые подписи",
            "result": "Результаты",
            "node": "Узел",
            "operation": "Этап",
            "events_consumed": "Записанных действий выполнено",
            "events_remaining": "Записанных действий осталось",
            "source_identity": "Источник библиотеки",
            "native_build": "Версия",
            "module": "Библиотека",
            "error_type": "Ошибка",
            "automatic_retry": "Автоматический повтор",
            "resume_authorized": "Продолжение разрешено",
            "programming_completed": "Физическое программирование подтверждено",
            "source": "Источник",
            "physical_status": "Проверка на автомобиле",
            "workflow": "Процедура",
            "summary": "Итог",
            "format": "Формат",
            "path": "Файл",
            "name": "Название",
            "value": "Значение",
            "status": "Состояние",
            "unit": "Единица",
            "samples": "Отсчёты",
            "frames": "Кадры",
            "records": "Записи",
            "channels": "Каналы",
            "events": "События",
            "steps": "Шаги",
            "count": "Количество",
            "version": "Версия",
            "ecu": "Блок",
            "ecus": "Блоки",
            "dtcs": "Коды неисправностей",
            "data": "Данные",
            "parameters": "Параметры",
            "calibration_ids": "Калибровки",
            "bytes": "Байт",
            "size": "Размер",
            "filename": "Имя файла",
            "warnings": "Примечания",
            "errors": "Ошибки",
            "codes": "Коды неисправностей",
            "measurement": "Измерение",
            "session": "Сеанс",
            "active_state": "Активный тест",
            "routine_status": "Состояние процедуры",
            "rid": "Идентификатор процедуры",
            "normal": "Нормальный ответ",
            "abnormal": "Нештатный ответ",
            "stop_pattern": "Ответ совпал с шаблоном остановки",
            "routine_info": "Флаг структуры ответа",
            "state": "Состояние",
            "operations": "Операции",
            "action": "Действие",
            "remaining_exchanges": "Осталось ответов записи",
            "remaining_driver_events": "Осталось действий связи",
            "host_simulation": "Учебная передача",
            "native_transfer_fragment": "Передача блоков",
            "transferred": "Передано байт",
            "request_hex": "Запрос, hex",
            "response_hex": "Ответ, hex",
            "write_count": "Отправлено команд",
            "usb_packets": "Пакеты USB",
            "controller": "Регистратор",
            "storage": "Значения процедуры",
            "stack": "Результаты сценария",
            "results": "Результаты",
            "physical": "Измерение",
            "raw_value": "Исходное значение",
            "raw_minimum": "Нижняя граница",
            "raw_maximum": "Верхняя граница",
            "test_name": "Название проверки",
            "minimum": "Минимум",
            "maximum": "Максимум",
            "dtc": "Код неисправности",
            "commands": "Команды",
            "profile": "Профиль системы",
            "file": "Файл",
            "category": "Категория",
            "receive_mask": "Маска ответа, hex",
            "receive_check": "Проверка ответа, hex",
            "error": "Ошибка",
            "last_error": "Последняя ошибка",
            "uncertain": "Результат не определён",
            "reply": "Ответ",
            "request": "Запрос",
            "response": "Ответ",
            "values": "Значения",
            "timestamp_raw": "Исходная метка",
            "raw": "Исходное значение",
            "attempt": "Попытка",
            "start": "Запуск",
            "stop": "Остановка",
            "phase": "Этап",
            "history": "События",
            "supported_mids": "Поддерживаемые мониторы",
            "mode": "Режим",
            "kind": "Тип",
            "scope": "Область проверки",
            "display": "Описание",
            "next_operation": "Следующая операция",
            "signals": "Параметры",
            "native_support": "Поддержка по базе",
            "native_status": "Статус обработки",
            "input_byte_count": "Байт ввода",
            "button_byte_count": "Байт команды кнопки",
            "initial_value": "Исходное значение",
            "displays": "Переключатели значения",
            "routine_inputs": "Поля ввода",
            "routine_buttons": "Кнопки процедуры",
            "controls": "Управление",
            "press": "Нажатие",
            "release": "Отпускание",
            "enabled": "Доступно",
            "captures": "Сохранённые снимки",
            "systems": "Системы",
            "functions": "Сохранённые функции",
            "error_reports": "Отчёты об ошибках",
            "memory_captures": "Снимки памяти",
            "status_markers": "Сохранённые признаки состояния",
            "status_flags_raw": "Исходные числовые флаги DTC",
            "native_settings": "Нативные настройки регистратора",
            "table_count": "Количество таблиц",
            "tables": "Таблицы",
            "header_words": "Исходные слова заголовка",
            "current": "Текущий",
            "pending": "Ожидающий",
            "permanent": "Постоянный",
            "short_name": "Короткое имя",
            "timestamp": "Время снимка",
            "freeze_frame_state_raw": "Исходное состояние стоп-кадра",
            "freeze_frame_data_check": "Freeze frame data check",
            "freeze_frame_marker": "Маркер freeze frame",
            "freeze_frame_number_raw": "Исходный номер стоп-кадра",
            "consumed_steps": "Воспроизведено действий",
            "total_steps": "Всего записанных действий",
            "cleanup_calls": "Завершающие действия",
            "watch_statuses": "Состояния окна запроса",
            "message_count": "Количество сообщений",
            "unlocking_value_present": "Ответ содержит ключевое значение",
            "signature_characters": "Длина приложенного ключа",
            "dismissal": "Закрытие уведомления",
            "omitted": "Пропущенные параметры",
            "signal_key": "Ключ параметра",
            "responses_hex": "Ответы, hex",
            "messages_hex": "Сообщения, hex",
            "data_hex": "Данные, hex",
            "function_id": "Идентификатор функции",
            "payload_hex": "Содержимое записи, hex",
            "tick": "Исходная метка",
            "elapsed_ms": "От начала, мс",
            "catalog": "Таблицы параметров",
            "parameter_keys": "Ключи параметров",
            "can_id_rows": "Строки адресов CAN",
            "logical_address_rows": "Логические адреса",
            "vehicle_compatibility_validated": "Совместимость с автомобилем проверена",
            "programming_authorized": "Программирование разрешено",
            "module_version_checked": "Версия библиотеки проверена",
            "modules": "Библиотеки",
            "exports": "Функции",
            "required_exports": "Требуемые функции",
            "selectors": "Правила выбора адресов",
            "addresses": "Адреса",
            "sources": "Исходные файлы",
            "rows": "Строки",
            "columns": "Столбцы",
            "key": "Ключ",
            "stage": "Этап",
            "plan": "План",
            "existing_files_replaced": "Существующие файлы заменены",
            "verification": "Проверка",
            "authenticity": "Подлинность",
            "code": "Код",
            "description": "Описание",
            "comment": "Комментарий",
            "native_clear_flag": "Исходный флаг удаления ошибок",
            "ECUName": "Название ЭБУ",
            "ECUId": "Идентификатор ЭБУ",
            "DTCCode": "Код неисправности",
            "DTCDispValue": "Код неисправности",
            "DTCName": "Описание неисправности",
            "DTCTypeName": "Тип неисправности из отчёта",
            "StatusGridName": "Состояние из отчёта",
            "family": "Раздел отчёта",
            "ecu_index": "Номер ЭБУ в отчёте",
            "address": "Адрес RAM, hex",
            "requested_bytes": "Запрошено байт",
            "received_bytes": "Получено байт",
            "direct_read": "Непосредственное чтение без кэша",
            "transactions": "Записанные обмены",
        }
        values = {
            "selection_identity": "Идентификатор выбранного автомобиля",
            "selection_choice": "Выбранный вариант",
            "vin_code": "Код VIN из исходного выбора",
            "selection_name": "Название выбранного варианта",
            "car_information": "Сведения об автомобиле",
            "option_name": "Название опции",
            "vehicle_type": "Тип автомобиля",
            "model_year": "Модельный год",
            "alternate_model_year": "Альтернативный модельный год",
            "engine": "Двигатель",
            "message": "Сообщение",
            "confirmation": "Подтверждение",
            "authored_synthetic": "Учебные данные",
            "PHYSICAL_UNCONFIRMED": "Не выполнена",
            "True": "Да",
            "False": "Нет",
            "completed": "Выполнено",
            "write": "Запись",
            "read": "Чтение",
            "prepare": "Подготовка",
            "recovery": "Восстановление",
            "get_cid": "Чтение идентификатора",
            "ok": "Успешно",
            "idle": "Остановлен",
            "inactive": "Остановлен",
            "stopped": "Остановлен",
            "running": "Выполняется",
            "cancelled": "Отменено",
            "start": "Запуск",
            "step": "Шаг",
            "stop": "Остановка",
            "completion_pattern_matched": "Ответ совпал с шаблоном завершения",
            "writer_completed": "Записанный этап записи воспроизведён",
            "read_completed": "Записанный этап чтения воспроизведён",
            "prepare_completed": "Записанная подготовка воспроизведена",
            "preparation_completed": "Записанная подготовка воспроизведена",
            "prepare_retry_completed": "Записанная повторная подготовка воспроизведена",
            "recovery_completed": "Записанное восстановление воспроизведено",
            "probe_completed": "Записанная проверка воспроизведена",
            "passed": "Пройдено",
            "pass": "Пройдено",
            "fail": "Не пройдено",
            "partial": "Данные получены частично",
            "unresolved_scaling": "Преобразование не установлено",
            "failed": "Не пройдено",
            "fragment_completed": "Блоки переданы",
            "none": "Нет",
            "unknown": "Не определено",
            "clear_dtc": "Удаление ошибок по записи",
            "clear_dtc_mazda": "Удаление ошибок Mazda по записи",
            "clear_dtc_psa": "Удаление ошибок PSA по записи",
            "clear_dtc_p4": "Удаление ошибок P4 по записи",
            "clear_dtc_vgrs": "Удаление ошибок VGRS по записи",
            "operation_freeze_p4": "Стоп-кадры операций P4",
        }
        details = {
            "schema",
            "source_path",
            "port_sources",
            "source_identity",
            "source_paths",
            "source",
            "workflow",
            "provenance",
            "provider",
            "definition_source",
            "text_ids",
            "trace",
            "plan_sha256",
            "patterns",
            "input_hashes",
            "management_sha256",
            "ecu_sha256",
            "selection",
            "physical_status",
            "native_control_wire",
            "communication",
            "capabilities",
            "exception_ids",
            "vehicle_name_key",
            "native_34",
            "sha256",
        }

        native_report = False

        def append(value, trail=()):
            if store.get_n_items() >= 1000:
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    if key == "short_name" and "group_name" in value:
                        continue
                    if (
                        key in details
                        or str(key).endswith("_sha256")
                        or (
                            str(key).endswith("_hex")
                            and key
                            not in (
                                "request_hex",
                                "response_hex",
                                "messages_hex",
                                "data_hex",
                                "responses_hex",
                                "payload_hex",
                            )
                        )
                    ):
                        continue
                    append(
                        child, (*trail, names.get(str(key), str(key).replace("_", " ")))
                    )
            elif isinstance(value, list):
                if not value:
                    append("Нет записей", trail)
                for index, child in enumerate(value):
                    append(child, (*trail, str(index + 1)))
            else:
                text = "—" if value is None else str(value)
                title = (
                    f"{trail[-1]} · {' / '.join(trail[:-1])}"
                    if native_report and len(trail) > 1
                    else " / ".join(trail)
                )
                if len(text) > 2048:
                    text = text[:2048] + "… (полные данные в JSON)"
                if len(title) > 512:
                    title = title[:512] + "…"
                translated = (
                    values.get(text, text)
                    if not native_report
                    or (trail and trail[-1] in ("Поле автомобиля", "Экран"))
                    or (
                        trail
                        and trail[0] == "Данные автомобиля"
                        and trail[-1] == "Название"
                    )
                    else text
                )
                store.append(Parameter({"name": title, "value": translated}))

        result = report.get("result", {})
        if result.get("report_views"):
            index = self.offline_report_view.get_selected()
            if 0 < index <= len(result["report_views"]):
                result = result["report_views"][index - 1]
        if report.get("workflow") == "monitor_replay" and result.get("outputs"):
            selected = self.monitor_output.get_selected()
            if selected < len(self.monitor_output_ids):
                stream = self.monitor_output_ids[selected]
                result = next(row for row in result["outputs"] if row["id"] == stream)
        native_report = (
            "family" in result
            or result.get("format") == "all-dtc-xml"
            or report.get("workflow") in ("native_utility_replay", "monitor_replay")
        )
        if "family" in result:
            semantic_keys = (
                "messages",
                "error_reports",
                "vehicle",
                "ddr_headers",
                "ddr_attributes",
                "history_headers",
                "history_time_information",
                "history_contents",
                "parameters",
                "systems",
                "captures",
                "events",
                "monitors",
                "functions",
                "images",
                "memory_captures",
                "dtcs",
            )
            result = {
                "family": result["family"],
                **{key: result[key] for key in semantic_keys if result.get(key)},
            }
        if store is self.offline_store:
            self.offline_dtc_store.remove_all()
            dtcs = result.get("dtcs", []) if "family" in result else []
            for dtc in dtcs[:1000]:
                self.offline_dtc_store.append(
                    Parameter(
                        {
                            "code": dtc["code"],
                            "description": dtc["description"],
                            **{
                                key: (
                                    "Поле отсутствует"
                                    if dtc["status_markers"].get(key) is None
                                    else dtc["status_markers"][key]
                                )
                                for key in (
                                    "current",
                                    "pending",
                                    "history",
                                    "permanent",
                                )
                            },
                        }
                    )
                )
            self.offline_dtc_table.set_visible(bool(dtcs))
            self.offline_parameter_store.remove_all()
            for parameter in result.get("parameters", []) if "family" in result else []:
                for value in parameter.get("values", []):
                    if self.offline_parameter_store.get_n_items() >= 1000:
                        break
                    self.offline_parameter_store.append(
                        Parameter(
                            {
                                key: str(item)[:2048] if item is not None else "—"
                                for key, item in {
                                    "name": parameter["name"],
                                    "identifier": parameter["identifier_raw"],
                                    "display": (
                                        value["invalid_display_resource"]
                                        if value.get("invalidity_check")
                                        else value["display"]
                                    ),
                                    "unit": parameter["unit"],
                                    "raw": value["raw"],
                                    "flags": value["flags_raw"],
                                }.items()
                            }
                        )
                    )
                if self.offline_parameter_store.get_n_items() >= 1000:
                    break
            self.offline_parameter_table.set_visible(
                bool(self.offline_parameter_store.get_n_items())
            )
        playback = result.get("playback", result)
        samples = playback.get("samples", [])
        if samples:
            if "trigger_timestamp_raw" in result:
                append(result["trigger_timestamp_raw"], ("Метка триггера",))
            for index, sample in enumerate(samples[:1000]):
                for value in sample["values"]:
                    append(
                        f"{value.get('display', value['value'])} {value['unit']}",
                        (
                            f"Отсчёт {index + 1} · метка {sample.get('timestamp_raw', '—')}",
                            value["name"],
                        ),
                    )
        else:
            data = result or report
            if data.get("format") == "all-dtc-xml":
                append(data.get("vehicle", {}), ("Автомобиль из отчёта",))
                for ecu in data.get("ecus", []):
                    title = ecu.get("ECUName") or ecu.get("ECUId") or "ЭБУ без названия"
                    append(ecu.get("ECUId"), (title, "Идентификатор ЭБУ"))
                    append(ecu.get("dtcs", []), (title, "Неисправности"))
            elif report.get("workflow") == "ram_replay":
                append(report["status"], ("Воспроизведение записи",))
                append(result)
            elif report.get("workflow") == "toyota_workflow":
                append(report["operation"], ("Процедура",))
                append(report["status"], ("Воспроизведение записи",))
                append(report["event_count"], ("Выполнено записанных действий",))
                append(report["events_remaining"], ("Осталось записанных действий",))
                append(report.get("error"), ("Ошибка",))
                append(result)
            elif report.get("workflow") == "active_replay" or (
                report.get("workflow") == "active_initialization" and "status" in report
            ):
                selected = report.get("initialization") or report.get(
                    "selected_test", {}
                )
                append(selected.get("name", "Имя не получено"), ("Тест",))
                for event in report.get("events", []):
                    for state in event.get("routine_status", []):
                        append(
                            state["normal"],
                            (f"Процедура {state['rid']} / нормальный ответ",),
                        )
                        append(
                            state["abnormal"],
                            (f"Процедура {state['rid']} / нештатный ответ",),
                        )
                        append(
                            state["stop_pattern"],
                            (f"Процедура {state['rid']} / шаблон остановки",),
                        )
                        if store.get_n_items() >= 1000:
                            break
                    if store.get_n_items() >= 1000:
                        break
                append(report["status"], ("Воспроизведение записи",))
                append(report.get("state"), ("Состояние теста",))
                for key in ("remaining_exchanges", "remaining_driver_events"):
                    if key in report:
                        append(report[key], (names[key],))
                if report.get("semantic_status") == "native-lifecycle-observed":
                    append(
                        "Наблюдались записанные действия теста", ("Область проверки",)
                    )
                if report.get("error"):
                    append(report["error"], ("Ошибка",))
                append(report.get("events", []), ("События теста",))
            elif report.get("workflow") == "programming_replay":
                append(report.get("state"), ("Результат этапа",))
                for key in (
                    "operation",
                    "node",
                    "events_consumed",
                    "events_remaining",
                    "error",
                ):
                    if key in report:
                        append(report[key], (names[key],))
                append(
                    report.get("programming_completed", False),
                    ("Физическое программирование подтверждено",),
                )
            elif report.get("workflow") == "service_replay":
                kind = data["kind"]
                if "error_type" in data:
                    outcome = "Воспроизведение не завершено: " + data["error_type"]
                elif data.get("watch_statuses"):
                    code = data["watch_statuses"][-1]
                    outcome = {
                        0: "Страница сообщила об одобрении (0)",
                        11: "Поле результата пусто (11)",
                        12: "Ожидание ответа (12)",
                    }.get(code, str(code))
                elif "native_status" in data:
                    code = data["native_status"]
                    outcome = {
                        1: "Ответ принят алгоритмом (1)",
                        50: "Ответ не принят алгоритмом (50)",
                    }.get(code, f"Код ответа: {code}")
                elif "dismissal" in data:
                    outcome = {
                        "key": "Уведомление закрыто по клавише",
                        "click": "Уведомление закрыто нажатием",
                        "cursor": "Уведомление закрыто движением курсора",
                    }.get(data["dismissal"], str(data["dismissal"]))
                else:
                    outcome = "Ответ не наблюдался"
                append(outcome, ("Результат",))
                append(
                    {
                        "tis-check": "Проверка TIS",
                        "tis-save": "Отправка TIS",
                        "euro-online": "Обращение Euro",
                        "euro-save": "Отправка Euro",
                        "euro-key": "Запрос ключа Euro",
                        "rks": "Окно запроса RKS",
                        "notice": "Уведомление о завершении",
                    }.get(kind, kind),
                    ("Операция",),
                )
                append(report["status"], ("Воспроизведение записи",))
                if "native_status" in data:
                    code = data["native_status"]
                    append(
                        {
                            1: "Ответ принят алгоритмом (1)",
                            50: "Ответ не принят алгоритмом (50)",
                        }.get(code, str(code)),
                        ("Ответ сервиса",),
                    )
                if "watch_statuses" in data:
                    for index, code in enumerate(data["watch_statuses"], 1):
                        append(
                            {
                                0: "Страница сообщила об одобрении (0)",
                                11: "Поле результата пусто (11)",
                                12: "Ожидание ответа (12)",
                            }.get(code, str(code)),
                            (f"Проверка окна {index}",),
                        )
                append(
                    f"{data['consumed_steps']} / {data['total_steps']}",
                    ("Воспроизведено действий",),
                )
                for key in (
                    "cleanup_calls",
                    "message_count",
                    "unlocking_value_present",
                    "signature_characters",
                    "dismissal",
                    "elapsed_ms",
                    "error_type",
                ):
                    if key in data:
                        append(data[key], (names.get(key, "Ошибка"),))
                append("Не проверено", ("Право программирования",))
            elif data.get("dtcs"):
                append(data.get("family"), ("Раздел отчёта",))
                append({key: value for key, value in data.items() if key != "dtcs"})
                for dtc in data["dtcs"]:
                    title = dtc.get("code") or "Код не указан"
                    append(dtc.get("description"), (title, "Описание"))
                    append(dtc.get("comment"), (title, "Комментарий"))
                    for key in (
                        "freeze_frame_data_check",
                        "freeze_frame_marker",
                        "freeze_frame_state_raw",
                        "freeze_frame_number_raw",
                    ):
                        if key in dtc:
                            append(dtc[key], (title, names[key]))
                    if "status_flags_raw" in dtc:
                        for flag, flag_title in (
                            ("current", "Текущий"),
                            ("history", "История"),
                            ("pending", "Ожидающий"),
                            ("permanent", "Постоянный"),
                        ):
                            append(
                                dtc["status_flags_raw"].get(flag),
                                (title, names["status_flags_raw"], flag_title),
                            )
                    for key, title_text in (
                        ("current", "Текущий"),
                        ("history", "История"),
                        ("pending", "Ожидающий"),
                        ("permanent", "Постоянный"),
                    ):
                        marker = dtc.get("status_markers", {}).get(key)
                        append(
                            "Поле отсутствует" if marker is None else marker,
                            (title, title_text),
                        )
            elif "signals" in data and isinstance(data["signals"], list):
                for signal in data["signals"]:
                    title = signal.get(
                        "name", f"Параметр {signal.get('signal_key', '—')}"
                    )
                    value = signal.get("value", {})
                    if isinstance(value, dict):
                        unit = signal.get("unit", value.get("unit"))
                        append(
                            f"{value.get('display', value.get('value', '—'))} {unit or '(единица не определена)'}",
                            (title, "Значение"),
                        )
                    else:
                        append(value, (title, "Значение"))
                    append(signal.get("native_support"), (title, "Поддержка по базе"))
                append(
                    {
                        key: data[key]
                        for key in ("status", "errors", "omitted")
                        if key in data
                    }
                )
            elif isinstance(data.get("values"), list):
                for index, value in enumerate(data["values"]):
                    if all(key in value for key in ("name", "value", "unit")):
                        title, text = measurement_text(value)
                        append(text, (title,))
                    else:
                        append(value, (f"Параметр {index + 1}",))
                append(
                    {
                        key: data[key]
                        for key in ("status", "errors", "unresolved_pids")
                        if key in data
                    }
                )
            elif isinstance(data.get("values"), dict):
                info_names = {"02": "VIN", "04": "CALID", "06": "CVN"}
                append(
                    {
                        info_names.get(key, f"Сведения 0x{key}"): value
                        for key, value in data["values"].items()
                    }
                )
                append(
                    {
                        key: data[key]
                        for key in ("status", "errors", "unresolved_info_types")
                        if key in data
                    }
                )
            elif "results" in data:
                for index, row in enumerate(data["results"]):
                    if isinstance(row, dict) and all(
                        key in row for key in ("mid", "tid", "value", "unit")
                    ):
                        title = f"Монитор {row['mid']} · тест {row['tid']}"
                        append(f"{row['value']} {row['unit']}", (title, "Значение"))
                        if "minimum" in row and "maximum" in row:
                            append(
                                f"{row['minimum']} … {row['maximum']} {row['unit']}",
                                (title, "Допустимые пределы"),
                            )
                        append(row.get("status", "unknown"), (title, "Результат"))
                        append(
                            row.get("test_name", "unknown").replace("_", " "),
                            (title, "Название проверки"),
                        )
                    else:
                        append(row, (f"Проверка {index + 1}",))
                append(
                    {
                        key: data[key]
                        for key in ("status", "errors", "unresolved_tids")
                        if key in data
                    }
                )
            elif "supported_pids" in data:
                append(
                    ", ".join(f"{value:02X}" for value in data["supported_pids"])
                    or "Нет",
                    ("Поддерживаемые PID, hex",),
                )
                append(
                    {
                        key: value
                        for key, value in data.items()
                        if key not in ("source", "physical_status", "supported_pids")
                    }
                )
            else:
                append(data)
        if store.get_n_items() >= 1000:
            store.append(
                Parameter(
                    {
                        "name": "Показаны первые 1000 показателей",
                        "value": "Полные данные доступны в сохранённом отчёте JSON",
                    }
                )
            )
        if not include_chart:
            return
        self.offline_samples = samples
        if samples and samples[0].get("values"):
            numeric = {value["pid"] for value in samples[0]["values"]}
            for sample in samples:
                numeric.intersection_update(
                    {
                        value["pid"]
                        for value in sample["values"]
                        if type(value.get("value")) in (int, float)
                        and math.isfinite(value["value"])
                    }
                )
            self.offline_chart_values = [
                value for value in samples[0]["values"] if value["pid"] in numeric
            ]
            self.offline_chart_choice.set_model(
                Gtk.StringList.new(
                    [
                        f"{value['name']} · {value['unit']}"
                        for value in self.offline_chart_values
                    ]
                )
            )
            self.update_offline_chart()
            stamps = [
                str(sample["timestamp_raw"])
                for sample in self.offline_samples[:12]
                if "timestamp_raw" in sample
            ]
            if self.offline_picture.get_paintable() is not None:
                self.offline_time.set_text(
                    "Ось X — порядок отсчётов. Исходные метки: "
                    + ", ".join(stamps)
                    + ("…" if len(self.offline_samples) > 12 else "")
                    + ". Единицы времени не установлены."
                )
            self.offline_chart.set_visible(bool(self.offline_chart_values))
        self.offline_raw.get_buffer().set_text(self.report_preview(report))

    @staticmethod
    def report_preview(report):
        chunks, size = [], 0
        for chunk in json.JSONEncoder(ensure_ascii=False, indent=2).iterencode(report):
            remaining = 100000 - size
            chunks.append(chunk[:remaining])
            if len(chunk) > remaining:
                chunks.append("\n… Полный отчёт доступен при сохранении JSON.")
                break
            size += len(chunk)
        return "".join(chunks)

    def update_offline_chart(self, *_args):
        selected = self.offline_chart_choice.get_selected()
        values = getattr(self, "offline_chart_values", [])
        if selected >= len(values):
            return
        try:
            svg = sample_chart(self.offline_samples, values[selected]["pid"])
            self.set_chart(self.offline_picture, svg)
        except (ValueError, KeyError) as exc:
            self.offline_picture.set_paintable(None)
            self.offline_time.set_text(f"График недоступен: {exc}")

    def copy_offline(self, *_args):
        source = self.offline_source
        if source is None or self.offline_report is None:
            return
        chooser = Gtk.FileDialog(
            title="Сохранить копию записи без изменений",
            initial_name=f"{source.stem}-copy{source.suffix}",
        )

        def finished(dialog, result):
            try:
                path = dialog.save_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                if not self.closed and not self.offline_busy:
                    self.start_native_copy(source, Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(f"Не удалось сохранить копию: {exc}")

        chooser.save(self.window, None, finished)

    def start_native_copy(self, source, destination):
        self.start_offline_write(
            lambda: copy_native(source, destination),
            "Копия записи сохранена без изменения байтов.",
        )

    def start_offline_write(self, operation, message):
        if self.offline_busy or self.closed:
            return
        self.offline_busy = True
        self.offline_write_copy_enabled = self.offline_copy.get_sensitive()
        for widget in (
            self.offline_run,
            self.offline_open,
            self.offline_choice,
            self.offline_export,
            self.offline_copy,
            self.offline_catalog_open,
            self.offline_catalog_controls,
            self.offline_procedure_controls,
            self.offline_recorder_controls,
            self.offline_monitor_controls,
            self.native_utility_form,
            self.offline_programming_controls,
            self.offline_active_controls,
            self.programming_form,
            self.offline_buffer,
        ):
            widget.set_sensitive(False)
        self.offline_status.set_text("Проверка и сохранение файла…")

        def work():
            try:
                operation()
                error = ""
            except Exception as exc:  # noqa: BLE001 - every write failure restores controls.
                error = str(exc) or type(exc).__name__
            GLib.idle_add(self.offline_write_ready, error, message)

        self.offline_thread = threading.Thread(target=work, name="techstream-export")
        self.offline_thread.start()

    def offline_write_ready(self, error, message):
        self.offline_busy = False
        if self.closed:
            return GLib.SOURCE_REMOVE
        for widget in (
            self.offline_run,
            self.offline_open,
            self.offline_choice,
            self.offline_export,
            self.offline_copy,
            self.offline_catalog_open,
            self.offline_catalog_controls,
            self.offline_procedure_controls,
            self.offline_recorder_controls,
            self.offline_monitor_controls,
            self.native_utility_form,
            self.offline_programming_controls,
            self.offline_active_controls,
            self.programming_form,
            self.offline_buffer,
        ):
            widget.set_sensitive(True)
        self.offline_copy.set_sensitive(self.offline_write_copy_enabled)
        self.offline_status.set_text(
            f"Не удалось сохранить файл: {error}" if error else message
        )
        if self.smoke_test:
            GLib.idle_add(self.check_offline_smoke)
        return GLib.SOURCE_REMOVE

    def export_offline(self, *_args):
        report, source = self.offline_report, self.offline_source
        sources = self.offline_sources
        if report is None:
            return
        chooser = Gtk.FileDialog(
            title="Сохранить отчёт", initial_name="offline-report.json"
        )

        def finished(dialog, result):
            try:
                path = dialog.save_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                self.start_offline_write(
                    lambda: save_report(
                        Path(path), report, source=source, sources=sources
                    ),
                    "Отчёт сохранён.",
                )
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(f"Не удалось сохранить отчёт: {exc}")

        chooser.save(self.window, None, finished)

    def start_example(self, *_args):
        filenames = (
            "diagnostic-session.json",
            "live-session.json",
            "calibration-session.json",
            "monitors-session.json",
            "support-session.json",
            "parameters-session.json",
            "vehicle-info-session.json",
        )
        self.session_ecu.set_text("")
        self.session_service.set_selected(0)
        self.session_sensor.set_value(1)
        self.session_pids.set_text("")
        self.session_freeze.set_active(False)
        if self.session_mode.get_selected() == 1:
            self.session_samples.set_value(12)
        self.start_session(
            PROJECT / "examples" / filenames[self.session_mode.get_selected()]
        )

    def start_session(self, path):
        if self.session_busy:
            return
        mode = self.session_mode.get_selected()
        try:
            pids = parse_pids(self.session_pids.get_text()) if mode == 5 else None
        except ValueError as exc:
            self.session_summary.set_text(str(exc))
            return
        ecu = self.session_ecu.get_text().strip() or None
        service = (1, 2, 5, 6, 9)[self.session_service.get_selected()]
        sensor = self.session_sensor.get_value_as_int()
        freeze = self.session_freeze.get_active()
        self.session_busy = True
        self.session_report = None
        self.session_source = path
        self.session_cancel.clear()
        self.session_example.set_sensitive(False)
        self.session_open.set_sensitive(False)
        self.session_mode.set_sensitive(False)
        self.session_samples.set_sensitive(False)
        for widget in (
            self.session_ecu,
            self.session_support_options,
            self.session_parameter_options,
        ):
            widget.set_sensitive(False)
        self.session_stop.set_sensitive(True)
        self.session_export.set_sensitive(False)
        while child := self.session_results.get_first_child():
            self.session_results.remove(child)
        self.session_summary.set_text("Чтение записи и разбор ответов…")

        operation = (
            "replay",
            "poll",
            "calibration",
            "monitors",
            "support",
            "parameters",
            "vehicle_info",
        )[mode]
        self.session_operation = operation
        samples = self.session_samples.get_value_as_int()

        def work():
            try:
                report, error = (
                    replay_session(
                        path,
                        self.session_cancel.is_set,
                        operation=operation,
                        samples=samples,
                        ecu=ecu,
                        service=service,
                        sensor=sensor,
                        pids=pids,
                        freeze=freeze,
                    ),
                    "",
                )
            except Exception as exc:  # noqa: BLE001 - every provider failure restores controls.
                report, error = None, str(exc) or type(exc).__name__
                code = getattr(exc, "code", None)
                if type(code) is int:
                    error += f" · Код ошибки: {code}"
                    if 0 <= code <= 0xFFFFFFFF:
                        error += f" (0x{code:08X})"
            GLib.idle_add(self.session_ready, report, error)

        self.session_thread = threading.Thread(target=work, name="techstream-replay")
        self.session_thread.start()

    def session_ready(self, report, error):
        self.session_busy = False
        if self.closed:
            return GLib.SOURCE_REMOVE
        self.session_example.set_sensitive(True)
        self.session_open.set_sensitive(True)
        self.session_mode.set_sensitive(True)
        self.session_samples.set_sensitive(self.session_mode.get_selected() == 1)
        for widget in (
            self.session_ecu,
            self.session_support_options,
            self.session_parameter_options,
        ):
            widget.set_sensitive(True)
        self.session_stop.set_sensitive(False)
        if self.session_cancel.is_set():
            report, error = None, "Воспроизведение отменено."
        if report is None:
            self.session_summary.set_text(f"Сеанс не завершён: {error}")
            if self.smoke_test:
                self.finish_smoke(AssertionError(error))
            return GLib.SOURCE_REMOVE
        self.session_report = report
        self.session_export.set_sensitive(True)
        source = (
            "Синтетическая запись"
            if report["source"] == "authored_synthetic"
            else "Запись обмена; происхождение не подтверждено"
        )
        if self.session_operation in (
            "monitors",
            "support",
            "parameters",
            "vehicle_info",
        ):
            status = {"ok": "успешно", "partial": "данные получены частично"}.get(
                report.get("status"), "прочитано"
            )
            self.session_summary.set_text(
                f"{source} · {report['ecu']}\nАвтомобиль не подключён. Результат: {status}."
            )
            store = Gio.ListStore.new(Parameter)
            self.render_offline(report, store=store, include_chart=False)
            self.session_value_store = store
            table = Gtk.ColumnView(
                model=Gtk.NoSelection(model=store), show_row_separators=True
            )
            for title, field in (("Показатель", "name"), ("Результат", "value")):
                factory = Gtk.SignalListItemFactory()
                factory.connect("setup", self.cell_setup)
                factory.connect("bind", self.cell_bind, field)
                column = Gtk.ColumnViewColumn.new(title, factory)
                column.set_expand(True)
                column.set_resizable(True)
                table.append_column(column)
            self.session_results.append(
                Gtk.ScrolledWindow(child=table, min_content_height=230, vexpand=True)
            )
            raw = Gtk.TextView(
                editable=False,
                cursor_visible=False,
                monospace=True,
                wrap_mode=Gtk.WrapMode.WORD_CHAR,
            )
            raw.get_buffer().set_text(self.report_preview(report))
            details = Gtk.Expander(label="Подробности отчёта JSON")
            details.set_child(
                Gtk.ScrolledWindow(
                    child=raw, min_content_height=130, max_content_height=200
                )
            )
            self.session_results.append(details)
            if self.smoke_test:
                GLib.idle_add(self.check_extended_session_smoke)
            return GLib.SOURCE_REMOVE
        if "samples" in report:
            self.session_summary.set_text(
                f"{source} · отсчётов: {len(report['samples'])}\nАвтомобиль не подключён. Ось X — порядок отсчётов записи."
            )
            self.plot_parameter = Gtk.DropDown.new_from_strings(
                [measurement_text(value)[0] for value in report["samples"][0]["values"]]
            )
            self.plot_picture = Gtk.Picture(can_shrink=True, keep_aspect_ratio=True)
            self.plot_picture.set_tooltip_text(
                "Значения выбранного параметра по порядку отсчётов"
            )
            self.plot_parameter.connect("notify::selected", self.update_session_plot)
            self.session_results.append(self.plot_parameter)
            self.session_results.append(self.plot_picture)
            self.plot_parameter.set_selected(1)
            self.update_session_plot()
            if self.smoke_test and self.smoke_stage == 5:
                self.smoke_stage = 6
                GLib.idle_add(self.check_smoke)
            return GLib.SOURCE_REMOVE
        if "calibration_ids" in report or "supported_info_types" in report:
            self.session_summary.set_text(
                f"{source} · {report['ecu']}\nИдентификаторы из записи; автомобиль не подключён."
            )
            group = Adw.PreferencesGroup(title="Идентификаторы калибровки")
            for field, title in (("calibration_ids", "CALID"), ("cvns", "CVN")):
                group.add(
                    Adw.ActionRow(
                        title=title,
                        subtitle=GLib.markup_escape_text(
                            ", ".join(report.get(field, [])) or "Не прочитано"
                        ),
                    )
                )
            for error in report["errors"]:
                group.add(
                    Adw.ActionRow(
                        title="Ошибка чтения",
                        subtitle=GLib.markup_escape_text(error["message"]),
                    )
                )
            self.session_results.append(group)
            if self.smoke_test and self.smoke_stage == 7:
                self.smoke_stage = 8
                GLib.idle_add(self.check_smoke)
            return GLib.SOURCE_REMOVE
        partial = sum(ecu["status"] != "ok" for ecu in report["ecus"])
        self.session_summary.set_text(
            f"{source} · систем: {len(report['ecus'])} · с ошибками чтения: {partial}\nАвтомобиль не подключён. Результат получен из файла."
        )
        for ecu in report["ecus"]:
            group = Adw.PreferencesGroup(
                title={"engine": "Двигатель", "transmission": "Трансмиссия"}.get(
                    ecu["ecu"], ecu["ecu"]
                )
            )

            def add(title, text, group=group):
                group.add(
                    Adw.ActionRow(
                        title=GLib.markup_escape_text(title),
                        subtitle=GLib.markup_escape_text(str(text)) or "—",
                    )
                )

            add("VIN", ecu.get("vin", "Не прочитан"))
            for field, title in (
                ("stored_dtcs", "Сохранённые ошибки"),
                ("pending_dtcs", "Ожидающие ошибки"),
                ("permanent_dtcs", "Постоянные ошибки"),
            ):
                codes = ecu.get(field)
                add(
                    title,
                    ", ".join(codes)
                    if codes
                    else ("Нет" if codes is not None else "Не прочитаны"),
                )
            readiness = ecu.get("readiness")
            if readiness:
                monitors = [m for m in readiness["monitors"] if m["supported"]]
                add(
                    "Готовность мониторов",
                    f"Завершено: {sum(bool(m['complete']) for m in monitors)} из {len(monitors)} · MIL: {'включена' if readiness['mil_on'] else 'выключена'}",
                )
            for value in ecu.get("live", []):
                add(*measurement_text(value))
            if "freeze_dtc" in ecu:
                add("Ошибка стоп-кадра", ecu["freeze_dtc"] or "Нет")
            for value in ecu.get("freeze", []):
                title, text = measurement_text(value)
                add(f"Стоп-кадр · {title}", text)
            for failure in ecu["errors"]:
                add(f"Ошибка чтения · {failure['field']}", failure["message"])
            self.session_results.append(group)
        if self.smoke_test and self.smoke_stage == 3:
            self.smoke_stage = 4
            GLib.idle_add(self.check_smoke)
        return GLib.SOURCE_REMOVE

    def update_session_plot(self, *_args):
        report = self.session_report
        if report is None or "samples" not in report:
            return
        selected = self.plot_parameter.get_selected()
        values = report["samples"][0]["values"]
        if selected >= len(values):
            return
        svg = sample_chart(report["samples"], values[selected]["pid"])
        self.set_chart(self.plot_picture, svg)

    @staticmethod
    def set_chart(picture, svg):
        loader = GdkPixbuf.PixbufLoader.new_with_type("svg")
        loader.write(svg.encode("utf-8"))
        loader.close()
        pixbuf = loader.get_pixbuf()
        if pixbuf is not None:
            pixel_format = (
                Gdk.MemoryFormat.R8G8B8A8
                if pixbuf.get_has_alpha()
                else Gdk.MemoryFormat.R8G8B8
            )
            picture.set_paintable(
                Gdk.MemoryTexture.new(
                    pixbuf.get_width(),
                    pixbuf.get_height(),
                    pixel_format,
                    pixbuf.read_pixel_bytes(),
                    pixbuf.get_rowstride(),
                )
            )

    def open_session(self, *_args):
        chooser = Gtk.FileDialog(title="Открыть запись диагностического обмена")

        def finished(dialog, result):
            try:
                path = dialog.open_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                self.start_session(Path(path))
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(str(exc))

        chooser.open(self.window, None, finished)

    def export_session(self, *_args):
        report = self.session_report
        source = self.session_source
        if report is None:
            return
        chooser = Gtk.FileDialog(
            title="Сохранить диагностический отчёт",
            initial_name="diagnostic-report.json",
        )

        def finished(dialog, result):
            try:
                path = dialog.save_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                save_report(Path(path), report, source=source)
                self.toast("Диагностический отчёт сохранён.")
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(f"Не удалось сохранить отчёт: {exc}")

        chooser.save(self.window, None, finished)

    def load_diagnostics(self):
        if self.diagnostics_loading:
            return
        self.diagnostics_loading = True
        self.diagnostic_generation += 1
        generation = self.diagnostic_generation
        region = self.root.parent.name.removeprefix("Techstream_Data_")
        root = self.root.parent.parent / f"Techstream_DB_{region}"
        self.diagnostic_status.set_text("Чтение баз ЭБУ и языковых ресурсов…")
        self.system_choice.set_sensitive(False)

        def work():
            try:
                catalog, error = DiagnosticCatalog(root), ""
            except (OSError, ValueError) as exc:
                catalog, error = None, str(exc)
            GLib.idle_add(self.diagnostics_ready, generation, catalog, error)

        threading.Thread(target=work, daemon=True, name="techstream-databases").start()

    def diagnostics_ready(self, generation, catalog, error):
        if self.closed or generation != self.diagnostic_generation:
            return GLib.SOURCE_REMOVE
        self.diagnostics_loading = False
        self.diagnostics = catalog
        if catalog is None:
            self.diagnostic_status.set_text(f"Не удалось открыть базы: {error}")
            if self.smoke_test:
                self.finish_smoke(AssertionError(error))
            return GLib.SOURCE_REMOVE
        self.system_choice.set_model(
            Gtk.StringList.new(
                [
                    f"{row['name'] or row['short_name'] or 'Система без названия'} · {row['file']}"
                    for row in catalog.systems
                ]
            )
        )
        self.system_choice.set_sensitive(True)
        self.choose_diagnostic_system()
        if self.smoke_test and self.smoke_stage == 2:
            GLib.idle_add(self.check_smoke)
        return GLib.SOURCE_REMOVE

    def choose_diagnostic_system(self, *_args):
        self.diagnostic_database = None
        self.diagnostic_store.remove_all()
        if self.diagnostics is None:
            return
        selected = self.system_choice.get_selected()
        if selected >= len(self.diagnostics.systems):
            return
        system = self.diagnostics.systems[selected]
        try:
            self.diagnostic_database = self.diagnostics.read_system(system["file"])
        except (OSError, ValueError) as exc:
            self.diagnostic_status.set_text(
                f"Не удалось открыть {system['file']}: {exc}"
            )
            return
        self.filter_diagnostics()

    def filter_diagnostics(self, *_args):
        if self.diagnostics is None or self.diagnostic_database is None:
            return
        self.diagnostic_store.remove_all()
        slot = (5, 10, 14, 15)[self.diagnostic_kind.get_selected()]
        try:
            records = self.diagnostic_database.named_records(
                slot, self.diagnostics.language
            )
        except ValueError as exc:
            self.diagnostic_status.set_text(f"Ошибка базы: {exc}")
            return
        words = self.diagnostic_search.get_text().casefold().split()
        visible = [
            row
            for row in records
            if all(
                word
                in f"{row.get('code', '')} {row.get('name', '')} {row.get('comment', '')}".casefold()
                for word in words
            )
        ]
        self.diagnostic_store.splice(
            0,
            0,
            [
                Parameter(
                    {
                        **row,
                        "code": row.get("code", str(row["row"] + 1)),
                        "comment": row.get("comment", ""),
                    }
                )
                for row in visible
            ],
        )
        system = self.diagnostics.systems[self.system_choice.get_selected()]
        self.diagnostic_status.set_text(
            f"{system['file']} · {len(visible)} из {len(records)} записей · справочные определения"
        )

    def inspect_diagnostic(self, _table, position):
        record = self.diagnostic_store.get_item(position).record
        if self.diagnostics is None or self.diagnostic_database is None:
            return
        system = self.diagnostics.systems[self.system_choice.get_selected()]
        text = f"{record.get('name', '')}\n{record.get('comment', '')}\n\nИсточник: {self.diagnostics.root / system['file']}\nСтрока: {record['row'] + 1}\nSHA-256: {self.diagnostic_database.sha256}"
        if self.diagnostic_kind.get_selected() == 1:
            try:
                variants = self.diagnostic_database.signal_variants(record["row"])
                units = self.diagnostic_database.named_records(
                    15, self.diagnostics.language
                )
                for variant in variants:
                    unit_names = ", ".join(
                        dict.fromkeys(
                            unit["name"]
                            for unit in units
                            if unit["key"] == variant["unit_key"] and unit["name"]
                        )
                    )
                    text += (
                        f"\n\nОпределение {variant['physical_row'] + 1}: биты {variant['start_bit']}…{variant['end_bit']}"
                        f"\nКоэффициенты: {variant['multiplier']}, {variant['divisor']}, {variant['offset']}"
                        f"\nДесятичных разрядов: {variant['decimal_precision']}"
                        f"\nЕдиница по умолчанию: {unit_names or 'не задана'}"
                        f"\nРежим знака: {variant['sign_mode']}; преобразование: {variant['selector']}"
                    )
                text += "\n\nПоказаны исходные определения. При диагностике позиции и коэффициенты могут уточняться для выбранного ЭБУ."
            except ValueError as exc:
                text += f"\n\nОшибка определения: {exc}"
        self.info_dialog(record["code"], text)

    def configure_sources(self, root):
        self.configuring = True
        self.roots = {
            REGIONS.get(code, "Выбранный каталог"): path
            for code, path in catalog_roots(root).items()
        }
        self.region.set_model(Gtk.StringList.new(list(self.roots)))
        selected = next(
            (
                i
                for i, path in enumerate(self.roots.values())
                if path.resolve() == root.resolve()
            ),
            0,
        )
        self.region.set_selected(selected)
        self.vehicle_region.set_model(Gtk.StringList.new(list(self.roots)))
        self.vehicle_region.set_selected(selected)
        self.root = list(self.roots.values())[selected]
        self.configuring = False

    def change_region(self, *_args):
        if not getattr(self, "configuring", True):
            self.root = list(self.roots.values())[self.region.get_selected()]
            self.configuring = True
            self.vehicle_region.set_selected(self.region.get_selected())
            self.configuring = False
            self.load_catalog()

    def load_catalog(self):
        self.vehicle_generation += 1
        self.vehicle_loading = False
        self.vehicle_catalog = None
        self.vehicle_variants.set_sensitive(False)
        self.vehicle_reload.set_sensitive(True)
        for widget in (
            self.vehicle_filters,
            self.vehicle_options,
            self.vehicle_system_list,
        ):
            while child := widget.get_first_child():
                widget.remove(child)
        self.vehicle_status.set_text(
            "Каталог региона изменён. Загрузите каталог заново."
        )
        self.diagnostic_generation += 1
        self.diagnostics_loading = False
        self.diagnostics = None
        self.diagnostic_database = None
        self.system_choice.set_sensitive(False)
        self.diagnostic_store.remove_all()
        self.diagnostic_status.set_text(
            "Базы выбранного региона будут загружены при открытии раздела."
        )
        self.generation += 1
        generation, root = self.generation, self.root
        self.index = None
        self.selected_group = None
        self.records = []
        self.store.remove_all()
        self.group_model.splice(0, self.group_model.get_n_items(), [])
        self.favorite.set_sensitive(False)
        self.source_button.set_sensitive(False)
        self.export_button.set_sensitive(False)
        self.source_summary.set_text("Чтение локальных данных…")
        self.group_count.set_text("Загрузка…")
        self.table_stack.set_visible_child_name("loading")
        self.result_count.set_text(str(root))

        def work():
            try:
                index, error = CatalogIndex(root), ""
            except (OSError, ValueError) as exc:
                index, error = None, str(exc)
            GLib.idle_add(self.catalog_ready, generation, index, error)

        threading.Thread(target=work, daemon=True, name="techstream-catalog").start()
        if self.pages.get_visible_child_name() == "diagnostics":
            self.load_diagnostics()

    def catalog_ready(self, generation, index, error):
        if self.closed or generation != self.generation:
            return GLib.SOURCE_REMOVE
        self.index = index
        if index is None:
            self.source_summary.set_text("Каталог недоступен")
            self.group_count.set_text("Нет данных")
            self.show_empty(
                "Не удалось открыть данные",
                f"{error}\nВыберите папку PIDGroup кнопкой папки вверху.",
            )
            self.result_count.set_text("Исходные файлы не изменены.")
            if self.smoke_test:
                self.finish_smoke(AssertionError(error))
            return GLib.SOURCE_REMOVE
        self.source_summary.set_text(
            f"{len(index.groups):,} групп   /   {index.record_count:,} параметров".replace(
                ",", " "
            )
        )
        self.filter_groups()
        if not index.groups and not index.errors:
            self.show_empty(
                "В этой папке нет групп параметров",
                "Выберите PIDGroup или папку комплекта кнопкой папки вверху.",
            )
        if index.errors:
            self.toast(
                f"Не удалось прочитать групп: {len(index.errors)}. Они отмечены в списке."
            )
        if self.smoke_test:
            GLib.timeout_add(250, self.check_smoke)
        return GLib.SOURCE_REMOVE

    def group_setup(self, _factory, item):
        content = box(spacing=3)
        content.append(label(ellipsize=Pango.EllipsizeMode.END))
        content.append(label(css="dim-label", ellipsize=Pango.EllipsizeMode.MIDDLE))
        item.set_child(content)

    def group_bind(self, _factory, item):
        group = item.get_item().get_string()
        content = item.get_child()
        prefix = "⚠ " if self.index and group in self.index.errors else ""
        prefix += "★ " if group in self.current_saved() else ""
        content.get_first_child().set_text(prefix + Path(group).stem)
        content.get_last_child().set_text(str(Path(group).parent))
        content.set_tooltip_text(group)

    def current_saved(self):
        return self.saved.get(str(self.root.resolve()), [])

    def filter_groups(self, *_args):
        if self.index is None:
            return
        words = self.group_search.get_text().casefold().split()
        favorites = set(self.current_saved())
        groups = sorted(set(self.index.groups) | set(self.index.errors))
        visible = [
            group
            for group in groups
            if all(word in group.casefold() for word in words)
            and (not self.saved_only or group in favorites)
        ]
        previous = self.selected_group
        self.group_model.splice(0, self.group_model.get_n_items(), visible)
        self.group_count.set_text(f"{len(visible)} из {len(groups)} групп")
        if visible:
            self.group_selection.set_selected(
                visible.index(previous) if previous in visible else 0
            )
        else:
            self.selected_group = None
            self.select_group()

    def select_group(self, *_args):
        item = self.group_selection.get_selected_item()
        self.selected_group = item.get_string() if item is not None else None
        group = self.selected_group
        self.group_title.set_text(Path(group).stem if group else "Выберите группу")
        self.group_path.set_text(str(Path(group).parent) if group else "")
        self.group_path.set_tooltip_text(group)
        self.source_button.set_sensitive(
            bool(group and self.index and group in self.index.groups)
        )
        self.favorite.set_sensitive(bool(group) and not self.saved_error)
        self.changing_saved = True
        active = group in self.current_saved()
        self.favorite.set_active(active)
        self.favorite.set_icon_name(
            "starred-symbolic" if active else "non-starred-symbolic"
        )
        self.favorite.set_tooltip_text(
            self.saved_error
            or ("Убрать из избранного" if active else "Добавить в избранное")
        )
        self.changing_saved = False
        self.filter_parameters()

    def activate_group(self, _view, _position):
        if self.catalog_split.get_collapsed():
            self.catalog_split.set_show_sidebar(False)

    @staticmethod
    def cell_setup(_factory, item):
        widget = label(
            ellipsize=Pango.EllipsizeMode.END,
            margin_top=10,
            margin_bottom=10,
            margin_start=12,
            margin_end=12,
        )
        item.set_child(widget)

    @staticmethod
    def cell_bind(_factory, item, field):
        value = item.get_item().record[field]
        text = Path(value).stem if field == "group" else value or "—"
        item.get_child().set_text(text)
        item.get_child().set_tooltip_text(value or "Единица не указана в источнике")

    def filter_parameters(self, *_args):
        if self.index is None:
            return
        query = self.parameter_search.get_text()
        global_search = self.all_groups.get_active()
        self.records = []
        if global_search and query.strip():
            self.records = self.index.search(query)
            if self.saved_only:
                favorites = set(self.current_saved())
                self.records = [
                    record for record in self.records if record["group"] in favorites
                ]
        elif not global_search and self.selected_group:
            self.records = self.index.search(query, self.selected_group)
        self.store.remove_all()
        # shortcut: cap rendered global matches at 1000; export keeps every match, add paging if needed.
        self.store.splice(0, 0, [Parameter(record) for record in self.records[:1000]])
        self.export_button.set_sensitive(bool(self.records))
        count = len(self.records)
        self.result_count.set_text(
            f"Показано {min(count, 1000)} из {count} параметров. Экспорт сохраняет все найденные."
            if count > 1000
            else f"Параметров: {count}. Имена и единицы из исходного комплекта."
        )
        if self.records:
            self.table_stack.set_visible_child_name("table")
        elif global_search and not query.strip():
            self.show_empty(
                "Поиск во всех группах",
                "Введите название параметра или единицу в поле поиска.",
            )
        elif self.selected_group in self.index.errors:
            self.show_empty(
                "Группа повреждена или не поддерживается",
                self.index.errors[self.selected_group],
            )
        elif self.saved_only and self.group_model.get_n_items() == 0:
            self.show_empty(
                "Нет избранных групп",
                "Откройте «Параметры» и нажмите звезду рядом с названием группы. Проверьте фильтр групп.",
            )
        else:
            self.show_empty(
                "Ничего не найдено", "Измените запрос или выберите другую группу."
            )

    def show_empty(self, title, description):
        self.empty.set_title(title)
        self.empty.set_description(description)
        self.table_stack.set_visible_child_name("empty")

    def clear_breakpoint_focus(self, *_args):
        self.breakpoint_focus = None

    def remember_breakpoint_focus(self, *_args):
        self.clear_breakpoint_focus()
        target = self.window.get_focus()
        if target is None or not target.is_ancestor(self.pages):
            return
        pending = {
            "target": target,
            "page": self.pages.get_visible_child_name(),
            "route": self.navigation_page,
            "lost": False,
        }
        self.breakpoint_focus = pending

        def retire():
            if self.breakpoint_focus is pending:
                self.clear_breakpoint_focus()
            return GLib.SOURCE_REMOVE

        GLib.timeout_add(250, retire)

    def restore_breakpoint_focus(self, *_args):
        pending = self.breakpoint_focus
        if pending is None:
            return
        current = self.window.get_focus()
        if current is None:
            pending["lost"] = True
            return
        if not pending["lost"] or not current.is_ancestor(self.navigation):
            if current != pending["target"]:
                self.clear_breakpoint_focus()
            return
        self.clear_breakpoint_focus()

        def restore():
            target = pending["target"]
            if (
                not self.closed
                and self.navigation_page == pending["route"]
                and self.pages.get_visible_child_name() == pending["page"]
            ):
                page = self.pages.get_visible_child()
                if (
                    target.get_mapped()
                    and page is not None
                    and target.is_ancestor(page)
                ):
                    target.grab_focus()
                elif pending["page"] == "offline":
                    self.offline_open.grab_focus()
                elif page is not None:
                    page.child_focus(Gtk.DirectionType.TAB_FORWARD)
            return GLib.SOURCE_REMOVE

        GLib.idle_add(restore)

    def select_navigation(self, row):
        self.navigate(self.navigation, row)

    def navigate(self, _list, row):
        if row is None:
            return
        if self.layout.get_collapsed():
            self.layout.set_show_sidebar(False)
        page = row.get_index()
        if getattr(self, "navigation_page", None) == page:
            return
        previous_row = self.navigation.get_row_at_index(
            getattr(self, "navigation_page", 0)
        )
        if previous_row is not None:
            previous_row.remove_css_class("active")
            previous_row.update_state(
                [Gtk.AccessibleState.SELECTED], [int(Gtk.AccessibleTristate.FALSE)]
            )
        self.navigation_page = page
        row.add_css_class("active")
        row.update_state(
            [Gtk.AccessibleState.SELECTED], [int(Gtk.AccessibleTristate.TRUE)]
        )
        self.pages.set_visible_child_name(
            "catalog"
            if page < 2
            else (
                "adapter",
                "docs",
                "diagnostics",
                "session",
                "offline",
                "vehicle",
                "programming",
            )[page - 2]
        )
        if page < 2:
            self.saved_only = page == 1
            self.page_title.set_text("Избранное" if self.saved_only else "Параметры")
            self.filter_groups()
        elif page == 2:
            self.refresh_devices()
        elif page == 4 and self.diagnostics is None:
            self.load_diagnostics()
        elif page == 7 and self.vehicle_catalog is None:
            self.load_vehicle_catalog()

    def focus_search(self, groups):
        if self.pages.get_visible_child_name() != "catalog":
            self.select_navigation(self.navigation.get_row_at_index(0))
        if groups:
            self.catalog_split.set_show_sidebar(True)
        (self.group_search if groups else self.parameter_search).grab_focus()

    def toggle_saved(self, *_args):
        if self.changing_saved or self.selected_group is None or self.saved_error:
            return
        group = self.selected_group
        root = str(self.root.resolve())
        selected = set(self.current_saved())
        if self.favorite.get_active():
            selected.add(group)
        else:
            selected.discard(group)
        updated = {**self.saved, root: sorted(selected)}
        try:
            save_saved(self.state_path, updated)
        except (OSError, ValueError) as exc:
            self.toast(f"Не удалось сохранить избранное: {exc}")
            self.select_group()
            return
        self.saved = updated
        self.filter_groups()
        self.select_group()

    def show_source(self, *_args):
        if self.index is None or self.selected_group not in self.index.groups:
            return
        content = self.index.groups[self.selected_group]
        text = f"{self.index.root / self.selected_group}\n\nSHA-256\n{content['sha256']}\n\nЗаписей: {len(content['records'])}\nФормат: CT v2/52\nМетаданные не являются декодированными командами ECU."
        self.info_dialog("Исходный файл", text)

    def inspect_parameter(self, _table, position):
        record = self.store.get_item(position).record
        self.info_dialog(
            record["name"],
            f"Группа: {record['group']}\nКороткое имя: {record['short_name'] or 'не сохранено'}\nЕдиница: {record['unit'] or 'не указана'}\n\nID параметра DDB: {record['parameter_id']}\nКатегория преобразования единиц: {record['unit_conversion_category']}\nСохранённое поле списка (+6): {record['saved_list_field']}\n\nНазвания и единицы — снимок списка. Оригинал при загрузке сверяет ID с доступными параметрами выбранного ЭБУ.\n\nИсходные байты: {record['metadata_hex']}",
        )

    def info_dialog(self, title, text):
        dialog = Adw.AlertDialog(heading=title, body=text)
        dialog.add_response("copy", "Копировать")
        dialog.add_response("close", "Закрыть")
        dialog.set_default_response("close")
        dialog.set_close_response("close")
        dialog.connect(
            "response",
            lambda _dialog, response: (
                self.window.get_clipboard().set(text) if response == "copy" else None
            ),
        )
        dialog.present(self.window)

    def export_dialog(self, *_args):
        if not self.records:
            self.toast("Нет параметров для экспорта.")
            return
        dialog = Gtk.FileDialog(
            title="Экспорт параметров", initial_name="techstream-parameters.csv"
        )
        records = list(self.records)

        def finished(chooser, result):
            try:
                file = chooser.save_finish(result)
                path = file.get_path()
                if path is None:
                    raise ValueError("Выберите локальный файл")
                export_csv(Path(path), records)
                self.toast(f"Сохранено параметров: {len(records)}")
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(f"Не удалось сохранить CSV: {exc}")

        dialog.save(self.window, None, finished)

    def open_source(self, *_args):
        dialog = Gtk.FileDialog(
            title="Выберите PIDGroup или папку комплекта Techstream"
        )

        def finished(chooser, result):
            try:
                path = chooser.select_folder_finish(result).get_path()
                if path is None:
                    raise ValueError("Выберите локальную папку")
                root = Path(path)
                self.root = root
                self.configure_sources(root)
                self.load_catalog()
            except GLib.Error as exc:
                self.dialog_error(exc)
            except (OSError, ValueError) as exc:
                self.toast(f"Не удалось открыть каталог: {exc}")

        dialog.select_folder(self.window, None, finished)

    def dialog_error(self, error):
        if not error.matches(
            Gtk.dialog_error_quark(), Gtk.DialogError.DISMISSED
        ) and not error.matches(Gio.io_error_quark(), Gio.IOErrorEnum.CANCELLED):
            self.toast(str(error))

    def refresh_devices(self, *_args):
        self.adapter_result = None
        self.devices.remove_all()
        try:
            devices = usb_devices()
            for device in devices:
                row = Adw.ActionRow(
                    title=GLib.markup_escape_text(
                        device["product"] or "USB-устройство"
                    ),
                    subtitle=GLib.markup_escape_text(
                        f"{device['manufacturer']}  |  {device['id']}  |  порт {device['port']}"
                    ),
                )
                row.add_prefix(
                    Gtk.Image.new_from_icon_name(
                        "network-wired-symbolic"
                        if device["candidate"]
                        else "drive-removable-media-usb-symbolic"
                    )
                )
                self.devices.append(row)
            matched = any(device["id"] == "18e1:0104" for device in devices)
            self.adapter_probe.set_sensitive(matched and not self.adapter_busy)
            if self.adapter_busy:
                return
            self.adapter_status.set_title(
                "Найден MongoosePro JLR" if matched else "Соединение не установлено"
            )
            self.adapter_status.set_description(
                "Устройство 18e1:0104 присутствует. Нажмите «Проверить адаптер» для чтения версии."
                if matched
                else "Адаптер 18e1:0104 не обнаружен. Подключите его по USB и обновите список."
            )
            if not devices:
                self.devices.append(Adw.ActionRow(title="USB-устройства не обнаружены"))
        except OSError as exc:
            self.adapter_status.set_description(
                f"Не удалось прочитать список USB: {exc}"
            )

    def check_adapter(self, *_args):
        if self.adapter_busy:
            return
        self.adapter_busy = True
        self.adapter_result = None
        self.adapter_probe.set_sensitive(False)
        self.adapter_status.set_title("Чтение версии адаптера…")
        self.adapter_status.set_description(
            "Открытие USB и чтение сведений об устройстве."
        )

        def work():
            try:
                locations = discover_jlr()
                if len(locations) != 1:
                    raise ValueError(
                        "Для проверки подключите ровно один MongoosePro JLR."
                    )
                result = {
                    **probe_adapter(locations[0], self.adapter_cancel),
                    "port": locations[0].port,
                    "usb_bus": locations[0].bus,
                    "usb_address": locations[0].address,
                }
                error = ""
            except (OSError, ValueError, BufferError) as exc:
                result, error = None, str(exc)
            GLib.idle_add(self.adapter_checked, result, error)

        self.adapter_thread = threading.Thread(target=work, name="techstream-jlr")
        self.adapter_thread.start()

    def adapter_checked(self, result, error):
        self.adapter_busy = False
        if self.closed:
            return GLib.SOURCE_REMOVE
        try:
            locations = discover_jlr()
            if result is not None and not any(
                (location.port, location.bus, location.address)
                == (result["port"], result["usb_bus"], result["usb_address"])
                for location in locations
            ):
                result, error = (
                    None,
                    "Адаптер отключён или переподключён во время проверки. Повторите проверку.",
                )
        except (OSError, ValueError) as exc:
            locations = []
            if result is not None:
                result, error = None, str(exc)
        self.adapter_result = result
        self.adapter_probe.set_sensitive(len(locations) == 1)
        if result is None:
            self.adapter_status.set_title("Не удалось проверить адаптер")
            self.adapter_status.set_description(error)
        else:
            self.show_adapter_result()
        return GLib.SOURCE_REMOVE

    def show_adapter_result(self):
        result = self.adapter_result
        if result is None:
            return
        self.adapter_status.set_title("Проверка адаптера прошла")
        self.adapter_status.set_description(
            f"Серийный номер: {result['serial_text']}\nПрошивка: {result['firmware_raw']:#010x}\nЗагрузчик: {result['bootloader_raw']:#010x}\nUSB-порт: {result['port']}\n\nUSB-проверка завершена. Диагностическое соединение с автомобилем не установлено."
        )

    def read_document(self, *_args):
        name = list(DOCUMENTS.values())[self.document.get_selected()]
        try:
            text = (PROJECT / "docs" / name).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            text = f"Не удалось открыть документ: {exc}"
        buffer = self.doc_view.get_buffer()
        buffer.set_text("")
        code = False
        for line in text.splitlines():
            if line.startswith("```"):
                code = not code
                continue
            end = buffer.get_end_iter()
            if line.startswith("#") and not code:
                buffer.insert_with_tags_by_name(
                    end, line.lstrip("#").strip() + "\n", "heading"
                )
            elif code:
                buffer.insert_with_tags_by_name(end, line + "\n", "code")
            else:
                buffer.insert(end, line + "\n")

    def show_about(self, *_args):
        dialog = Adw.AboutDialog(
            application_name="Techstream",
            application_icon="applications-engineering-symbolic",
            version="0.1 · Linux workbench",
            website="https://github.com/gon7187/techstream",
            license_type=Gtk.License.MIT_X11,
            comments="Нативная рабочая область: ресурсы Toyota / Lexus, воспроизведение диагностических записей и USB-проверка MongoosePro JLR. Полный диагностический движок ещё переносится; связь с автомобилем не подтверждена.",
        )
        dialog.present(self.window)

    def toast(self, text):
        self.toast_overlay.add_toast(Adw.Toast(title=text, timeout=5))

    def smoke_timeout(self):
        if not self.closed:
            self.finish_smoke(AssertionError("catalog smoke timed out"))
        return GLib.SOURCE_REMOVE

    def check_smoke(self):
        try:
            assert self.window.get_mapped(), "window was not mapped"
            if self.smoke_stage == 6:
                assert (
                    self.session_report is not None
                    and len(self.session_report["samples"]) == 12
                )
                assert self.plot_picture.get_paintable() is not None
                self.plot_parameter.set_selected(0)
                assert self.plot_picture.get_paintable() is not None
                self.smoke_stage = 7
                self.session_mode.set_selected(2)
                self.start_example()
                return GLib.SOURCE_REMOVE
            if self.smoke_stage == 8:
                assert self.session_report is not None
                assert self.session_report["calibration_ids"] == ["DEMO-CAL-0001"]
                assert self.session_report["cvns"] == ["DEADBEEF"]
                self.session_smoke_mode = 3
                self.session_mode.set_selected(3)
                self.start_example()
                return GLib.SOURCE_REMOVE
            if self.smoke_compact:
                assert self.window.get_width() <= 1100, "compact window is not narrow"
                assert (
                    self.layout.get_collapsed() and self.catalog_split.get_collapsed()
                )
                assert self.groups_button.get_visible()
            elif self.window.get_width() <= 1100:
                assert (
                    self.layout.get_collapsed() and self.catalog_split.get_collapsed()
                )
                assert self.groups_button.get_visible()
            assert self.index is not None and self.index.record_count > 0
            current = self.index
            self.catalog_ready(self.generation - 1, None, "obsolete result")
            assert self.index is current, (
                "An obsolete load replaced the current catalog"
            )
            group = "Demo/Engine.CT" if self.demo else "Brand/1/2ndary Air.CT"
            if self.smoke_stage == 0:
                assert json.loads(self.report_preview({"α": "β"})) == {"α": "β"}
                preview = self.report_preview({"long": "x" * 110000})
                assert len(preview) < 100100 and "Полный отчёт" in preview
                self.focus_search(True)
                self.group_search.set_text("Engine" if self.demo else "2ndary Air")
                self.filter_groups()
                if self.catalog_split.get_collapsed():
                    assert self.catalog_split.get_show_sidebar(), (
                        "Filtering closed the groups panel"
                    )
                names = [
                    self.group_model.get_string(i)
                    for i in range(self.group_model.get_n_items())
                ]
                assert group in names
                assert (
                    "Demo/Emissions.CT" if self.demo else "Brand/1/ATM.CT"
                ) not in names
                self.group_selection.set_selected(names.index(group))
                self.group_view.emit("activate", names.index(group))
                if self.catalog_split.get_collapsed():
                    assert not self.catalog_split.get_show_sidebar()
                self.parameter_search.set_text("engine rpm")
                self.filter_parameters()
                assert self.store.get_n_items() == 1
                expected_name = "Engine speed" if self.demo else "Engine SPD"
                assert self.store.get_item(0).record["name"] == expected_name
                self.favorite.set_active(True)
                assert group in load_saved(self.state_path)[str(self.root.resolve())]
                self.select_navigation(self.navigation.get_row_at_index(1))
                assert self.group_model.get_n_items() == 1
                self.all_groups.set_active(True)
                self.filter_parameters()
                assert self.records and all(r["group"] == group for r in self.records)
                destination = self.state_path.parent / "smoke-export.csv"
                export_csv(destination, self.records)
                assert expected_name in destination.read_text(encoding="utf-8-sig")
                self.select_navigation(self.navigation.get_row_at_index(2))
                assert self.devices.get_first_child() is not None
                self.check_adapter_smoke()
                self.select_navigation(self.navigation.get_row_at_index(3))
                assert self.doc_view.get_buffer().get_char_count() > 100
                self.select_navigation(self.navigation.get_row_at_index(0))
                self.group_search.set_text("")
                self.parameter_search.set_text("engine rpm")
                self.filter_groups()
                self.all_groups.set_active(True)
                self.filter_parameters()
                assert len(self.records) > 1
                assert self.store.get_n_items() == min(1000, len(self.records))
                self.smoke_stage = 1
                if len(self.roots) > 1:
                    self.region.set_selected(1)
                    return GLib.SOURCE_REMOVE
            assert self.index.root == self.root.resolve()
            if self.smoke_stage == 1:
                self.smoke_stage = 2
                self.select_navigation(self.navigation.get_row_at_index(4))
                return GLib.SOURCE_REMOVE
            assert self.diagnostics is not None
            assert len(self.diagnostics.systems) >= (1 if self.demo else 100)
            current_diagnostics = self.diagnostics
            self.diagnostics_ready(self.diagnostic_generation - 1, None, "obsolete")
            assert self.diagnostics is current_diagnostics
            system_index = next(
                i
                for i, row in enumerate(self.diagnostics.systems)
                if row["file"] == ("DemoEngine.ddb" if self.demo else "4WDS_P4.ddb")
            )
            self.system_choice.set_selected(system_index)
            self.diagnostic_kind.set_selected(0)
            self.diagnostic_search.set_text("P0300" if self.demo else "C120C")
            self.filter_diagnostics()
            assert self.diagnostic_store.get_n_items() == 1
            assert self.diagnostic_store.get_item(0).record["name"] == (
                "Synthetic diagnostic fault"
                if self.demo
                else "Linear Solenoid Power Supply System Malfunction"
            )
            self.diagnostic_kind.set_selected(1)
            self.diagnostic_search.set_text(
                "Engine speed" if self.demo else "FR Wheel Speed"
            )
            self.filter_diagnostics()
            assert self.diagnostic_store.get_n_items() > 0
            if self.smoke_stage == 2:
                self.smoke_stage = 3
                self.select_navigation(self.navigation.get_row_at_index(5))
                self.start_session(PROJECT / "examples/diagnostic-session.json")
                return GLib.SOURCE_REMOVE
            assert self.session_report is not None
            assert len(self.session_report["ecus"]) == 2
            assert self.session_report["source"] == "authored_synthetic"
            assert all(ecu["status"] == "ok" for ecu in self.session_report["ecus"])
            assert self.session_results.get_first_child() is not None
            save_report(
                self.state_path.parent / "smoke-report.json", self.session_report
            )
            self.smoke_stage = 5
            self.session_mode.set_selected(1)
            self.start_example()
        except Exception as exc:  # noqa: BLE001 - surface any failed GUI assertion to the launcher.
            self.finish_smoke(exc)
        return GLib.SOURCE_REMOVE

    def check_extended_session_smoke(self):
        try:
            assert self.session_report is not None
            assert self.session_value_store.get_n_items() > 0
            assert self.session_export.get_sensitive()
            if self.session_smoke_mode == 3:
                assert self.session_report["results"][0]["value"] == 0.122
            elif self.session_smoke_mode == 4:
                assert self.session_report["supported_pids"] == [13]
            elif self.session_smoke_mode == 5:
                assert [value["value"] for value in self.session_report["values"]] == [
                    2000,
                    50,
                ]
            elif self.session_smoke_mode == 6:
                assert self.session_report["values"]["02"] == "SYNTHET1C00000000"
            self.session_smoke_mode += 1
            if self.session_smoke_mode <= 6:
                self.session_mode.set_selected(self.session_smoke_mode)
                self.start_example()
            else:
                self.select_navigation(self.navigation.get_row_at_index(6))
                assert self.pages.get_visible_child_name() == "offline"
                self.offline_smoke_phase = "workflows"
                self.offline_smoke_index = 0
                self.offline_choice.set_selected(0)
                self.start_offline()
        except Exception as exc:  # noqa: BLE001 - propagate GUI assertions.
            self.finish_smoke(exc)
        return GLib.SOURCE_REMOVE

    def check_offline_smoke(self):
        from scripts.utility_authored import BSM_UTILITY_GROUP, DCM_UTILITY_GROUP

        try:
            assert not self.offline_busy
            assert self.offline_run.get_sensitive()
            assert not self.offline_stop.get_sensitive()
            phase = self.offline_smoke_phase
            if phase == "workflows":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["source"] == "authored_synthetic"
                assert self.offline_report["physical_status"] == "PHYSICAL_UNCONFIRMED"
                assert self.offline_store.get_n_items() > 0
                assert self.offline_export.get_sensitive()
                self.offline_smoke_index += 1
                if self.offline_smoke_index < len(self.offline_keys):
                    self.offline_choice.set_selected(self.offline_smoke_index)
                    self.start_offline()
                    return GLib.SOURCE_REMOVE
                self.offline_smoke_phase = "cancel"
                self.start_offline()
                thread = self.offline_thread
                self.start_offline()
                assert self.offline_thread is thread, "busy operation was replaced"
                self.offline_cancel.set()
            elif phase == "cancel":
                assert self.offline_report is None
                assert not self.offline_export.get_sensitive()
                assert "отменена" in self.offline_status.get_text()
                self.offline_smoke_phase = "fault"
                self.start_offline(self.state_path.parent / "missing.dm")
            elif phase == "fault":
                assert self.offline_report is None
                assert not self.offline_export.get_sensitive()
                assert self.offline_status.get_text()
                self.offline_smoke_phase = "file"
                path = self.state_path.parent / "authored-vector.dm"
                parsed = parse_snapshot(example_snapshot())
                assert isinstance(parsed, TableFile)
                path.write_bytes(
                    dump_snapshot(
                        TableFile(
                            parsed.magic,
                            parsed.version,
                            parsed.revision,
                            parsed.tables * 2,
                        )
                    )
                )
                self.start_offline(path)
            elif phase == "file":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert len(self.offline_report["result"]["available_buffers"]) == 2
                assert self.offline_buffer.get_visible()
                self.offline_smoke_phase = "buffer_switch"
                self.offline_buffer.set_selected(1)
            elif phase == "buffer_switch":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["result"]["playback_index"] == 1
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_store.get_n_items() > 0
                assert self.offline_chart.get_visible()
                assert self.offline_picture.get_paintable() is not None
                assert "100, 120" in self.offline_time.get_text()
                assert self.offline_copy.get_sensitive()
                assert self.offline_source is not None
                original = self.offline_source.read_bytes()
                try:
                    save_report(
                        self.offline_source,
                        self.offline_report,
                        source=self.offline_source,
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError("inspection export overwrote its source")
                assert self.offline_source.read_bytes() == original
                destination = self.state_path.parent / "offline-report.json"
                save_report(
                    destination, self.offline_report, source=self.offline_source
                )
                assert json.loads(destination.read_text()) == self.offline_report
                self.offline_smoke_original = original
                self.offline_smoke_phase = "copy_rejected"
                self.start_native_copy(self.offline_source, self.offline_source)
            elif phase == "copy_rejected":
                assert self.offline_source is not None
                assert self.offline_source.read_bytes() == self.offline_smoke_original
                assert "Не удалось сохранить" in self.offline_status.get_text()
                self.offline_smoke_phase = "copy"
                self.start_native_copy(
                    self.offline_source, self.state_path.parent / "native-copy.dm"
                )
            elif phase == "copy":
                assert (
                    self.state_path.parent / "native-copy.dm"
                ).read_bytes() == self.offline_smoke_original
                examples = create_examples(
                    self.state_path.parent / "file-inspection-inputs"
                )
                self.smoke_file_paths = [
                    examples[name]
                    for name in (
                        "settings.drs",
                        "capture.tse",
                        "calibration.cuw",
                        "procedure.xml",
                        "communication.clog",
                        "native-exchange.json",
                    )
                ]
                self.smoke_file_index = 0
                self.offline_smoke_phase = "inspect_files"
                self.start_offline(self.smoke_file_paths[0])
            elif phase == "inspect_files":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_store.get_n_items() > 0
                if (
                    self.offline_report["result"]["format"]
                    == "native-communication-log"
                ):
                    assert self.offline_copy.get_sensitive()
                self.smoke_file_index += 1
                if self.smoke_file_index < len(self.smoke_file_paths):
                    self.start_offline(self.smoke_file_paths[self.smoke_file_index])
                    return GLib.SOURCE_REMOVE
                self.offline_smoke_phase = "repeat"
                self.offline_choice.set_selected(0)
                self.start_offline()
            elif phase == "repeat":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_source is None
                previous = self.offline_status.get_text()
                self.closed = True
                self.offline_ready(None, "closed result must be ignored")
                self.closed = False
                assert self.offline_status.get_text() == previous
                self.offline_smoke_phase = "vehicle"
                self.select_navigation(self.navigation.get_row_at_index(7))
            elif phase == "vehicle_commands":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert (
                    self.offline_report["result"]["commands"][0]["request_hex"]
                    == "21 00"
                )
                self.start_native_smoke("readiness")
            elif phase == "native_readiness":
                assert self.offline_report is not None, self.offline_status.get_text()
                signal = self.offline_report["result"]["signals"][0]
                assert signal["value"]["value"] == 2000
                assert signal["native_support"] is True
                self.start_native_smoke("data_list")
            elif phase == "native_data_list":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert (
                    self.offline_report["result"]["signals"][0]["value"]["value"]
                    == 2000
                )
                self.start_native_smoke("command")
            elif phase == "native_command":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["result"]["responses_hex"] == ["6100"]
                for source in self.offline_sources:
                    original = source.read_bytes()
                    try:
                        save_report(
                            source, self.offline_report, sources=self.offline_sources
                        )
                    except ValueError:
                        pass
                    else:
                        raise AssertionError(
                            "native report replaced a profile or recording source"
                        )
                    assert source.read_bytes() == original
                self.start_native_smoke("readiness", observations=False)
            elif phase == "native_missing_observations":
                assert self.offline_report is None
                assert "observations" in self.offline_status.get_text()
                directory = self.state_path.parent / "calibration-inputs"
                directory.mkdir()
                paths = []
                for filename, raw in create_calibration_examples().items():
                    path = directory / filename
                    path.write_bytes(raw)
                    paths.append(path)
                self.calibration_smoke_paths = tuple(paths)
                self.offline_smoke_phase = "catalog_load"
                self.load_calibration_sources(self.calibration_smoke_paths)
            elif phase == "catalog_load":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.calibration_catalog.keys == ("synthetic",)
                assert self.offline_catalog_controls.get_visible()
                self.offline_smoke_phase = "catalog_plan"
                self.calibration_stage.set_selected(0)
                self.run_calibration_plan()
            elif phase in ("catalog_plan", "catalog_repeat", "catalog_final"):
                assert self.offline_report is not None, self.offline_status.get_text()
                plan = self.offline_report["result"]["plan"]
                assert plan["operation"] == "StartGetCID"
                assert plan["addresses"][0]["request_hex"] == "0100"
                assert plan["module_version_checked"] is True
                assert plan["programming_authorized"] is False
                assert self.offline_catalog_controls.get_visible()
                if phase == "catalog_plan":
                    for source in self.offline_sources:
                        original = source.read_bytes()
                        try:
                            save_report(
                                source,
                                self.offline_report,
                                sources=self.offline_sources,
                            )
                        except ValueError:
                            pass
                        else:
                            raise AssertionError(
                                "calibration report replaced a table or library source"
                            )
                        assert source.read_bytes() == original
                    self.offline_smoke_phase = "catalog_fault"
                    self.calibration_stage.set_selected(1)
                    self.run_calibration_plan()
                    return GLib.SOURCE_REMOVE
                if phase == "catalog_repeat":
                    self.smoke_catalog = self.calibration_catalog
                    self.offline_smoke_phase = "catalog_cancel"
                    self.load_calibration_sources(self.calibration_smoke_paths)
                    self.offline_cancel.set()
                    return GLib.SOURCE_REMOVE
                self.smoke_procedure_files = create_example_files(
                    self.state_path.parent / "procedure-inputs"
                )
                path = self.smoke_procedure_files["utility"]
                raw = path.read_bytes()
                xml = (
                    raw[6:]
                    .decode("utf-16le")
                    .replace('NEXT="END"', 'NEXT="timed"')
                    .replace(
                        "</FUNCTION>",
                        '<BLOCK ID="timed" TYPE="G002"><TITLE>Recorded progress</TITLE><PROGRESS PROGRESSTIME="80" UPDATETIME="20"><ACTION MODE="BLOCK" NEXT="END"/></PROGRESS></BLOCK></FUNCTION>',
                    )
                )
                path.write_bytes(raw[:6] + xml.encode("utf-16le"))
                self.start_procedure_smoke("utility", "definition")
            elif phase in ("utility_definition", "script_definition"):
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_procedure_controls.get_visible()
                kind = phase.split("_")[0]
                self.offline_smoke_phase = kind + "_replay"
                self.start_procedure_recording(
                    self.procedure_selection,
                    self.smoke_procedure_files[kind + "_recording"],
                    "demo" if kind == "utility" else None,
                )
            elif phase == "utility_replay":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                assert self.offline_report["remaining_events"] == 0
                assert self.utility_ui is None
                assert self.smoke_progress_ticks >= 1
                document = json.loads(
                    self.smoke_procedure_files["utility_recording"].read_text()
                )
                document["context"]["limits"]["seconds"] = 0.5
                path = self.state_path.parent / "procedure-idle-timeout.json"
                path.write_text(json.dumps(document))
                self.offline_smoke_phase = "utility_timeout"
                self.start_procedure_recording(self.procedure_selection, path, "demo")
            elif phase == "utility_timeout":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "failed", self.offline_report
                assert self.offline_report["error"]["type"] == "TimeoutError"
                assert self.smoke_idle_screen_seen
                assert self.utility_ui is None
                self.offline_smoke_phase = "utility_cancel"
                self.start_procedure_recording(
                    self.procedure_selection,
                    self.smoke_procedure_files["utility_recording"],
                    "demo",
                )
            elif phase == "utility_cancel":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "cancelled", self.offline_report
                assert self.utility_ui is None
                document = json.loads(
                    self.smoke_procedure_files["utility_recording"].read_text()
                )
                document["events"] = document["events"][1:]
                path = self.state_path.parent / "procedure-missing-initialize.json"
                path.write_text(json.dumps(document))
                self.offline_smoke_phase = "utility_fault"
                self.start_procedure_recording(self.procedure_selection, path, "demo")
            elif phase == "utility_fault":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "failed", self.offline_report
                assert self.offline_report["error"]
                assert self.utility_ui is None
                self.start_procedure_smoke("script", "definition")
            elif phase == "script_replay":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                assert self.offline_report["remaining_events"] == 0
                self.recorder_smoke_paths = {}
                directory = self.state_path.parent / "recorder-inputs"
                directory.mkdir()
                for name, raw in create_recorder_examples().items():
                    path = directory / name
                    path.write_bytes(raw)
                    self.recorder_smoke_paths[name] = path
                self.offline_smoke_phase = "recorder_definition"
                self.start_offline(self.recorder_smoke_paths["recorder-settings.drs"])
            elif phase == "recorder_definition":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_recorder_controls.get_visible()
                assert not self.recorder_export.get_sensitive()
                self.offline_smoke_phase = "recorder_capture"
                self.start_recorder_recording(
                    self.recorder_smoke_paths["recorder-settings.drs"],
                    self.recorder_smoke_paths["recorder-recording.json"],
                )
            elif phase == "recorder_capture":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                assert self.offline_report["result"]["trigger_timestamp_raw"] == 2000
                assert (
                    self.offline_chart.get_visible()
                    and self.recorder_export.get_sensitive()
                )
                self.recorder_smoke_report = self.offline_report
                self.recorder_smoke_sources = self.offline_sources
                self.offline_smoke_phase = "recorder_export"
                path = self.state_path.parent / "recorder-capture.dm"
                self.start_offline_write(
                    lambda: save_recorder_dm(
                        path,
                        self.recorder_smoke_report,
                        sources=self.recorder_smoke_sources,
                    ),
                    "Capture saved",
                )
            elif phase == "recorder_export":
                self.offline_smoke_phase = "recorder_open_export"
                self.start_offline(self.state_path.parent / "recorder-capture.dm")
            elif phase == "recorder_open_export":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert [
                    row["timestamp_raw"]
                    for row in self.offline_report["result"]["playback"]["samples"]
                ] == [1000, 2000, 3000]
                assert self.offline_chart.get_visible()
                document = json.loads(
                    self.recorder_smoke_paths["recorder-recording.json"].read_bytes()
                )
                document["context"]["capabilities"] = []
                path = self.state_path.parent / "recorder-invalid-context.json"
                path.write_text(json.dumps(document))
                self.offline_smoke_phase = "recorder_fault"
                self.start_recorder_recording(
                    self.recorder_smoke_paths["recorder-settings.drs"], path
                )
            elif phase == "recorder_fault":
                assert (
                    self.offline_report is None
                    and "capabilities" in self.offline_status.get_text()
                )
                self.offline_smoke_phase = "recorder_cancel"
                self.start_recorder_recording(
                    self.recorder_smoke_paths["recorder-settings.drs"],
                    self.recorder_smoke_paths["recorder-recording.json"],
                )
                self.offline_cancel.set()
            elif phase == "recorder_cancel":
                assert (
                    self.offline_report is None
                    or self.offline_report["status"] == "cancelled"
                )
                assert "отмен" in self.offline_status.get_text()
                self.offline_smoke_phase = "recorder_repeat"
                self.start_recorder_recording(
                    self.recorder_smoke_paths["recorder-settings.drs"],
                    self.recorder_smoke_paths["recorder-recording.json"],
                )
            elif phase == "recorder_repeat":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed"
                assert (
                    self.offline_chart.get_visible()
                    and self.recorder_export.get_sensitive()
                )
                self.recorder_smoke_report = self.offline_report
                self.recorder_smoke_sources = self.offline_sources
                for source in self.offline_sources:
                    try:
                        save_report(
                            source, self.offline_report, sources=self.offline_sources
                        )
                    except ValueError:
                        pass
                    else:
                        raise AssertionError(
                            "Recorder report replaced its settings or recording"
                        )
                self.recorder_smoke_settings = self.recorder_smoke_sources[
                    0
                ].read_bytes()
                self.offline_smoke_phase = "recorder_export_rejected"
                self.start_offline_write(
                    lambda: save_recorder_dm(
                        self.recorder_smoke_sources[0],
                        self.recorder_smoke_report,
                        sources=self.recorder_smoke_sources,
                    ),
                    "Must reject source replacement",
                )
            elif phase == "recorder_export_rejected":
                assert "Не удалось сохранить" in self.offline_status.get_text()
                assert (
                    self.recorder_smoke_sources[0].read_bytes()
                    == self.recorder_smoke_settings
                )
                assert (
                    self.offline_recorder_controls.get_visible()
                    and self.recorder_export.get_sensitive()
                )
                self.programming_smoke_paths = {}
                directory = self.state_path.parent / "programming-inputs"
                directory.mkdir()
                for name, raw in create_programming_examples().items():
                    path = directory / name
                    path.write_bytes(raw)
                    self.programming_smoke_paths[name] = path
                for role, names in {
                    "cuw": ("authored.cuw",),
                    "context": ("authored-programming.json",),
                    "catalog": ("DEMOP5DEMO.ini",),
                    "modules": ("SyntheticProgramming.dll",),
                }.items():
                    self.set_programming_files(
                        role,
                        tuple(self.programming_smoke_paths[name] for name in names),
                    )
                self.programming_smoke_attachment = (
                    self.state_path.parent / "данные вложения.bin"
                )
                self.programming_smoke_attachment.write_bytes(
                    b"Authored attached bytes"
                )
                self.set_programming_files(
                    "attachments",
                    (
                        self.programming_smoke_attachment,
                        self.programming_smoke_attachment,
                    ),
                )
                for entry, alias in zip(
                    self.programming_attachment_entries,
                    ("capture", "second_capture"),
                    strict=True,
                ):
                    entry.set_text(alias)
                self.offline_smoke_phase = "programming_definition"
                self.load_programming_selection()
            elif phase in ("programming_definition", "programming_repeat_definition"):
                assert self.offline_report is not None, self.offline_status.get_text()
                assert (
                    self.programming_session is not None
                    and self.programming_run.get_sensitive()
                )
                assert self.programming_session.available_operations == ("write",)
                expected_alias = (
                    "renamed_capture"
                    if getattr(self, "programming_smoke_alias_changed", False)
                    else "capture"
                )
                assert set(self.programming_session.input_hashes["attachments"]) == {
                    expected_alias,
                    "second_capture",
                }
                assert (
                    self.programming_session.attachments[expected_alias]
                    == b"Authored attached bytes"
                )
                if not getattr(self, "programming_smoke_alias_changed", False):
                    self.programming_attachment_entries[0].set_text("renamed_capture")
                    assert (
                        self.programming_session is None
                        and not self.programming_run.get_sensitive()
                    )
                    self.programming_smoke_alias_changed = True
                    self.load_programming_selection()
                    return GLib.SOURCE_REMOVE
                self.offline_smoke_phase = (
                    "programming_repeat"
                    if phase == "programming_repeat_definition"
                    else "programming_run"
                )
                self.run_programming_recording()
            elif phase in ("programming_run", "programming_repeat"):
                assert self.offline_report is not None, self.offline_status.get_text()
                assert (
                    self.offline_store.get_item(0).record["name"] == "Результат этапа"
                )
                assert self.offline_report["state"] == "writer_completed", (
                    self.offline_report
                )
                assert self.offline_report["events_remaining"] == 0
                assert self.offline_report["programming_completed"] is False
                assert (
                    self.programming_session is None
                    and not self.programming_run.get_sensitive()
                )
                for source in self.offline_sources:
                    try:
                        save_report(
                            source, self.offline_report, sources=self.offline_sources
                        )
                    except ValueError:
                        pass
                    else:
                        raise AssertionError(
                            "Programming report replaced one of its input files"
                        )
                if phase == "programming_run":
                    self.programming_attachment_entries[1].set_text("renamed_capture")
                    self.offline_smoke_phase = "programming_alias_fault"
                    self.load_programming_selection()
                    return GLib.SOURCE_REMOVE
                self.start_workflow_smoke()
            elif phase.startswith("workflow_"):
                self.check_workflow_smoke(phase)
            elif phase.startswith("ram_"):
                self.check_ram_smoke(phase)
            elif phase == "programming_alias_fault":
                assert self.offline_report is None
                assert "Имена" in self.offline_status.get_text()
                assert (
                    self.programming_session is None
                    and self.programming_form.get_sensitive()
                )
                self.programming_attachment_entries[1].set_text("second_capture")
                document = json.loads(
                    self.programming_smoke_paths[
                        "authored-programming.json"
                    ].read_bytes()
                )
                document["calibration_sha256"] = "0" * 64
                path = self.state_path.parent / "programming-invalid-context.json"
                path.write_text(json.dumps(document))
                self.set_programming_files("context", (path,))
                self.offline_smoke_phase = "programming_fault"
                self.load_programming_selection()
                return GLib.SOURCE_REMOVE
            elif phase == "active_definition":
                assert self.offline_report is not None, self.offline_status.get_text()
                wanted = {"p3": 1, "p5": 2, "routine": 3}[self.active_smoke_family]
                index = next(
                    index
                    for index, row in enumerate(self.active_tests)
                    if row["signal_id"] == wanted
                )
                self.active_choice.set_selected(index)
                self.offline_smoke_phase = "active_initialization"
                self.initialize_active_test()
            elif phase == "active_initialization":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.active_initial is not None
                assert self.active_arguments.get_visible()
                if not self.active_smoke_negative:
                    resources = self.active_initial["help_resources"]
                    assert all(
                        row["resource"] for row in resources["details"]["outputs"]
                    )
                    assert resources["instructions"]["caution"]["status"] == "resolved"
                    assert self.active_selection["viewer"] in self.offline_sources
                assert (
                    self.active_auxiliary.get_visible()
                    == self.active_initial["argument_fields"]["auxiliary"]
                )
                assert (
                    self.active_input.get_visible()
                    == self.active_initial["argument_fields"]["bytes"]
                )
                assert (
                    self.active_output_mask.get_visible()
                    == self.active_initial["argument_fields"]["output_mask"]
                )
                self.active_value.set_text("-1" if self.active_smoke_negative else "5")
                if getattr(self, "active_smoke_bytes", False):
                    self.active_value.set_text(str(0x7FFFFFFF))
                    self.active_input.set_text("ff")
                if self.active_smoke_negative:
                    assert self.active_initial["minimum"] == -5
                    assert self.active_initial["maximum"] == 5
                self.active_auxiliary.set_text("0")
                self.offline_smoke_phase = "active_run"
                self.run_active_test()
            elif phase == "active_run":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_store.get_item(0).record["name"] == "Тест"
                assert self.offline_report["status"] == "completed", self.offline_report
                assert self.offline_report["remaining_exchanges"] == 0
                assert self.active_session is None
                assert not self.active_execute.get_sensitive()
                for source in self.offline_sources:
                    try:
                        save_report(
                            source, self.offline_report, sources=self.offline_sources
                        )
                    except ValueError:
                        pass
                    else:
                        raise AssertionError("Active report replaced its input")
                if self.active_smoke_family == "p3":
                    self.start_active_smoke("p5", negative=self.active_smoke_negative)
                    return GLib.SOURCE_REMOVE
                if self.active_smoke_family == "p5":
                    self.start_active_smoke(
                        "routine", negative=self.active_smoke_negative
                    )
                    return GLib.SOURCE_REMOVE
                if not getattr(self, "active_smoke_fault_done", False):
                    document = json.loads(self.active_recording_path.read_bytes())
                    document["native"]["transactions"][0]["request"] = "00"
                    path = self.state_path.parent / "active-invalid-initialization.json"
                    path.write_text(json.dumps(document))
                    self.offline_smoke_phase = "active_fault_definition"
                    self.load_active_recording(self.active_selection, path)
                    return GLib.SOURCE_REMOVE
                if not self.active_smoke_negative:
                    self.start_active_smoke("p3", negative=True)
                    return GLib.SOURCE_REMOVE
                if not getattr(self, "active_smoke_bytes", False):
                    self.active_smoke_bytes = True
                    self.start_active_smoke("routine", negative=True)
                    return GLib.SOURCE_REMOVE
                self.service_smoke_index = 0
                self.offline_smoke_phase = "service_run"
                self.load_service_recording(kind=self.service_kinds[0])
            elif phase == "active_fault_definition":
                assert self.active_session is not None, self.offline_status.get_text()
                self.active_choice.set_selected(
                    next(
                        index
                        for index, row in enumerate(self.active_tests)
                        if row["signal_id"] == 3
                    )
                )
                self.offline_smoke_phase = "active_fault_initialization"
                self.initialize_active_test()
            elif phase == "active_fault_initialization":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "failed", self.offline_report
                assert self.active_session is None and self.active_initial is None
                assert not self.active_arguments.get_visible()
                assert not self.active_initialize.get_sensitive()
                self.active_smoke_fault_done = True
                self.start_active_smoke("routine")
                self.offline_smoke_phase = "active_cancel_definition"
            elif phase == "active_cancel_definition":
                assert self.active_session is not None, self.offline_status.get_text()
                self.active_choice.set_selected(
                    next(
                        index
                        for index, row in enumerate(self.active_tests)
                        if row["signal_id"] == 3
                    )
                )
                self.offline_smoke_phase = "active_cancel_initialization"
                self.initialize_active_test()
                self.offline_cancel.set()
            elif phase == "active_cancel_initialization":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "cancelled", self.offline_report
                assert (
                    self.active_session is None
                    and not self.active_initialize.get_sensitive()
                )
                self.start_active_smoke("routine")
            elif phase == "service_run":
                assert self.offline_store.get_item(0).record["name"] == "Результат"
                assert self.offline_store.get_item(1).record["name"] == "Операция"
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                result = self.offline_report["result"]
                assert result["consumed_steps"] == result["total_steps"]
                assert result["kind"] == self.service_kinds[self.service_smoke_index]
                assert result["state"] == "complete"
                self.service_smoke_index += 1
                if self.service_smoke_index < len(self.service_kinds):
                    self.load_service_recording(
                        kind=self.service_kinds[self.service_smoke_index]
                    )
                    return GLib.SOURCE_REMOVE
                self.service_smoke_path = self.state_path.parent / "service-rks.json"
                self.service_smoke_path.write_bytes(create_demo_service_capture("rks"))
                self.offline_smoke_phase = "service_file"
                self.load_service_recording(self.service_smoke_path)
            elif phase in ("service_file", "service_repeat"):
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                assert self.offline_sources == (self.service_smoke_path,)
                try:
                    save_report(
                        self.service_smoke_path,
                        self.offline_report,
                        sources=self.offline_sources,
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError("Service export replaced its capture")
                if phase == "service_file":
                    document = json.loads(self.service_smoke_path.read_bytes())
                    document["steps"][0]["fault"] = "io"
                    path = self.state_path.parent / "service-fault.json"
                    path.write_text(json.dumps(document))
                    self.offline_smoke_phase = "service_fault"
                    self.load_service_recording(path)
                    return GLib.SOURCE_REMOVE
                document = json.loads(create_demo_service_capture("rks"))
                for name, value in document["workflow"]["data"].items():
                    self.rks_fields[name].set_text(value)
                self.rks_smoke_values = {
                    name: row.get_text() for name, row in self.rks_fields.items()
                }
                self.rks_smoke_request = self.state_path.parent / "ReproKeyRequest.xml"
                self.rks_smoke_key = self.state_path.parent / "rks-signature.xml"
                self.rks_smoke_key.write_bytes(
                    bytes.fromhex(document["workflow"]["key_xml"])
                )
                self.offline_smoke_phase = "native_utility_dcm_success"
                self.start_native_utility_smoke(
                    "native_utility_dcm_success",
                    controller="dcm",
                    group=DCM_UTILITY_GROUP,
                    dcm_value=0,
                )
                return GLib.SOURCE_REMOVE
            elif phase == "native_utility_dcm_success":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                result = self.offline_report["result"]
                assert result["status"] == "completed", result
                assert result["result"] == 0, result
                assert result["block"] == 0x13724, result
                assert result["done"] is True, result
                assert self.smoke_native_utility_screens >= 2
                self.offline_smoke_phase = "native_utility_dcm_warning"
                self.start_native_utility_smoke(
                    "native_utility_dcm_warning",
                    controller="dcm",
                    group=DCM_UTILITY_GROUP,
                    dcm_value=7,
                )
                return GLib.SOURCE_REMOVE
            elif phase == "native_utility_dcm_warning":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                result = self.offline_report["result"]
                assert result["status"] == "native-result", result
                assert result["result"] == 2005, result
                assert self.smoke_native_utility_screens >= 2
                self.offline_smoke_phase = "native_utility_dcm_cancel"
                self.start_native_utility_smoke(
                    "native_utility_dcm_cancel",
                    controller="dcm",
                    group=DCM_UTILITY_GROUP,
                    dcm_value=0,
                    cancel=True,
                )
                return GLib.SOURCE_REMOVE
            elif phase == "native_utility_dcm_cancel":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "cancelled", self.offline_report
                result = self.offline_report["result"]
                assert result["status"] == "cancelled", result
                assert result["done"] is True, result
                assert self.smoke_native_utility_screens >= 1
                self.offline_smoke_phase = "native_utility_bsm_probe"
                self.start_native_utility_smoke(
                    "native_utility_bsm_probe",
                    controller="bsm",
                    group=BSM_UTILITY_GROUP,
                )
                return GLib.SOURCE_REMOVE
            elif phase == "native_utility_bsm_probe":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "completed", self.offline_report
                result = self.offline_report["result"]
                assert result["status"] == "error", result
                assert result["result"] == 99, result
                assert result["utility_group"] == BSM_UTILITY_GROUP, result
                assert result["done"] is True, result
                assert self.smoke_native_utility_screens >= 1
                self.offline_smoke_phase = "rks_export"
                self.export_rks_request(self.rks_smoke_request, self.rks_smoke_values)
            elif phase == "rks_export":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.rks_smoke_request.exists()
                assert self.rks_smoke_request.stat().st_mode & 0o777 == 0o600
                self.rks_smoke_request_bytes = self.rks_smoke_request.read_bytes()
                assert b"<ReproKeyRequest>" in self.rks_smoke_request_bytes
                assert (
                    self.rks_smoke_values["seed"].encode()
                    in self.rks_smoke_request_bytes
                )
                self.offline_smoke_phase = "rks_export_existing"
                self.export_rks_request(self.rks_smoke_request, self.rks_smoke_values)
            elif phase == "rks_export_existing":
                assert self.offline_report is None
                assert (
                    self.rks_smoke_request.read_bytes() == self.rks_smoke_request_bytes
                )
                assert not list(self.state_path.parent.glob(".techstream-rks-*"))
                self.offline_smoke_phase = "rks_import"
                self.inspect_rks_key(self.rks_smoke_key)
            elif phase in ("rks_import", "rks_import_repeat"):
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["result"]["signature_characters"] == 512
                assert "A" * 512 not in json.dumps(self.offline_report)
                try:
                    save_report(
                        self.rks_smoke_key,
                        self.offline_report,
                        sources=self.offline_sources,
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError("RKS report replaced its signature source")
                if phase == "rks_import":
                    path = self.state_path.parent / "rks-invalid.xml"
                    path.write_bytes(b"<Signature>bad</Signature>")
                    self.offline_smoke_phase = "rks_import_fault"
                    self.inspect_rks_key(path)
                    return GLib.SOURCE_REMOVE
                print(
                    "GTK workbench smoke passed: source-bound Toyota procedure replay and explicit raw RAM reads with profile mismatch, native partial fault, cancellation, retry and source guards; selected Viewer/V native active help resources; local RKS XML export/import with collision, write-fault, malformed-input and redaction/source guards; seven captured service/RKS/notice workflows with imported-file/fault/cancel/repeat/export checks; active P3/P5/routine native initialization, signed negative-value wire execution, argument forms and recorded cleanup; resource browsing, search, favorites, CSV, regions, USB inventory, docs, "
                    "2-ECU health replay, JSON export, rendered selectable chart, 7 recorded session modes, "
                    f"{len(self.offline_keys)} offline procedures, native file inspection, cancellation, busy guard, failure recovery, protected export, vehicle categories/options/systems, selected command frames, 3 native recorded operations, exact calibration catalog planning, multiple snapshot buffers and imported XML/CSDF execution with native radio/key interaction, dialog cancellation, native DCM45 procedure success/native-warning/cancellation and the native BSM27 source rejection through the real utility dialog and imported DRS capture with actual trigger/graph/native DM export and source-bound CUW programming stage replay with single-use/fault/cancel/export guards"
                )
                self.finish_smoke()
            elif phase == "rks_import_fault":
                assert self.offline_report is None
                assert "512" in self.offline_status.get_text()
                self.rks_smoke_directory = (
                    self.state_path.parent / "rks-existing-directory"
                )
                self.rks_smoke_directory.mkdir()
                self.offline_smoke_phase = "rks_write_fault"
                self.export_rks_request(self.rks_smoke_directory, self.rks_smoke_values)
            elif phase == "rks_write_fault":
                assert self.offline_report is None
                assert self.rks_smoke_directory.is_dir()
                assert not list(self.state_path.parent.glob(".techstream-rks-*"))
                assert self.programming_form.get_sensitive()
                self.offline_smoke_phase = "rks_import_repeat"
                self.inspect_rks_key(self.rks_smoke_key)
            elif phase == "service_fault":
                assert self.offline_report is not None, self.offline_status.get_text()
                assert self.offline_report["status"] == "failed", self.offline_report
                assert self.offline_report["result"]["error_type"] == "OSError"
                self.offline_smoke_phase = "service_cancel"
                self.load_service_recording(self.service_smoke_path)
                self.offline_cancel.set()
            elif phase == "service_cancel":
                assert (
                    self.offline_report is None
                    or self.offline_report["status"] == "cancelled"
                )
                assert self.programming_form.get_sensitive()
                self.offline_smoke_phase = "service_repeat"
                self.load_service_recording(self.service_smoke_path)
            elif phase == "programming_fault":
                assert self.offline_report is None
                assert "source hash mismatch" in self.offline_status.get_text()
                assert self.programming_form.get_sensitive()
                self.set_programming_files(
                    "context",
                    (self.programming_smoke_paths["authored-programming.json"],),
                )
                self.offline_smoke_phase = "programming_cancel"
                self.load_programming_selection()
                self.offline_cancel.set()
            elif phase == "programming_cancel":
                assert self.offline_report is None and self.programming_session is None
                self.offline_smoke_phase = "programming_repeat_definition"
                self.load_programming_selection()
            elif phase == "catalog_fault":
                assert self.offline_report is None
                assert self.offline_catalog_controls.get_visible()
                self.offline_smoke_phase = "catalog_repeat"
                self.calibration_stage.set_selected(0)
                self.run_calibration_plan()
            elif phase == "catalog_cancel":
                assert self.offline_report is None
                assert self.calibration_catalog is self.smoke_catalog
                assert self.offline_catalog_controls.get_visible()
                self.offline_smoke_phase = "catalog_final"
                self.run_calibration_plan()
        except Exception as exc:  # noqa: BLE001 - every GUI assertion must fail the launcher.
            self.finish_smoke(exc)
        return GLib.SOURCE_REMOVE

    def start_workflow_smoke(self):
        inputs = create_workflow_examples(self.state_path.parent / "toyota-workflow")
        region, recording, category = (
            inputs["region_root"],
            inputs["recording"],
            inputs["category"],
        )
        assert (
            isinstance(region, str)
            and isinstance(recording, str)
            and isinstance(category, int)
        )
        catalog = VehicleCatalog(Path(region))
        profile = catalog.build_profile(category)
        self.workflow_smoke_selection = {
            "catalog": catalog,
            "vehicle_key": None,
            "system": {
                "category": category,
                "file": profile.filename,
            },
        }
        self.workflow_smoke_path = Path(recording)
        self.offline_smoke_phase = "workflow_run"
        self.load_workflow_recording(
            self.workflow_smoke_selection, self.workflow_smoke_path
        )

    def check_workflow_smoke(self, phase):
        if phase in ("workflow_run", "workflow_repeat"):
            assert self.offline_report is not None, self.offline_status.get_text()
            assert self.offline_report["status"] == "ok"
            assert self.offline_report["events_remaining"] == 0
            assert self.offline_report["result"]["native_clear_flag"] == 1
            for source in self.offline_sources:
                before = source.read_bytes()
                try:
                    save_report(
                        source, self.offline_report, sources=self.offline_sources
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError("Workflow export replaced a source")
                assert source.read_bytes() == before
            if phase == "workflow_repeat":
                self.start_ram_smoke()
                return GLib.SOURCE_REMOVE
            document = json.loads(self.workflow_smoke_path.read_bytes())
            document["context"]["database_sha256"] = "0" * 64
            invalid = self.state_path.parent / "workflow-wrong-profile.json"
            invalid.write_text(json.dumps(document))
            self.offline_smoke_phase = "workflow_fault"
            self.load_workflow_recording(self.workflow_smoke_selection, invalid)
        elif phase == "workflow_fault":
            assert self.offline_report is None
            self.offline_smoke_phase = "workflow_cancel"
            self.load_workflow_recording(
                self.workflow_smoke_selection, self.workflow_smoke_path
            )
            self.offline_cancel.set()
        elif phase == "workflow_cancel":
            assert (
                self.offline_report is None
                or self.offline_report["status"] == "cancelled"
            )
            self.offline_smoke_phase = "workflow_repeat"
            self.load_workflow_recording(
                self.workflow_smoke_selection, self.workflow_smoke_path
            )

    def start_ram_smoke(self):
        directory = self.state_path.parent / "ram-inputs"
        directory.mkdir()
        for name, raw in create_ram_examples().items():
            (directory / name).write_bytes(raw)
        self.ram_smoke_path = directory / "ram.json"
        self.ram_smoke_selection = {
            "catalog": VehicleCatalog(directory),
            "vehicle_key": None,
            "system": {"category": 42, "file": "demo.ddb"},
        }
        self.offline_smoke_phase = "ram_run"
        self.load_ram_recording(
            self.ram_smoke_selection, self.ram_smoke_path, address=256, length=8
        )

    def check_ram_smoke(self, phase):
        if phase in ("ram_run", "ram_repeat"):
            assert self.offline_report is not None, self.offline_status.get_text()
            assert self.offline_report["status"] == "ok"
            assert (
                self.offline_report["result"]["data_hex"] == "00 01 02 03 04 05 06 07"
            )
            assert self.offline_report["result"]["events_remaining"] == 0
            for source in self.offline_sources:
                before = source.read_bytes()
                try:
                    save_report(
                        source, self.offline_report, sources=self.offline_sources
                    )
                except ValueError:
                    pass
                else:
                    raise AssertionError("RAM export replaced source")
                assert source.read_bytes() == before
            if phase == "ram_repeat":
                self.start_active_smoke("p3")
                return
            document = json.loads(self.ram_smoke_path.read_bytes())
            document["binding"]["vehicle_ddb_sha256"] = "0" * 64
            path = self.state_path.parent / "ram-wrong-profile.json"
            path.write_text(json.dumps(document))
            self.offline_smoke_phase = "ram_fault"
            self.load_ram_recording(
                self.ram_smoke_selection, path, address=256, length=8
            )
        elif phase == "ram_fault":
            assert self.offline_report is None
            document = json.loads(self.ram_smoke_path.read_bytes())
            transaction = document["exchange"]["transactions"][0]
            transaction.pop("response")
            transaction.update(status=0xA0030201, partial_response="aabb")
            path = self.state_path.parent / "ram-native-error.json"
            path.write_text(json.dumps(document))
            self.offline_smoke_phase = "ram_native_fault"
            self.load_ram_recording(
                self.ram_smoke_selection, path, address=256, length=8
            )
        elif phase == "ram_native_fault":
            assert self.offline_report is not None
            assert self.offline_report["status"] == "failed"
            transaction = self.offline_report["result"]["transactions"][0]
            assert transaction["native_status"] == 0xA0030201
            assert transaction["response_hex"] == "aa bb"
            self.offline_smoke_phase = "ram_cancel"
            self.load_ram_recording(
                self.ram_smoke_selection, self.ram_smoke_path, address=256, length=8
            )
            self.offline_cancel.set()
        elif phase == "ram_cancel":
            assert (
                self.offline_report is None
                or self.offline_report["status"] == "cancelled"
            )
            self.offline_smoke_phase = "ram_repeat"
            self.load_ram_recording(
                self.ram_smoke_selection, self.ram_smoke_path, address=256, length=8
            )

    def start_active_smoke(self, family, *, negative=False):
        self.active_smoke_negative = negative
        directory = self.state_path.parent / (
            "active-signed-inputs" if negative else "active-inputs"
        )
        files = (
            create_signed_active_examples()
            if negative
            else create_active_text_examples()
        )
        for name, payload in files.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        catalog = VehicleCatalog(directory / "Techstream_DB_NA")
        selection = {
            "catalog": catalog,
            "system": {"category": 1, "file": "DemoEngine.ddb"},
            "vehicle_key": None,
            "sa_library": None,
        }
        if not negative:
            selection["viewer"] = directory / "Techstream_DB_NA" / "Viewer.ddb"
            selection["help_language"] = (
                directory / "Techstream_DB_NA" / "V_Example.ddb"
            )
        self.active_smoke_family = family
        self.offline_smoke_phase = "active_definition"
        filename = (
            f"active-{family}-negative.json" if negative else f"active-{family}.json"
        )
        self.load_active_recording(selection, directory / filename)

    def start_procedure_smoke(self, kind, phase):
        assert self.vehicle_catalog is not None
        selection = {
            "catalog": self.vehicle_catalog,
            "vehicle_key": 10001,
            "system": self.vehicle_catalog.vehicle_systems(10001)[0],
            "kind": kind,
            "resource": self.smoke_procedure_files[kind],
            "key_library": None,
            "record_files": {},
        }
        self.offline_smoke_phase = kind + "_" + phase
        self.load_procedure_resource(selection)

    def interact_utility_smoke(self):
        try:
            ui = self.utility_ui
            assert ui is not None
            if self.offline_smoke_phase == "utility_cancel":
                ui["dialog"].close()
            else:
                if not ui["keys"]:
                    return GLib.SOURCE_REMOVE
                button = dict(ui["keys"])["1"]
                if not button.get_sensitive():
                    assert self.utility_values() == {"INT02": 1}
                    next(
                        widget
                        for out, key, widget in ui["radios"]
                        if out == "INT02" and key == 2
                    ).set_active(True)
                else:
                    assert self.utility_values() == {"INT02": 2}
                    button.emit("clicked")
        except Exception as exc:  # noqa: BLE001
            self.offline_cancel.set()
            self.finish_smoke(exc)
        return GLib.SOURCE_REMOVE

    def start_native_utility_smoke(
        self, phase, *, controller, group, dcm_value=None, cancel=False
    ):
        """Drive a recovered native utility controller through the real GTK dialog."""
        from scripts.utility_authored import (
            DCM_COMMON_IDENTIFIERS,
            DCM_TEXT_IDENTIFIERS,
            DCM_UTILITY_GROUP,
            AuthoredNativeUtility,
        )

        directory = self.state_path.parent / "native-utility-inputs"
        directory.mkdir(exist_ok=True)
        files = create_utility_group_text_examples(
            DCM_UTILITY_GROUP,
            DCM_TEXT_IDENTIFIERS,
            common=DCM_COMMON_IDENTIFIERS,
        )
        language = directory / "U_Example.ddb"
        symbols = directory / "UtilityResID_NK.rsd"
        language.write_bytes(files["U_Example.ddb"])
        symbols.write_bytes(files["UtilityResID_NK.rsd"])
        self.native_utility_cancel = cancel
        self.smoke_native_utility_screens = 0

        def work():
            from scripts.utility import NativeBSMRuntime

            texts = UtilityTextResources.load(language, symbols, utility_group=group)
            fixture = AuthoredNativeUtility(dcm_value=dcm_value)
            runtime = fixture.runtime
            if controller == "bsm":
                runtime = NativeBSMRuntime(fixture.runtime.libraries)
            try:
                if controller == "bsm":
                    runtime.open(0x137B8)
                else:
                    runtime.start(0x13723)
                while not runtime.done:
                    event = self.utility_dialog(native_utility_screen(runtime, texts))
                    if type(event) is dict and set(event) == {"elapsed_ms"}:
                        runtime.progress(event["elapsed_ms"])
                    elif type(event) is dict and "key" in event:
                        runtime.key(event["key"], event.get("values") or None)
                    else:
                        raise ValueError("Invalid native utility host dialog event")
                status, report = "completed", runtime.report()
            except InterruptedError:
                runtime.cancel()
                status, report = "cancelled", runtime.report()
            finally:
                fixture.close()
            return {
                "workflow": f"native_utility_{controller}",
                "status": status,
                "physical_status": "PHYSICAL_UNCONFIRMED",
                "summary": "Нативная процедура выполнена по авторским данным",
                "result": report,
            }

        self.offline_smoke_phase = phase
        self.start_offline(language, operation=work, sources=(language, symbols))

    def interact_native_utility_smoke(self):
        try:
            ui = self.utility_ui
            assert ui is not None
            if self.native_utility_cancel:
                ui["dialog"].close()
                return GLib.SOURCE_REMOVE
            button = dict(ui["keys"]).get("acknowledge")
            if button is not None and button.get_sensitive():
                button.emit("clicked")
        except Exception as exc:  # noqa: BLE001
            self.offline_cancel.set()
            self.finish_smoke(exc)
        return GLib.SOURCE_REMOVE

    def start_native_smoke(self, operation, observations=True):
        assert self.vehicle_catalog is not None
        path = self.state_path.parent / f"native-{operation}.json"
        pairs = (
            [("2100", "6100")]
            if operation == "command"
            else [("210c", "610c80"), ("010c", "410c1f40")]
        )
        path.write_text(
            json.dumps(
                {
                    "schema": "techstream-native-exchange-v1",
                    "source": "authored_synthetic",
                    "ecus": ["engine"],
                    "support": {
                        "engine": {
                            "pid_lengths": {"0c": 2} if observations else None,
                            "did_lengths": None,
                        }
                    },
                    "transactions": [
                        {"ecu": "engine", "request": request, "response": response}
                        for request, response in pairs
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.offline_smoke_phase = (
            f"native_{operation}" if observations else "native_missing_observations"
        )
        system = self.vehicle_catalog.vehicle_systems(10001)[0]
        self.start_native_recording(
            path, system, operation, function_id=0x10, signal_keys=(1,)
        )

    def check_vehicle_smoke(self):
        try:
            assert self.vehicle_catalog is not None, self.vehicle_status.get_text()
            assert len(self.vehicle_filter_choices) == 4
            assert len(self.vehicle_candidates) == 1
            option = self.vehicle_options.get_first_child()
            assert option is not None
            option.emit("activated")
            assert self.vehicle_selection["vehicle_name_key"] == 10001
            assert self.vehicle_system_list.get_first_child() is not None
            self.vehicle_filter_choices[2][1].set_selected(1)
            assert self.vehicle_answers == []
            assert self.vehicle_options.get_first_child() is not None
            self.vehicle_options.get_first_child().emit("activated")
            assert self.vehicle_selection["vehicle_name_key"] == 10001
            system = self.vehicle_catalog.vehicle_systems(10001)[0]
            self.open_vehicle_system(None, system)
            assert self.pages.get_visible_child_name() == "diagnostics"
            assert self.diagnostic_database is not None
            self.offline_smoke_phase = "vehicle_commands"
            self.inspect_vehicle_function(system, 0x10)
        except Exception as exc:  # noqa: BLE001 - propagate every GUI assertion.
            self.finish_smoke(exc)
        return GLib.SOURCE_REMOVE

    def check_adapter_smoke(self):
        from unittest.mock import patch

        from scripts.jlr import USBLocation

        result = {
            "port": "1-2",
            "usb_bus": 1,
            "usb_address": 3,
            "serial_text": "SYNTHETIC",
            "firmware_raw": 1,
            "bootloader_raw": 2,
        }
        module = sys.modules[__name__]
        with patch.object(
            module,
            "usb_devices",
            return_value=[
                {
                    "id": "18e1:0104",
                    "port": "1-2",
                    "product": "Replay fixture",
                    "manufacturer": "",
                    "candidate": True,
                }
            ],
        ):
            self.adapter_result = result
            self.refresh_devices()
            assert self.adapter_result is None, (
                "Refresh retained an unverified cached identity"
            )
        with patch.object(
            module, "discover_jlr", return_value=[USBLocation("1-2", 1, 4, 0x81, 2)]
        ):
            self.adapter_checked(result, "")
            assert self.adapter_result is None, (
                "Reconnected device received an earlier USB incarnation's result"
            )
        with patch.object(module, "discover_jlr", return_value=[]):
            self.adapter_checked(result, "")
            assert (
                self.adapter_result is None and not self.adapter_probe.get_sensitive()
            )
        self.refresh_devices()

    def finish_smoke(self, error=None):
        if error is not None:
            print(f"GTK smoke failed: {error}", file=sys.stderr)
            traceback.print_exception(error)
            self.exit_code = 1
        self.window.close()
        self.quit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--root", type=Path)
    source.add_argument(
        "--demo",
        action="store_true",
        help="Generate synthetic resources; no original data required",
    )
    parser.add_argument(
        "--replay", type=Path, help="Open a diagnostic recording in the session page"
    )
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument(
        "--smoke-compact",
        action="store_true",
        help="Run the smoke flow in the collapsed narrow layout",
    )
    args = parser.parse_args()
    if args.smoke_compact and not args.smoke_test:
        parser.error("--smoke-compact requires --smoke-test")
    demo = args.demo or (args.root is None and not DEFAULT_ROOT.is_dir())
    temporary = (
        tempfile.TemporaryDirectory(prefix="techstream-smoke-")
        if args.smoke_test or demo
        else None
    )
    state = (
        Path(temporary.name)
        if temporary
        else Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
        / "techstream"
    )
    try:
        root = (
            create_demo(Path(temporary.name) / "demo")
            if demo and temporary is not None
            else args.root or DEFAULT_ROOT
        )
        app = Catalog(
            root,
            args.smoke_test,
            state / "saved.json",
            demo=demo,
            replay_path=args.replay,
            smoke_compact=args.smoke_compact,
        )
        result = app.run([])
        return app.exit_code or result
    finally:
        if temporary:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
