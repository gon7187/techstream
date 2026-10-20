"""Native resource workbench, offline diagnostic sessions and JLR USB probe."""

import argparse
import os
import sys
import tempfile
import threading
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

from scripts.demo import create_demo
from scripts.diagnostic_db import DiagnosticCatalog
from scripts.jlr import discover_jlr, probe_adapter
from scripts.pid_catalog import DEFAULT_ROOT
from scripts.plot import sample_chart
from scripts.session_cli import replay_session, save_report
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
    "Граница полного порта": "full-port.md",
}
CSS = b"""
.sidebar { background: #192635; color: #e1e8f0; }
.sidebar row { color: #d1dbe6; border-radius: 8px; margin: 3px 10px; }
.sidebar row:selected { background: #345574; color: white; }
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
    ):
        super().__init__(
            application_id="local.techstream.Workbench",
            flags=Gio.ApplicationFlags.NON_UNIQUE,
        )
        self.root = root
        self.demo = demo
        self.replay_path = replay_path
        self.smoke_test = smoke_test
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
        if self.adapter_thread is not None:
            self.adapter_thread.join()
        if self.session_thread is not None:
            self.session_thread.join()

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
        compact = Adw.Breakpoint.new(Adw.BreakpointCondition.parse("max-width: 1100px"))
        for split in (self.layout, self.catalog_split):
            compact.add_setter(split, "collapsed", True)
            compact.add_setter(split, "show-sidebar", False)
        for button in [*self.nav_buttons, self.groups_button]:
            compact.add_setter(button, "visible", True)
        self.window.add_breakpoint(compact)
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
        self.navigation.select_row(self.navigation.get_row_at_index(0))
        self.window.present()
        self.load_catalog()
        if self.replay_path is not None and not self.smoke_test:
            self.navigation.select_row(self.navigation.get_row_at_index(5))
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
        self.navigation = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.navigation.add_css_class("navigation-sidebar")
        for title, icon in (
            ("Параметры", "view-list-symbolic"),
            ("Избранное", "starred-symbolic"),
            ("Адаптер", "network-wired-symbolic"),
            ("Документация", "help-browser-symbolic"),
            ("Системы и ошибки", "dialog-warning-symbolic"),
            ("Сеанс диагностики", "media-playback-start-symbolic"),
        ):
            row = Adw.ActionRow(title=title)
            row.add_prefix(Gtk.Image.new_from_icon_name(icon))
            self.navigation.append(row)
        self.navigation.connect("row-selected", self.navigate)
        sidebar.append(self.navigation)
        footer = box(margin=24, spacing=8)
        footer.set_vexpand(True)
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
            lambda *_: self.navigation.select_row(self.navigation.get_row_at_index(2)),
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
            icon_name="edit-find-symbolic",
            title="Выберите группу",
            description="Выберите группу слева или найдите параметр во всех группах.",
        )
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
            ["Обзор систем", "График параметров", "Калибровки"]
        )
        self.session_mode.set_hexpand(True)
        choices.append(self.session_mode)
        self.session_samples = Gtk.SpinButton.new_with_range(1, 10000, 1)
        self.session_samples.set_value(12)
        self.session_samples.set_tooltip_text("Число отсчётов для графика")
        self.session_samples.set_sensitive(False)
        self.session_mode.connect(
            "notify::selected",
            lambda *_: self.session_samples.set_sensitive(
                self.session_mode.get_selected() == 1
            ),
        )
        choices.append(self.session_samples)
        page.append(choices)
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

    def start_example(self, *_args):
        filenames = (
            "diagnostic-session.json",
            "live-session.json",
            "calibration-session.json",
        )
        if self.session_mode.get_selected() == 1:
            self.session_samples.set_value(12)
        self.start_session(
            PROJECT / "examples" / filenames[self.session_mode.get_selected()]
        )

    def start_session(self, path):
        if self.session_busy:
            return
        self.session_busy = True
        self.session_report = None
        self.session_source = path
        self.session_cancel.clear()
        self.session_example.set_sensitive(False)
        self.session_open.set_sensitive(False)
        self.session_mode.set_sensitive(False)
        self.session_samples.set_sensitive(False)
        self.session_stop.set_sensitive(True)
        self.session_export.set_sensitive(False)
        while child := self.session_results.get_first_child():
            self.session_results.remove(child)
        self.session_summary.set_text("Чтение записи и разбор ответов…")

        operation = ("replay", "poll", "calibration")[self.session_mode.get_selected()]
        samples = self.session_samples.get_value_as_int()

        def work():
            try:
                report, error = (
                    replay_session(
                        path,
                        self.session_cancel.is_set,
                        operation=operation,
                        samples=samples,
                    ),
                    "",
                )
            except (OSError, ValueError) as exc:
                report, error = None, str(exc)
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
            self.plot_picture.set_paintable(
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
        self.root = list(self.roots.values())[selected]
        self.configuring = False

    def change_region(self, *_args):
        if not getattr(self, "configuring", True):
            self.root = list(self.roots.values())[self.region.get_selected()]
            self.load_catalog()

    def load_catalog(self):
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

    def navigate(self, _list, row):
        if row is None:
            return
        if self.layout.get_collapsed():
            self.layout.set_show_sidebar(False)
        page = row.get_index()
        self.pages.set_visible_child_name(
            "catalog"
            if page < 2
            else ("adapter", "docs", "diagnostics", "session")[page - 2]
        )
        if page < 2:
            self.saved_only = page == 1
            self.page_title.set_text("Избранное" if self.saved_only else "Параметры")
            self.filter_groups()
        elif page == 2:
            self.refresh_devices()
        elif page == 4 and self.diagnostics is None:
            self.load_diagnostics()

    def focus_search(self, groups):
        if self.pages.get_visible_child_name() != "catalog":
            self.navigation.select_row(self.navigation.get_row_at_index(0))
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
                print(
                    "GTK workbench smoke passed: resource browsing, search, favorites, CSV, regions, USB inventory, docs, 2-ECU health replay, JSON export, rendered selectable chart and calibration replay"
                )
                self.finish_smoke()
                return GLib.SOURCE_REMOVE
            if self.window.get_width() <= 1100:
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
                self.navigation.select_row(self.navigation.get_row_at_index(1))
                assert self.group_model.get_n_items() == 1
                self.all_groups.set_active(True)
                self.filter_parameters()
                assert self.records and all(r["group"] == group for r in self.records)
                destination = self.state_path.parent / "smoke-export.csv"
                export_csv(destination, self.records)
                assert expected_name in destination.read_text(encoding="utf-8-sig")
                self.navigation.select_row(self.navigation.get_row_at_index(2))
                assert self.devices.get_first_child() is not None
                self.check_adapter_smoke()
                self.navigation.select_row(self.navigation.get_row_at_index(3))
                assert self.doc_view.get_buffer().get_char_count() > 100
                self.navigation.select_row(self.navigation.get_row_at_index(0))
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
                self.navigation.select_row(self.navigation.get_row_at_index(4))
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
                self.navigation.select_row(self.navigation.get_row_at_index(5))
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
    args = parser.parse_args()
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
        )
        result = app.run([])
        return app.exit_code or result
    finally:
        if temporary:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
