#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = [
#     "msgpack",
#     "urwid",
# ]
# ///
"""
w1dump_tui.py - an interactive TUI for exploring w1dump files

usage:
    ./scripts/w1dump_tui.py dump.w1dump

features:
    - multi-tab interface with keyboard navigation
    - overview, registers, modules, memory map, and region editor tabs
    - export filtered dumps with selected regions
    - search and filtering capabilities
"""

import sys
import argparse
import re
from pathlib import Path
from typing import List, Optional, Tuple, Any, NamedTuple

import urwid
import w1dump


class SearchResult(NamedTuple):
    """search result with context"""
    address: int
    region_index: int
    offset: int
    context_before: bytes
    match: bytes
    context_after: bytes


class HexSearcher:
    """efficient hex pattern search using Boyer-Moore algorithm"""
    
    @staticmethod
    def parse_hex_pattern(pattern: str) -> Tuple[bytes, bytes]:
        """
        parse hex pattern like "48 8B ?? 90" into pattern and mask
        returns (pattern_bytes, mask_bytes) where mask 0x00 = wildcard, 0xFF = exact match
        """
        # remove whitespace and normalize
        pattern = re.sub(r'\s+', ' ', pattern.strip().upper())
        parts = pattern.split(' ')
        
        pattern_bytes = bytearray()
        mask_bytes = bytearray()
        
        for part in parts:
            if part == '??':
                pattern_bytes.append(0x00)
                mask_bytes.append(0x00)  # wildcard
            else:
                try:
                    byte_val = int(part, 16)
                    pattern_bytes.append(byte_val)
                    mask_bytes.append(0xFF)  # exact match
                except ValueError:
                    raise ValueError(f"invalid hex byte: {part}")
        
        return bytes(pattern_bytes), bytes(mask_bytes)
    
    @staticmethod
    def search(data: bytes, pattern: bytes, mask: bytes) -> List[int]:
        """
        search for pattern in data using boyer-moore with wildcard support
        returns list of offsets where pattern matches
        """
        if len(pattern) != len(mask):
            raise ValueError("pattern and mask must be same length")
        
        if not pattern:
            return []
        
        results = []
        data_len = len(data)
        pattern_len = len(pattern)
        
        if pattern_len > data_len:
            return results
        
        # simplified boyer-moore with wildcards
        # build bad character table for exact bytes only
        bad_char = {}
        for i, (p_byte, m_byte) in enumerate(zip(pattern, mask)):
            if m_byte == 0xFF:  # exact match required
                bad_char[p_byte] = i
        
        skip = 0
        while skip <= data_len - pattern_len:
            # check pattern at current position
            match = True
            for i in range(pattern_len):
                if mask[i] == 0xFF:  # exact match required
                    if data[skip + i] != pattern[i]:
                        match = False
                        break
                # wildcards (mask[i] == 0x00) always match
            
            if match:
                results.append(skip)
                skip += 1  # continue searching for overlapping matches
            else:
                # boyer-moore skip calculation
                if skip + pattern_len - 1 < data_len:
                    bad_char_byte = data[skip + pattern_len - 1]
                    if bad_char_byte in bad_char:
                        skip = max(1, pattern_len - bad_char[bad_char_byte] - 1) + skip
                    else:
                        skip += pattern_len
                else:
                    skip += 1
        
        return results


class GotoDialog:
    """dialog for entering hex addresses"""
    
    def __init__(self, callback):
        self.callback = callback
        self.edit = urwid.Edit("Address: ")
        
        ok_button = urwid.Button("OK", on_press=self.on_ok)
        cancel_button = urwid.Button("Cancel", on_press=self.on_cancel)
        
        buttons = urwid.Columns([
            ('fixed', 6, urwid.AttrMap(ok_button, 'body')),
            ('fixed', 10, urwid.AttrMap(cancel_button, 'body')),
        ], dividechars=2)
        
        pile = urwid.Pile([
            self.edit,
            urwid.Divider(),
            buttons
        ])
        
        self.widget = urwid.LineBox(pile, title="Goto")
    
    def keypress(self, size, key):
        if key == 'enter':
            self.on_ok(None)
            return None
        elif key == 'esc':
            self.on_cancel(None)
            return None
        else:
            return self.widget.keypress(size, key)
    
    def on_ok(self, button):
        text = self.edit.get_edit_text().strip()
        try:
            if text.startswith('0x') or text.startswith('0X'):
                address = int(text, 16)
            else:
                address = int(text, 16) if text else 0
            self.callback(address)
        except ValueError:
            # invalid input, show error
            pass
        raise urwid.ExitMainLoop()
    
    def on_cancel(self, button):
        self.callback(None)
        raise urwid.ExitMainLoop()


class HelpDialog:
    """enhanced help dialog with categorized shortcuts"""
    
    def __init__(self, on_close):
        self.on_close = on_close
        help_sections = [
            ("Navigation", [
                "Tab/Shift-Tab    - Switch between tabs",
                "1-6              - Jump directly to tab",
                "↑/↓ or j/k       - Navigate lists",
                "Page Up/Down     - Scroll pages",
                "Home/End         - Go to top/bottom",
            ]),
            ("Search & Navigation", [
                "/                - Search hex pattern (e.g., '48 8B ?? 90')",
                "g                - Goto address",
                "n                - Next search result",
                "p                - Previous search result",
            ]),
            ("Region Editor", [
                "Space            - Toggle region selection",
                "a                - Select all regions",
                "Ctrl+a           - Select all regions",
                "z                - Select none",
                "e                - Export selected regions",
            ]),
            ("Global", [
                "?                - Show this help",
                "h                - Show this help",
                "q                - Quit",
                "Ctrl+c           - Quit",
            ])
        ]
        
        lines = []
        for section_name, shortcuts in help_sections:
            lines.append(urwid.Text(('header', section_name)))
            for shortcut in shortcuts:
                lines.append(urwid.Text(f"  {shortcut}"))
            lines.append(urwid.Divider())
        
        lines.append(urwid.Text("Press any key to close this help...", align='center'))
        
        listbox = urwid.ListBox(urwid.SimpleFocusListWalker([
            urwid.AttrMap(line, 'body') for line in lines
        ]))
        
        self.widget = urwid.LineBox(listbox, title="Help - w1dump TUI")
    
    def keypress(self, size, key):
        # close on any key press
        self.on_close()
        return key


class W1DumpTUI:
    """main TUI application class"""
    
    TAB_OVERVIEW = 0
    TAB_REGISTERS = 1
    TAB_MODULES = 2
    TAB_MEMORY = 3
    TAB_REGION_EDITOR = 4
    TAB_SEARCH = 5
    
    def __init__(self, dump_file: Path):
        self.dump_file = dump_file
        self.dump = None
        self.selected_regions = set()
        self.search_results = []
        self.current_search_index = -1
        self.last_search_pattern = ""
        
        try:
            self.dump = w1dump.load_dump(dump_file)
        except Exception as e:
            raise ValueError(f"failed to load dump: {e}")
        
        self.palette = [
            ('title', 'white,bold', 'dark blue'),
            ('tab_active', 'white,bold', 'dark blue'),
            ('tab_inactive', 'white', 'black'),
            ('header', 'yellow,bold', 'black'),
            ('body', 'white', 'black'),
            ('footer', 'white', 'dark blue'),
            ('error', 'light red', 'black'),
            ('success', 'light green', 'black'),
            ('highlight', 'white,bold', 'dark red'),
            ('checkbox', 'white', 'black'),
            ('checkbox_selected', 'white,bold', 'dark green'),
        ]
        
        self.tab_names = ['Overview', 'Registers', 'Modules', 'Memory Map', 'Region Editor', 'Search']
        self.current_tab = 0
        self.setup_ui()
    
    @staticmethod
    def format_size(size: int) -> str:
        """format byte size in human readable form"""
        if size >= 1024*1024*1024:
            return f"{size/(1024*1024*1024):.1f}G"
        elif size >= 1024*1024:
            return f"{size/(1024*1024):.1f}M"
        elif size >= 1024:
            return f"{size/1024:.1f}K"
        else:
            return f"{size:,}"
    
    @staticmethod
    def build_flag_string(region) -> str:
        """build flag string for memory region"""
        flags = []
        if region.is_stack:
            flags.append("STACK")
        if region.is_code:
            flags.append("CODE")
        if region.is_data:
            flags.append("DATA")
        if region.is_anonymous:
            flags.append("ANON")
        if hasattr(region, 'data') and region.data:
            flags.append("DUMPED" if len(flags) < 4 else "DUMP")
        return ",".join(flags)
    
    def create_table_header(self, columns_data: List[Tuple]) -> urwid.Widget:
        """create a table header row"""
        widgets = self._build_column_widgets(columns_data, is_header=True)
        row = urwid.Columns(widgets, dividechars=1)
        return urwid.AttrMap(row, 'header')
    
    def create_table_row(self, columns_data: List[Tuple], selectable=True) -> urwid.Widget:
        """create a table data row"""
        widgets = self._build_column_widgets(columns_data, is_header=False)
        row = urwid.Columns(widgets, dividechars=1)
        if selectable:
            return urwid.AttrMap(row, 'body', 'highlight')
        else:
            return urwid.AttrMap(row, 'body')
    
    def _build_column_widgets(self, columns_data: List[Tuple], is_header: bool) -> List[Tuple]:
        """build column widgets from specifications"""
        widgets = []
        for spec in columns_data:
            if len(spec) == 2:
                width, text = spec
                if isinstance(width, int):
                    attr = ('header', text) if is_header else text
                    widgets.append(('fixed', width, urwid.Text(attr)))
                else:
                    attr = ('header', text) if is_header else text
                    widgets.append(urwid.Text(attr))
            elif len(spec) == 3:
                width_type, width_val, text = spec
                attr = ('header', text) if is_header else text
                widgets.append((width_type, width_val, urwid.Text(attr)))
        return widgets
    
    def update_status_bar(self, message=None):
        """update status bar with dynamic shortcuts based on current tab"""
        if message:
            self.status_text.set_text(message)
            return
        
        base_shortcuts = "Tab:Switch ?:Help q:Quit"
        tab_shortcuts = {
            self.TAB_REGION_EDITOR: " g:Goto /:Search Space:Toggle a:All z:None e:Export",
            self.TAB_MODULES: " g:Goto /:Search",
            self.TAB_MEMORY: " g:Goto /:Search",
            self.TAB_SEARCH: " Enter:Search n:Next p:Prev",
        }
        
        shortcuts = base_shortcuts + tab_shortcuts.get(self.current_tab, "")
        
        if self.search_results:
            shortcuts += f" | Results: {len(self.search_results)}"
            if self.current_search_index >= 0:
                shortcuts += f" ({self.current_search_index + 1}/{len(self.search_results)})"
        
        self.status_text.set_text(f"File: {self.dump_file.name} | {shortcuts}")
        self.status_bar.set_attr_map({None: 'footer'})
    
    def setup_ui(self):
        """initialize the main UI structure"""
        self.tab_buttons = []
        for i, name in enumerate(self.tab_names):
            btn = urwid.Button(f" {name} ", on_press=self.switch_tab, user_data=i)
            if i == 0:
                btn = urwid.AttrMap(btn, 'tab_active', 'tab_active')
            else:
                btn = urwid.AttrMap(btn, 'tab_inactive', 'tab_inactive')
            self.tab_buttons.append(btn)
        
        self.tab_bar = urwid.Columns(self.tab_buttons, dividechars=1)
        
        self.tab_contents = [None] * len(self.tab_names)
        self.tab_contents[self.TAB_OVERVIEW] = self.create_overview_tab()
        self.tab_contents[self.TAB_REGISTERS] = self.create_registers_tab()
        self.tab_contents[self.TAB_MODULES] = self.create_modules_tab()
        self.tab_contents[self.TAB_MEMORY] = self.create_memory_tab()
        self.tab_contents[self.TAB_REGION_EDITOR] = self.create_region_editor_tab()
        self.tab_contents[self.TAB_SEARCH] = self.create_search_tab()
        
        self.status_text = urwid.Text("")
        self.status_bar = urwid.AttrMap(self.status_text, 'footer')
        self.update_status_bar()
        
        header = urwid.Pile([
            urwid.AttrMap(urwid.Text(f"w1dump TUI - {self.dump.metadata.process_name}", align='center'), 'title'),
            urwid.Divider(),
            self.tab_bar,
            urwid.Divider('─'),
        ])
        
        self.content_area = self.tab_contents[self.TAB_OVERVIEW]
        
        self.main_frame = urwid.Frame(
            body=self.content_area,
            header=header,
            footer=self.status_bar
        )
    
    def create_overview_tab(self):
        """create overview tab content"""
        lines = []
        
        lines.append(urwid.Text(('header', 'Process Information')))
        lines.append(urwid.Text(f"Name:         {self.dump.metadata.process_name}"))
        lines.append(urwid.Text(f"PID:          {self.dump.metadata.pid}"))
        lines.append(urwid.Text(f"Architecture: {self.dump.metadata.arch} ({self.dump.metadata.pointer_size * 8}-bit)"))
        lines.append(urwid.Text(f"Platform:     {self.dump.metadata.os}"))
        
        # timestamp
        if self.dump.metadata.timestamp > 0:
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(self.dump.metadata.timestamp / 1000.0, tz=timezone.utc)
            lines.append(urwid.Text(f"Captured:     {dt.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}"))
        
        lines.append(urwid.Text(f"Thread ID:    {self.dump.thread.thread_id}"))
        lines.append(urwid.Divider())
        
        lines.append(urwid.Text(('header', 'Statistics')))
        lines.append(urwid.Text(f"Modules:         {len(self.dump.modules):4d}"))
        lines.append(urwid.Text(f"Memory regions:  {len(self.dump.regions):4d}"))
        
        total_size = sum(r.size for r in self.dump.regions)
        code_size = sum(r.size for r in self.dump.regions if r.is_code)
        data_size = sum(r.size for r in self.dump.regions if r.is_data)
        stack_size = sum(r.size for r in self.dump.regions if r.is_stack)
        anon_size = sum(r.size for r in self.dump.regions if r.is_anonymous)
        
        
        lines.append(urwid.Divider())
        lines.append(urwid.Text(('header', 'Memory Breakdown')))
        lines.append(urwid.Text(f"Total:      {self.format_size(total_size):>12} ({total_size:,} bytes)"))
        lines.append(urwid.Text(f"Code:       {self.format_size(code_size):>12} ({code_size:,} bytes)"))
        lines.append(urwid.Text(f"Data:       {self.format_size(data_size):>12} ({data_size:,} bytes)"))
        lines.append(urwid.Text(f"Stack:      {self.format_size(stack_size):>12} ({stack_size:,} bytes)"))
        lines.append(urwid.Text(f"Anonymous:  {self.format_size(anon_size):>12} ({anon_size:,} bytes)"))
        
        # current execution context
        if self.dump.thread.gpr_state:
            lines.append(urwid.Divider())
            lines.append(urwid.Text(('header', 'Execution Context')))
            pc = self.dump.thread.gpr_state.pc
            lines.append(urwid.Text(f"PC:           {pc:016x}"))
            
            # find module at PC
            module = self.dump.get_module_at(pc)
            if module:
                lines.append(urwid.Text(f"Module:       {module.name}"))
                lines.append(urwid.Text(f"Module base:  {module.base_address:016x}"))
                lines.append(urwid.Text(f"Offset:       +{pc - module.base_address:x}"))
            
            # find region at PC
            region = self.dump.get_region_at(pc)
            if region:
                lines.append(urwid.Text(f"Region:       {region.start:016x}-{region.end:016x} {region.perms_str}"))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker([urwid.AttrMap(line, 'body') for line in lines]))
    
    def create_registers_tab(self):
        """create registers tab content"""
        lines = []
        
        if self.dump.thread.gpr_state:
            lines.append(urwid.Text(('header', 'General Purpose Registers')))
            # split the register string by newlines and create text widgets
            reg_str = str(self.dump.thread.gpr_state)
            for reg_line in reg_str.split('\n'):
                lines.append(urwid.Text(f"  {reg_line}"))
        else:
            lines.append(urwid.Text(('error', 'No parsed register state available')))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker([urwid.AttrMap(line, 'body') for line in lines]))
    
    def create_modules_tab(self):
        """create modules tab content"""
        lines = []
        
        # table header
        header_cols = [
            (18, "Address"),
            (12, "Size"),
            ('weight', 1, "Name"),
            (4, "Type"),
            (8, "Flags")
        ]
        
        lines.append(self.create_table_header(header_cols))
        lines.append(urwid.Divider('─'))
        
        # sort all modules by address
        all_modules = sorted(self.dump.modules, key=lambda m: m.base_address)
        
        for module in all_modules:
            # build flags
            flags = ["SYS"] if module.is_system_library else []
            flag_str = ",".join(flags)
            
            # format size and type
            size_str = self.format_size(module.size)
            type_short = "E" if module.type == "main_executable" else "L"
            
            row_data = [
                (18, f"{module.base_address:016x}"),
                (12, size_str),
                ('weight', 1, module.name),
                (4, type_short),
                (8, flag_str)
            ]
            
            lines.append(self.create_table_row(row_data))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker(lines))
    
    def create_memory_tab(self):
        """create memory map tab content"""
        lines = []
        
        # table header
        header_cols = [
            (18, "Start"),
            (18, "End"),
            (5, "Perms"),
            (12, "Size"),
            ('weight', 1, "Module"),
            (20, "Flags")
        ]
        
        lines.append(self.create_table_header(header_cols))
        lines.append(urwid.Divider('─'))
        
        # show ALL regions (no truncation)
        regions = sorted(self.dump.regions, key=lambda r: r.start)
        
        for region in regions:
            flag_str = self.build_flag_string(region)
            size_str = self.format_size(region.size)
            
            row_data = [
                (18, f"{region.start:016x}"),
                (18, f"{region.end:016x}"),
                (5, region.perms_str),
                (12, size_str),
                ('weight', 1, region.module_name or ""),
                (20, flag_str)
            ]
            
            lines.append(self.create_table_row(row_data))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker(lines))
    
    def create_region_editor_tab(self):
        """create region editor tab content"""
        lines = []
        
        # control buttons
        buttons = urwid.Columns([
            urwid.Text(('header', 'Region Editor - Select regions to export:')),
            ('fixed', 8, urwid.AttrMap(urwid.Button("All", on_press=self.select_all_regions), 'body')),
            ('fixed', 9, urwid.AttrMap(urwid.Button("None", on_press=self.select_no_regions), 'body')),
            ('fixed', 11, urwid.AttrMap(urwid.Button("Export", on_press=self.export_selected), 'success')),
        ], dividechars=2)
        
        lines.append(buttons)
        lines.append(urwid.Divider('─'))
        
        # table header
        header_cols = [
            (4, "Sel"),
            (18, "Start"),
            (18, "End"),
            (6, "Perms"),
            (12, "Size"),
            ('weight', 1, "Module"),
            (15, "Flags")
        ]
        
        lines.append(self.create_table_header(header_cols))
        lines.append(urwid.Divider('─'))
        
        # region checkboxes for ALL regions (no truncation)
        self.region_checkboxes = []
        regions = sorted(self.dump.regions, key=lambda r: r.start)
        
        for i, region in enumerate(regions):
            flag_str = self.build_flag_string(region).replace("DUMPED", "DUMP")
            size_str = self.format_size(region.size)
            
            checkbox = urwid.CheckBox("", state=True, on_state_change=self.region_checkbox_changed, user_data=i)
            self.region_checkboxes.append(checkbox)
            
            # create a selectable row with proper column alignment
            row = urwid.Columns([
                ('fixed', 4, checkbox),
                ('fixed', 18, urwid.Text(f"{region.start:016x}")),
                ('fixed', 18, urwid.Text(f"{region.end:016x}")),
                ('fixed', 6, urwid.Text(region.perms_str)),
                ('fixed', 12, urwid.Text(size_str)),
                ('weight', 1, urwid.Text(region.module_name or "")),
                ('fixed', 15, urwid.Text(flag_str))
            ], dividechars=1)
            
            lines.append(urwid.AttrMap(row, 'body', 'highlight'))
        
        # initialize selected regions to all
        self.selected_regions = set(range(len(self.dump.regions)))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker(lines))
    
    def create_search_tab(self):
        """create search tab content"""
        lines = []
        
        # search input
        self.search_edit = urwid.Edit("Hex Pattern (e.g., '48 8B ?? 90'): ")
        search_btn = urwid.Button("Search", on_press=self.perform_search)
        
        search_row = urwid.Columns([
            ('weight', 1, self.search_edit),
            ('fixed', 10, urwid.AttrMap(search_btn, 'body')),
        ], dividechars=2)
        
        lines.append(urwid.Text(('header', 'Hex Pattern Search')))
        lines.append(urwid.Divider())
        lines.append(search_row)
        lines.append(urwid.Divider())
        
        # results display
        self.search_results_walker = urwid.SimpleFocusListWalker([])
        self.search_results_listbox = urwid.ListBox(self.search_results_walker)
        
        if not self.search_results:
            lines.append(urwid.Text("No search results. Enter a hex pattern above."))
        else:
            # show search results
            lines.append(urwid.Text(('header', f'Results ({len(self.search_results)}):')))
            for i, result in enumerate(self.search_results):
                region = self.dump.regions[result.region_index]
                text = f"{result.address:016x} (+{result.offset:x}) in {region.module_name or 'unknown'}"
                if i == self.current_search_index:
                    lines.append(urwid.AttrMap(urwid.Text(f"→ {text}"), 'highlight'))
                else:
                    lines.append(urwid.Text(f"  {text}"))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker([urwid.AttrMap(line, 'body') for line in lines]))
    
    def switch_tab(self, button, tab_index):
        """switch to a different tab"""
        # update tab button appearance
        for i, btn in enumerate(self.tab_buttons):
            if i == tab_index:
                btn.set_attr_map({None: 'tab_active'})
            else:
                btn.set_attr_map({None: 'tab_inactive'})
        
        # update content
        self.current_tab = tab_index
        self.content_area = self.tab_contents[tab_index]
        self.main_frame.body = self.content_area
        self.update_status_bar()
    
    def select_all_regions(self, button):
        """select all regions for export"""
        for checkbox in self.region_checkboxes:
            checkbox.set_state(True)
    
    def select_no_regions(self, button):
        """deselect all regions for export"""
        for checkbox in self.region_checkboxes:
            checkbox.set_state(False)
    
    def region_checkbox_changed(self, checkbox, new_state, user_data):
        """handle region checkbox state change"""
        region_index = user_data
        if new_state:
            self.selected_regions.add(region_index)
        else:
            self.selected_regions.discard(region_index)
    
    def export_selected(self, button):
        """export dump with selected regions"""
        if not self.selected_regions:
            self.show_message("No regions selected for export", "error")
            return
        
        # generate output filename
        base_name = self.dump_file.stem
        output_file = self.dump_file.parent / f"{base_name}_filtered.w1dump"
        
        try:
            selected_list = list(self.selected_regions)
            w1dump.export_dump(self.dump, output_file, selected_list)
            self.show_message(f"Exported {len(selected_list)} regions to {output_file.name}", "success")
        except Exception as e:
            self.show_message(f"Export failed: {e}", "error")
    
    def perform_search(self, button=None):
        """perform hex pattern search"""
        pattern = self.search_edit.get_edit_text().strip()
        if not pattern:
            self.show_message("Enter a hex pattern to search", "error")
            return
        
        try:
            pattern_bytes, mask_bytes = HexSearcher.parse_hex_pattern(pattern)
        except ValueError as e:
            self.show_message(f"Invalid hex pattern: {e}", "error")
            return
        
        self.search_results = []
        self.current_search_index = -1
        self.last_search_pattern = pattern
        
        # search through all regions with data
        for region_idx, region in enumerate(self.dump.regions):
            if not region.data:
                continue
            
            matches = HexSearcher.search(region.data, pattern_bytes, mask_bytes)
            for offset in matches:
                address = region.start + offset
                context_start = max(0, offset - 8)
                context_end = min(len(region.data), offset + len(pattern_bytes) + 8)
                
                result = SearchResult(
                    address=address,
                    region_index=region_idx,
                    offset=offset,
                    context_before=region.data[context_start:offset],
                    match=region.data[offset:offset + len(pattern_bytes)],
                    context_after=region.data[offset + len(pattern_bytes):context_end]
                )
                self.search_results.append(result)
        
        if self.search_results:
            self.current_search_index = 0
            self.show_message(f"Found {len(self.search_results)} matches", "success")
        else:
            self.show_message("No matches found", "error")
        
        self.update_status_bar()
        
        # refresh search tab if currently active
        if self.current_tab == self.TAB_SEARCH:
            self.tab_contents[self.TAB_SEARCH] = self.create_search_tab()
            self.main_frame.body = self.tab_contents[self.TAB_SEARCH]
    
    def goto_address(self):
        """show goto address dialog"""
        def on_address_entered(address):
            if address is None:
                return
            
            # find module containing this address
            module = self.dump.get_module_at(address)
            region = self.dump.get_region_at(address)
            
            if module or region:
                # switch to appropriate tab and highlight the item
                if module:
                    self.switch_tab(None, self.TAB_MODULES)
                    self.show_message(f"Found address in module: {module.name}", "success")
                elif region:
                    self.switch_tab(None, self.TAB_MEMORY)
                    self.show_message(f"Found address in region: {region.start:016x}-{region.end:016x}", "success")
            else:
                self.show_message(f"Address {address:016x} not found in dump", "error")
        
        dialog = GotoDialog(on_address_entered)
        overlay = urwid.Overlay(
            dialog.widget,
            self.main_frame,
            align='center',
            width=30,
            valign='middle',
            height=5,
        )
        
        def dialog_unhandled_input(key):
            return dialog.keypress(None, key)
        
        loop = urwid.MainLoop(overlay, self.palette, unhandled_input=dialog_unhandled_input)
        loop.run()
    
    def next_search_result(self):
        """go to next search result"""
        if not self.search_results:
            self.show_message("No search results", "error")
            return
        
        self.current_search_index = (self.current_search_index + 1) % len(self.search_results)
        self.update_status_bar()
        self.show_message(f"Search result {self.current_search_index + 1}/{len(self.search_results)}", "body")
    
    def prev_search_result(self):
        """go to previous search result"""
        if not self.search_results:
            self.show_message("No search results", "error")
            return
        
        self.current_search_index = (self.current_search_index - 1) % len(self.search_results)
        self.update_status_bar()
        self.show_message(f"Search result {self.current_search_index + 1}/{len(self.search_results)}", "body")
    
    def show_message(self, message, style='body'):
        """show a message in the status bar temporarily"""
        self.status_text.set_text(message)
        if style == 'error':
            self.status_bar.set_attr_map({None: 'error'})
        elif style == 'success':
            self.status_bar.set_attr_map({None: 'success'})
        else:
            self.status_bar.set_attr_map({None: 'footer'})
    
    def show_help_dialog(self):
        """show enhanced help dialog"""
        def close_help():
            raise urwid.ExitMainLoop()
        
        help_dialog = HelpDialog(close_help)
        overlay = urwid.Overlay(
            help_dialog.widget,
            self.main_frame,
            align='center',
            width=60,
            valign='middle',
            height=30,
        )
        
        def help_unhandled_input(key):
            close_help()
            return None
        
        loop = urwid.MainLoop(overlay, self.palette, unhandled_input=help_unhandled_input)
        loop.run()
        self.update_status_bar()
    
    def unhandled_input(self, key):
        """handle global keyboard shortcuts"""
        # quit commands
        if key in ('q', 'Q', 'ctrl c'):
            raise urwid.ExitMainLoop()
        
        # help commands  
        if key in ('h', '?'):
            self.show_help_dialog()
            return
        
        # tab navigation
        if key == 'tab':
            self.switch_tab(None, (self.current_tab + 1) % len(self.tab_names))
            return
        if key == 'shift tab':
            self.switch_tab(None, (self.current_tab - 1) % len(self.tab_names))
            return
        if key in ('1', '2', '3', '4', '5', '6'):
            tab_idx = int(key) - 1
            if 0 <= tab_idx < len(self.tab_names):
                self.switch_tab(None, tab_idx)
            return
        
        # search navigation
        if key == 'n':
            self.next_search_result()
            return
        if key == 'p':
            self.prev_search_result()
            return
        
        # tabs that support goto/search
        goto_search_tabs = {self.TAB_MODULES, self.TAB_MEMORY, self.TAB_REGION_EDITOR}
        if self.current_tab in goto_search_tabs:
            if key == 'g':
                self.goto_address()
                return
            if key == '/':
                self.switch_tab(None, self.TAB_SEARCH)
                self.main_frame.set_focus('body')
                return
        
        # region editor specific commands
        if self.current_tab == self.TAB_REGION_EDITOR:
            region_commands = {
                'a': self.select_all_regions,
                'z': self.select_no_regions, 
                'e': self.export_selected
            }
            if key in region_commands:
                region_commands[key](None)
                return
        
        # search tab specific commands
        if self.current_tab == self.TAB_SEARCH and key == 'enter':
            self.perform_search()
            return
    
    
    def run(self):
        """start the TUI"""
        try:
            loop = urwid.MainLoop(self.main_frame, self.palette, unhandled_input=self.unhandled_input)
            loop.run()
        except Exception as e:
            # fallback to text mode if TUI fails
            print(f"TUI failed to start: {e}")
            print("Falling back to text mode...")
            self.dump.print_summary()
            if input("\nShow registers? (y/n): ").lower().startswith('y'):
                self.dump.print_registers()
            if input("\nShow modules? (y/n): ").lower().startswith('y'):
                self.dump.print_modules()


def main():
    parser = argparse.ArgumentParser(
        description="interactive TUI for exploring w1dump process dump files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s dump.w1dump                 # open dump in TUI
  
keyboard shortcuts:
  Tab/Shift-Tab: switch tabs    h: help    q: quit
  1-6: jump to tab             space: toggle checkbox
""")
    
    parser.add_argument("dump_file", help="path to w1dump file")
    
    args = parser.parse_args()
    
    dump_file = Path(args.dump_file)
    if not dump_file.exists():
        print(f"error: dump file not found: {dump_file}")
        sys.exit(1)
    
    try:
        app = W1DumpTUI(dump_file)
        app.run()
    except KeyboardInterrupt:
        print("\nExited by user")
        pass
    except Exception as e:
        import traceback
        print(f"error: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()