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
    
    def __init__(self, dump_file: Path):
        self.dump_file = dump_file
        self.dump = None
        self.selected_regions = set()  # indices of selected regions for export
        self.search_results = []  # list of SearchResult objects
        self.current_search_index = -1
        self.last_search_pattern = ""
        
        # load the dump
        try:
            self.dump = w1dump.load_dump(dump_file)
        except Exception as e:
            raise ValueError(f"failed to load dump: {e}")
        
        # setup urwid palette
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
        
        # tab names
        self.tab_names = ['Overview', 'Registers', 'Modules', 'Memory Map', 'Region Editor', 'Search']
        self.current_tab = 0
        
        # initialize UI components
        self.setup_ui()
    
    def create_table_row(self, columns_data: List[Tuple[str, str]], selectable=False):
        """
        create a table row using urwid Columns
        columns_data: list of (width, text) tuples where width can be 'weight' or int
        """
        column_widgets = []
        for width, text in columns_data:
            if isinstance(width, int):
                column_widgets.append(('fixed', width, urwid.Text(text)))
            else:
                # flexible width
                column_widgets.append(urwid.Text(text))
        
        row = urwid.Columns(column_widgets, dividechars=1)
        if selectable:
            return urwid.AttrMap(row, 'body', 'highlight')
        else:
            return urwid.AttrMap(row, 'body')
    
    def update_status_bar(self, message=None):
        """update status bar with dynamic shortcuts based on current tab"""
        if message:
            self.status_text.set_text(message)
            return
        
        tab_name = self.tab_names[self.current_tab]
        base_shortcuts = "Tab:Switch ?:Help q:Quit"
        
        if tab_name == 'Region Editor':
            shortcuts = f"{base_shortcuts} g:Goto /:Search Space:Toggle a:All z:None e:Export"
        elif tab_name in ['Modules', 'Memory Map']:
            shortcuts = f"{base_shortcuts} g:Goto /:Search"
        elif tab_name == 'Search':
            shortcuts = f"{base_shortcuts} Enter:Search n:Next p:Prev"
        else:
            shortcuts = base_shortcuts
        
        if self.search_results:
            shortcuts += f" | Results: {len(self.search_results)}"
            if self.current_search_index >= 0:
                shortcuts += f" ({self.current_search_index + 1}/{len(self.search_results)})"
        
        self.status_text.set_text(f"File: {self.dump_file.name} | {shortcuts}")
        self.status_bar.set_attr_map({None: 'footer'})
    
    def setup_ui(self):
        """initialize the main UI structure"""
        # create tab bar
        self.tab_buttons = []
        for i, name in enumerate(self.tab_names):
            btn = urwid.Button(f" {name} ", on_press=self.switch_tab, user_data=i)
            if i == 0:
                btn = urwid.AttrMap(btn, 'tab_active', 'tab_active')
            else:
                btn = urwid.AttrMap(btn, 'tab_inactive', 'tab_inactive')
            self.tab_buttons.append(btn)
        
        self.tab_bar = urwid.Columns(self.tab_buttons, dividechars=1)
        
        # create tab contents
        self.tab_contents = [
            self.create_overview_tab(),
            self.create_registers_tab(),
            self.create_modules_tab(),
            self.create_memory_tab(),
            self.create_region_editor_tab(),
            self.create_search_tab(),
        ]
        
        # status bar
        self.status_text = urwid.Text("")
        self.status_bar = urwid.AttrMap(self.status_text, 'footer')
        self.update_status_bar()  # initialize with proper shortcuts
        
        # main layout
        header = urwid.Pile([
            urwid.AttrMap(urwid.Text(f"w1dump TUI - {self.dump.metadata.process_name}", align='center'), 'title'),
            urwid.Divider(),
            self.tab_bar,
            urwid.Divider('─'),
        ])
        
        self.content_area = self.tab_contents[0]
        
        self.main_frame = urwid.Frame(
            body=self.content_area,
            header=header,
            footer=self.status_bar
        )
    
    def create_overview_tab(self):
        """create overview tab content"""
        lines = []
        
        # process information
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
        
        # statistics
        lines.append(urwid.Text(('header', 'Statistics')))
        lines.append(urwid.Text(f"Modules:         {len(self.dump.modules):4d}"))
        lines.append(urwid.Text(f"Memory regions:  {len(self.dump.regions):4d}"))
        
        # memory breakdown
        total_size = sum(r.size for r in self.dump.regions)
        code_size = sum(r.size for r in self.dump.regions if r.is_code)
        data_size = sum(r.size for r in self.dump.regions if r.is_data)
        stack_size = sum(r.size for r in self.dump.regions if r.is_stack)
        anon_size = sum(r.size for r in self.dump.regions if r.is_anonymous)
        
        def format_size(size):
            for unit in ["B", "KB", "MB", "GB"]:
                if size < 1024.0:
                    return f"{size:6.1f} {unit}"
                size /= 1024.0
            return f"{size:6.1f} TB"
        
        lines.append(urwid.Divider())
        lines.append(urwid.Text(('header', 'Memory Breakdown')))
        lines.append(urwid.Text(f"Total:      {format_size(total_size):>12} ({total_size:,} bytes)"))
        lines.append(urwid.Text(f"Code:       {format_size(code_size):>12} ({code_size:,} bytes)"))
        lines.append(urwid.Text(f"Data:       {format_size(data_size):>12} ({data_size:,} bytes)"))
        lines.append(urwid.Text(f"Stack:      {format_size(stack_size):>12} ({stack_size:,} bytes)"))
        lines.append(urwid.Text(f"Anonymous:  {format_size(anon_size):>12} ({anon_size:,} bytes)"))
        
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
        header_widgets = []
        for width_spec in header_cols:
            if len(width_spec) == 2:
                width, text = width_spec
                if isinstance(width, int):
                    header_widgets.append(('fixed', width, urwid.Text(('header', text))))
                else:
                    header_widgets.append((width[0], width[1], urwid.Text(('header', text))))
            else:
                width_type, width_val, text = width_spec
                header_widgets.append((width_type, width_val, urwid.Text(('header', text))))
        
        header_row = urwid.Columns(header_widgets, dividechars=1)
        lines.append(urwid.AttrMap(header_row, 'header'))
        lines.append(urwid.Divider('─'))
        
        # sort all modules by address
        all_modules = sorted(self.dump.modules, key=lambda m: m.base_address)
        
        for module in all_modules:
            flags = []
            if module.is_system_library:
                flags.append("SYS")
            flag_str = ",".join(flags) if flags else ""
            
            # format size
            size_str = f"{module.size:,}"
            if module.size >= 1024*1024:
                size_str = f"{module.size/(1024*1024):.1f}M"
            elif module.size >= 1024:
                size_str = f"{module.size/1024:.1f}K"
            
            # shorten module type - only E and L as requested
            type_short = ""
            if module.type == "main_executable":
                type_short = "E"
            else:  # everything else is L (library)
                type_short = "L"
            
            row_data = [
                (18, f"{module.base_address:016x}"),
                (12, size_str),
                ('weight', 1, module.name),
                (4, type_short),
                (8, flag_str)
            ]
            
            row_widgets = []
            for width_spec in row_data:
                if len(width_spec) == 2:
                    width, text = width_spec
                    if isinstance(width, int):
                        row_widgets.append(('fixed', width, urwid.Text(text)))
                    else:
                        row_widgets.append(urwid.Text(text))
                else:
                    width_type, width_val, text = width_spec
                    row_widgets.append((width_type, width_val, urwid.Text(text)))
            
            row = urwid.Columns(row_widgets, dividechars=1)
            lines.append(urwid.AttrMap(row, 'body', 'highlight'))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker(lines))
    
    def create_memory_tab(self):
        """create memory map tab content"""
        lines = []
        
        # table header
        header_widgets = [
            ('fixed', 18, urwid.Text(('header', "Start"))),
            ('fixed', 18, urwid.Text(('header', "End"))),
            ('fixed', 5, urwid.Text(('header', "Perms"))),
            ('fixed', 12, urwid.Text(('header', "Size"))),
            ('weight', 1, urwid.Text(('header', "Module"))),
            ('fixed', 20, urwid.Text(('header', "Flags")))
        ]
        
        header_row = urwid.Columns(header_widgets, dividechars=1)
        lines.append(urwid.AttrMap(header_row, 'header'))
        lines.append(urwid.Divider('─'))
        
        # show ALL regions (no truncation)
        regions = sorted(self.dump.regions, key=lambda r: r.start)
        
        for region in regions:
            flags = []
            if region.is_stack:
                flags.append("STACK")
            if region.is_code:
                flags.append("CODE")
            if region.is_data:
                flags.append("DATA")
            if region.is_anonymous:
                flags.append("ANON")
            if region.data:
                flags.append("DUMPED")
            
            flag_str = ",".join(flags)
            
            # format size
            size_str = f"{region.size:,}"
            if region.size >= 1024*1024*1024:
                size_str = f"{region.size/(1024*1024*1024):.1f}G"
            elif region.size >= 1024*1024:
                size_str = f"{region.size/(1024*1024):.1f}M"
            elif region.size >= 1024:
                size_str = f"{region.size/1024:.1f}K"
            
            row_widgets = [
                ('fixed', 18, urwid.Text(f"{region.start:016x}")),
                ('fixed', 18, urwid.Text(f"{region.end:016x}")),
                ('fixed', 5, urwid.Text(region.perms_str)),
                ('fixed', 12, urwid.Text(size_str)),
                ('weight', 1, urwid.Text(region.module_name or "")),
                ('fixed', 20, urwid.Text(flag_str))
            ]
            
            row = urwid.Columns(row_widgets, dividechars=1)
            lines.append(urwid.AttrMap(row, 'body', 'highlight'))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker(lines))
    
    def create_region_editor_tab(self):
        """create region editor tab content"""
        lines = []
        
        # control buttons
        select_all_btn = urwid.Button("All", on_press=self.select_all_regions)
        select_none_btn = urwid.Button("None", on_press=self.select_no_regions)
        export_btn = urwid.Button("Export", on_press=self.export_selected)
        
        buttons = urwid.Columns([
            urwid.Text(('header', 'Region Editor - Select regions to export:')),
            ('fixed', 8, urwid.AttrMap(select_all_btn, 'body')),
            ('fixed', 9, urwid.AttrMap(select_none_btn, 'body')),
            ('fixed', 11, urwid.AttrMap(export_btn, 'success')),
        ], dividechars=2)
        
        lines.append(buttons)
        lines.append(urwid.Divider('─'))
        
        # table header
        header_row = urwid.Columns([
            ('fixed', 4, urwid.Text(('header', "Sel"))),
            ('fixed', 18, urwid.Text(('header', "Start"))),
            ('fixed', 18, urwid.Text(('header', "End"))),
            ('fixed', 6, urwid.Text(('header', "Perms"))),
            ('fixed', 12, urwid.Text(('header', "Size"))),
            ('weight', 1, urwid.Text(('header', "Module"))),
            ('fixed', 15, urwid.Text(('header', "Flags")))
        ], dividechars=1)
        lines.append(urwid.AttrMap(header_row, 'header'))
        lines.append(urwid.Divider('─'))
        
        # region checkboxes for ALL regions (no truncation)
        self.region_checkboxes = []
        regions = sorted(self.dump.regions, key=lambda r: r.start)
        
        for i, region in enumerate(regions):
            flags = []
            if region.is_stack:
                flags.append("STACK")
            if region.is_code:
                flags.append("CODE")
            if region.is_data:
                flags.append("DATA")
            if region.is_anonymous:
                flags.append("ANON")
            if region.data:
                flags.append("DUMP")
            
            flag_str = ",".join(flags)
            
            # format size
            size_str = f"{region.size:,}"
            if region.size >= 1024*1024*1024:
                size_str = f"{region.size/(1024*1024*1024):.1f}G"
            elif region.size >= 1024*1024:
                size_str = f"{region.size/(1024*1024):.1f}M"
            elif region.size >= 1024:
                size_str = f"{region.size/1024:.1f}K"
            
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
        if self.current_tab == 5:  # search tab
            self.tab_contents[5] = self.create_search_tab()
            self.main_frame.body = self.tab_contents[5]
    
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
                    # switch to modules tab and find the module
                    self.switch_tab(None, 2)
                    # TODO: highlight the specific module in the list
                    self.show_message(f"Found address in module: {module.name}", "success")
                elif region:
                    # switch to memory map tab
                    self.switch_tab(None, 3)
                    # TODO: highlight the specific region in the list
                    self.show_message(f"Found address in region: {region.start:016x}-{region.end:016x}", "success")
            else:
                self.show_message(f"Address {address:016x} not found in dump", "error")
        
        dialog = GotoDialog(on_address_entered)
        
        # create wrapper that forwards keypresses to dialog
        class GotoWrapper(urwid.WidgetWrap):
            def keypress(self, size, key):
                return dialog.keypress(size, key)
        
        wrapper = GotoWrapper(dialog.widget)
        overlay = urwid.Overlay(
            wrapper,
            self.main_frame,
            align='center',
            width=30,
            valign='middle',
            height=5,
        )
        
        loop = urwid.MainLoop(overlay, self.palette)
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
        
        # create a wrapper that handles keypresses
        class HelpWrapper(urwid.WidgetWrap):
            def keypress(self, size, key):
                close_help()
                return None
        
        wrapper = HelpWrapper(help_dialog.widget)
        overlay = urwid.Overlay(
            wrapper,
            self.main_frame,
            align='center',
            width=60,
            valign='middle',
            height=30,
        )
        
        loop = urwid.MainLoop(overlay, self.palette)
        loop.run()
        self.update_status_bar()  # restore status bar
    
    def unhandled_input(self, key):
        """handle global keyboard shortcuts"""
        if key in ('q', 'Q', 'ctrl c'):
            raise urwid.ExitMainLoop()
        elif key in ('h', '?'):
            self.show_help_dialog()
        elif key == 'tab':
            # switch to next tab
            self.switch_tab(None, (self.current_tab + 1) % len(self.tab_names))
        elif key == 'shift tab':
            # switch to previous tab
            self.switch_tab(None, (self.current_tab - 1) % len(self.tab_names))
        elif key in ('1', '2', '3', '4', '5', '6'):
            # direct tab switch
            tab_idx = int(key) - 1
            if 0 <= tab_idx < len(self.tab_names):
                self.switch_tab(None, tab_idx)
        elif key == 'g' and self.tab_names[self.current_tab] in ['Modules', 'Memory Map', 'Region Editor']:
            # goto address
            self.goto_address()
        elif key == '/' and self.tab_names[self.current_tab] in ['Modules', 'Memory Map', 'Region Editor']:
            # switch to search tab and focus input
            self.switch_tab(None, 5)
            self.main_frame.set_focus('body')
        elif key == 'n':
            # next search result
            self.next_search_result()
        elif key == 'p':
            # previous search result
            self.prev_search_result()
        elif key == 'a' and self.tab_names[self.current_tab] == 'Region Editor':
            # select all regions
            self.select_all_regions(None)
        elif key == 'z' and self.tab_names[self.current_tab] == 'Region Editor':
            # select no regions
            self.select_no_regions(None)
        elif key == 'e' and self.tab_names[self.current_tab] == 'Region Editor':
            # export selected regions
            self.export_selected(None)
        elif key == 'enter' and self.tab_names[self.current_tab] == 'Search':
            # perform search
            self.perform_search()
    
    
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