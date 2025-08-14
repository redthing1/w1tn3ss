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
from pathlib import Path
from typing import List, Optional, Tuple, Any

import urwid
import w1dump


class W1DumpTUI:
    """main TUI application class"""
    
    def __init__(self, dump_file: Path):
        self.dump_file = dump_file
        self.dump = None
        self.selected_regions = set()  # indices of selected regions for export
        
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
        self.status_text = urwid.Text(f"File: {self.dump_file.name} | Press 'h' for help, 'q' to quit")
        self.status_bar = urwid.AttrMap(self.status_text, 'footer')
        
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
        
        lines.append(urwid.Text(('header', f'Loaded Modules ({len(self.dump.modules)})')))
        lines.append(urwid.Divider())
        
        # group by type
        by_type = {}
        for module in self.dump.modules:
            by_type.setdefault(module.type, []).append(module)
        
        for mod_type, modules in sorted(by_type.items()):
            if modules:
                lines.append(urwid.Text(('header', f'{mod_type}:')))
                for module in sorted(modules, key=lambda m: m.base_address):
                    system = " [system]" if module.is_system_library else ""
                    text = f"  {module.base_address:016x}  {module.size:10,} bytes  {module.name}{system}"
                    lines.append(urwid.Text(text))
                lines.append(urwid.Divider())
        
        return urwid.ListBox(urwid.SimpleFocusListWalker([urwid.AttrMap(line, 'body') for line in lines]))
    
    def create_memory_tab(self):
        """create memory map tab content"""
        lines = []
        
        lines.append(urwid.Text(('header', f'Memory Map ({len(self.dump.regions)} regions)')))
        lines.append(urwid.Divider())
        
        regions = sorted(self.dump.regions, key=lambda r: r.start)
        
        for i, region in enumerate(regions[:100]):  # limit to first 100 for performance
            flags = []
            if region.is_stack:
                flags.append("STACK")
            if region.is_code:
                flags.append("CODE")
            if region.is_data:
                flags.append("DATA")
            if region.is_anonymous:
                flags.append("ANON")
            
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            module_str = f" ({region.module_name})" if region.module_name else ""
            
            text = f"{region.start:016x}-{region.end:016x} {region.perms_str} {region.size:10} bytes{module_str}{flag_str}"
            lines.append(urwid.Text(text))
        
        if len(regions) > 100:
            lines.append(urwid.Text(('error', f'... {len(regions) - 100} more regions (showing first 100)')))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker([urwid.AttrMap(line, 'body') for line in lines]))
    
    def create_region_editor_tab(self):
        """create region editor tab content"""
        lines = []
        
        lines.append(urwid.Text(('header', f'Region Editor - Select regions to export')))
        lines.append(urwid.Divider())
        
        # control buttons
        select_all_btn = urwid.Button("Select All", on_press=self.select_all_regions)
        select_none_btn = urwid.Button("Select None", on_press=self.select_no_regions)
        export_btn = urwid.Button("Export Selected", on_press=self.export_selected)
        
        buttons = urwid.Columns([
            ('fixed', 12, urwid.AttrMap(select_all_btn, 'body')),
            ('fixed', 14, urwid.AttrMap(select_none_btn, 'body')),
            ('fixed', 16, urwid.AttrMap(export_btn, 'success')),
        ], dividechars=2)
        
        lines.append(buttons)
        lines.append(urwid.Divider())
        
        # region checkboxes (limit for performance)
        self.region_checkboxes = []
        for i, region in enumerate(self.dump.regions[:100]):  # limit to first 100
            checkbox = urwid.CheckBox(f"{region.start:016x}-{region.end:016x} {region.perms_str} {region.size:10} bytes", 
                                    state=True, on_state_change=self.region_checkbox_changed, user_data=i)
            self.region_checkboxes.append(checkbox)
            lines.append(urwid.AttrMap(checkbox, 'checkbox'))
        
        if len(self.dump.regions) > 100:
            lines.append(urwid.Text(('error', f'... {len(self.dump.regions) - 100} more regions (showing first 100)')))
        
        # initialize selected regions to all
        self.selected_regions = set(range(min(100, len(self.dump.regions))))
        
        return urwid.ListBox(urwid.SimpleFocusListWalker(lines))
    
    def create_search_tab(self):
        """create search tab content"""
        lines = []
        
        lines.append(urwid.Text(('header', 'Search')))
        lines.append(urwid.Text('Search functionality - to be implemented'))
        
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
    
    def show_message(self, message, style='body'):
        """show a message in the status bar"""
        self.status_text.set_text(message)
        self.status_bar.set_attr_map({None: style})
    
    def unhandled_input(self, key):
        """handle global keyboard shortcuts"""
        if key in ('q', 'Q'):
            raise urwid.ExitMainLoop()
        elif key == 'h':
            self.show_help()
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
    
    def show_help(self):
        """show help overlay"""
        help_text = [
            "w1dump TUI - Keyboard Shortcuts",
            "",
            "Navigation:",
            "  Tab/Shift-Tab    - Switch between tabs",
            "  1-6              - Jump directly to tab",
            "  j/k or ↑/↓       - Navigate lists",
            "  Enter            - Activate selection",
            "",
            "Region Editor:",
            "  Space            - Toggle checkbox",
            "",
            "Global:",
            "  h                - Show this help",
            "  q                - Quit",
            "",
            "Press any key to close this help..."
        ]
        
        help_widget = urwid.ListBox(urwid.SimpleFocusListWalker([
            urwid.Text(line) for line in help_text
        ]))
        
        overlay = urwid.Overlay(
            urwid.LineBox(urwid.Padding(help_widget, align='center', width=50)),
            self.main_frame,
            align='center',
            width=52,
            valign='middle',
            height=len(help_text) + 2,
        )
        
        loop = urwid.MainLoop(overlay, self.palette)
        loop.run()
    
    def run(self):
        """start the TUI"""
        loop = urwid.MainLoop(self.main_frame, self.palette, unhandled_input=self.unhandled_input)
        loop.run()


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
        pass
    except Exception as e:
        print(f"error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()