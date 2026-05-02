import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import re
import copy
from datetime import datetime
import tkinter.font as tkfont
from tkinter import simpledialog

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        self.delay_id = None
        self.widget.bind('<Enter>', self.on_enter)
        self.widget.bind('<Leave>', self.hide_tip)

    def on_enter(self, event=None):
        if self.delay_id:
            self.widget.after_cancel(self.delay_id)
        self.delay_id = self.widget.after(500, self.show_tip)

    def show_tip(self, event=None):
        self.delay_id = None
        if self.tip_window:
            return
        
        try:
            x, y, _, _ = self.widget.bbox("insert")
        except:
            x, y = 0, 0
        
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25

        self.tip_window = tk.Toplevel(self.widget)
        self.tip_window.wm_overrideredirect(True)
        self.tip_window.wm_geometry(f"+{x}+{y}")
        self.tip_window.configure(bg=MODERN_COLORS['bg_tertiary'])
        self.tip_window.attributes('-topmost', True)

        label = tk.Label(self.tip_window, text=self.text, justify=tk.LEFT,
                         background=MODERN_COLORS['bg_tertiary'], foreground=MODERN_COLORS['text_primary'], 
                         relief=tk.SOLID, borderwidth=1,
                         font=("Microsoft YaHei", 10), padx=8, pady=5)
        label.pack()

    def hide_tip(self, event=None):
        if self.delay_id:
            self.widget.after_cancel(self.delay_id)
            self.delay_id = None
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

MODERN_COLORS_DARK = {
    'bg_primary': '#1e1e1e',
    'bg_secondary': '#252526',
    'bg_tertiary': '#2d2d30',
    'bg_hover': '#3e3e42',
    'bg_active': '#505050',
    'text_primary': '#e4e4e4',
    'text_secondary': '#a0a0a0',
    'accent_blue': '#569cd6',
    'accent_blue_hover': '#67afec',
    'accent_green': '#4ec9b0',
    'accent_orange': '#ce9178',
    'accent_yellow': '#dcdcaa',
    'accent_purple': '#c586c0',
    'border': '#3c3c3c',
    'highlight': '#264f78',
    'selection': '#094771',
    'error': '#f14c4c',
    'success': '#89d185',
    'warning': '#cca700',
}

MODERN_COLORS_LIGHT = {
    'bg_primary': '#ffffff',
    'bg_secondary': '#f5f5f5',
    'bg_tertiary': '#e8e8e8',
    'bg_hover': '#d3d3d3',
    'bg_active': '#b8b8b8',
    'text_primary': '#1e1e1e',
    'text_secondary': '#666666',
    'accent_blue': '#007acc',
    'accent_blue_hover': '#1a8ad6',
    'accent_green': '#00b894',
    'accent_orange': '#e17055',
    'accent_yellow': '#fdcb6e',
    'accent_purple': '#a29bfe',
    'border': '#d0d0d0',
    'highlight': '#7eb8da',
    'selection': '#87ceeb',
    'error': '#dc3545',
    'success': '#28a745',
    'warning': '#ffc107',
}

MODERN_COLORS = MODERN_COLORS_DARK
CURRENT_THEME = 'dark'

STYLE_CONFIG = {
    'frame_padding': 8,
    'section_spacing': 10,
    'button_padding': 6,
    'entry_padding': 5,
    'border_radius': 4,
    'shadow_depth': 2,
}

class ModernLabelFrame(tk.Frame):
    def __init__(self, master, text="", bg=None, fg=MODERN_COLORS['accent_green'],
                 font=("Microsoft YaHei", 10, "bold"), **kwargs):
        bg = bg or MODERN_COLORS['bg_primary']
        super().__init__(master, bg=MODERN_COLORS['bg_secondary'], **kwargs)

        header_frame = tk.Frame(self, bg=MODERN_COLORS['bg_secondary'], pady=3)
        header_frame.pack(side=tk.TOP, fill=tk.X)

        label = tk.Label(header_frame, text=text, bg=MODERN_COLORS['bg_secondary'],
                        fg=fg, font=font, padx=10)
        label.pack(side=tk.LEFT)

        content_frame = tk.Frame(self, bg=MODERN_COLORS['bg_secondary'], padx=5, pady=5)
        content_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self._content_frame = content_frame

    def pack(self, **kwargs):
        super().pack(**kwargs)

    def grid(self, **kwargs):
        super().grid(**kwargs)

    def grid_columnconfigure(self, index, **kwargs):
        self._content_frame.grid_columnconfigure(index, **kwargs)

    def grid_rowconfigure(self, index, **kwargs):
        self._content_frame.grid_rowconfigure(index, **kwargs)

class ModernText(tk.Text):
    def __init__(self, master, **kwargs):
        super().__init__(master,
                        bg=MODERN_COLORS['bg_primary'],
                        fg=MODERN_COLORS['text_primary'],
                        insertbackground=MODERN_COLORS['accent_green'],
                        selectbackground=MODERN_COLORS['selection'],
                        selectforeground='#ffffff',
                        relief=tk.FLAT,
                        borderwidth=2,
                        font=("Microsoft YaHei", 10),
                        **kwargs)

class ModernEntry(ttk.Entry):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.configure(style="ModernEntry.TEntry")

class ModernButton(tk.Button):
    def __init__(self, master, text="", command=None, width=10, **kwargs):
        super().__init__(master,
                        text=text,
                        command=command,
                        width=width,
                        bg=MODERN_COLORS['accent_blue'],
                        fg='#ffffff',
                        activebackground=MODERN_COLORS['accent_blue_hover'],
                        activeforeground='#ffffff',
                        relief=tk.FLAT,
                        borderwidth=0,
                        font=("Microsoft YaHei", 10, "bold"),
                        cursor="hand2",
                        padx=12,
                        pady=6,
                        **kwargs)

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, event):
        self.configure(bg=MODERN_COLORS['accent_blue_hover'])

    def _on_leave(self, event):
        self.configure(bg=MODERN_COLORS['accent_blue'])

class BinaryEditorApp:
    def __init__(self, root, config=None):
        self.root = root
        self.root.title("汉化辅助编辑器 v8.0")
        self.root.configure(bg=MODERN_COLORS['bg_primary'])

        if config is None:
            config = {}
        
        try:
            from ctypes import windll
            self.dpi = windll.user32.GetDpiForWindow(root.winfo_id())
            self.scale_factor = self.dpi / 96.0
        except:
            self.scale_factor = 1.0

        self.base_font_size = int(11 * self.scale_factor)
        self.zoom_level = 1.0
        self.zoom_factors = [0.9, 1.0]

        initial_width = int(1400 * self.scale_factor)
        initial_height = int(1000 * self.scale_factor * self.zoom_level)
        self.root.geometry(f"{initial_width}x{initial_height}")
        self.root.minsize(int(900 * self.scale_factor), int(650 * self.scale_factor))

        self._setup_modern_style()

        self.max_input_length = 500
        self.extended_threshold = 200
        self.max_extended_lines = 10
        self.initial_height = 3

        self.file_path = ""
        self.file_data = bytearray()
        self.original_data = None
        self.history = []
        self.history_index = 0
        self.max_history_items = 0
        self.mapping_file_path = None
        self.current_mapping_data = {}
        self.pending_changes = False
        self.current_scan_mode = None
        self.current_segments = []
        self.current_matches = []
        self.current_match_index = -1
        self.current_find_text = ""
        self.find_mode = "text"
        self.replace_buttons_disabled = False
        self.replace_buttons_clicked = False

        self.input_type_options = ['字符串', '十六进制']
        self.input_type_var = tk.StringVar(value=config.get('input_type', "字符串"))
        self.replace_type_var = tk.StringVar(value="字符串")

        self.encoding_options = [
            'utf-8', 'gbk', 'utf-16le', 'utf-16be',
            'shift_jis', 'euc-jp', 'big5', 'gb2312',
            'iso-8859-1', 'utf-7', 'ascii', 'latin1'
        ]
        self.encoding_var = tk.StringVar(value=config.get('encoding', "utf-8"))

        self.string_entries = []
        self.current_string_index = -1
        self.sidebar_expanded = True
        self.scan_mode_var = tk.StringVar(value=config.get('scan_mode', "ansi"))
        self.menubar = tk.Menu(self.root)
        self.common_symbols = set(' \'"!?.,:;()[]{}<>-+=*/\\&%$#@~`|')
        self.word_pattern = re.compile(r'^[A-Za-z][a-z]{2,}(?:[-\'\.][A-Za-z][a-z]*)*$')
        self.common_abbr = ['ok', 'hi', 'bye', 'yes', 'no', 'id', 'vs', 'am', 'pm']
        self.create_widgets()
        self.setup_drag_and_drop()
        self.update_status("就绪 - 请打开文件或拖拽文件到窗口")

    def _setup_modern_style(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure(".", background=MODERN_COLORS['bg_primary'])
        style.configure(".", foreground=MODERN_COLORS['text_primary'])
        style.configure("TFrame", background=MODERN_COLORS['bg_primary'])
        style.configure("TLabelframe", background=MODERN_COLORS['bg_secondary'], foreground=MODERN_COLORS['accent_green'], bordercolor=MODERN_COLORS['border'])
        style.configure("TLabelframe.Label", background=MODERN_COLORS['bg_secondary'], foreground=MODERN_COLORS['accent_green'], font=("Microsoft YaHei", 10, "bold"))

        style.configure("TLabel", background=MODERN_COLORS['bg_primary'], foreground=MODERN_COLORS['text_primary'], font=("Microsoft YaHei", 10))
        style.configure("TButton", background=MODERN_COLORS['bg_tertiary'], foreground=MODERN_COLORS['text_primary'], bordercolor=MODERN_COLORS['border'], lightcolor=MODERN_COLORS['bg_hover'], darkcolor=MODERN_COLORS['bg_tertiary'], relief="flat", font=("Microsoft YaHei", 10))
        style.map("TButton", background=[('active', MODERN_COLORS['accent_blue']), ('pressed', MODERN_COLORS['bg_active'])], foreground=[('active', '#ffffff')])

        style.configure("TEntry", fieldbackground=MODERN_COLORS['bg_secondary'], foreground=MODERN_COLORS['text_primary'], bordercolor=MODERN_COLORS['border'], lightcolor=MODERN_COLORS['bg_hover'], darkcolor=MODERN_COLORS['bg_tertiary'])
        style.configure("TCombobox", fieldbackground=MODERN_COLORS['bg_secondary'], background=MODERN_COLORS['bg_tertiary'], foreground=MODERN_COLORS['text_primary'], bordercolor=MODERN_COLORS['border'], arrowcolor=MODERN_COLORS['text_primary'])
        style.map("TCombobox", fieldbackground=[('readonly', MODERN_COLORS['bg_secondary'])], selectbackground=[('readonly', MODERN_COLORS['accent_blue'])], selectforeground=[('readonly', '#ffffff')])

        style.configure("TScrollbar", background=MODERN_COLORS['bg_tertiary'], troughcolor=MODERN_COLORS['bg_secondary'], bordercolor=MODERN_COLORS['border'], arrowcolor=MODERN_COLORS['text_secondary'])
        style.map("TScrollbar", background=[('active', MODERN_COLORS['bg_active']), ('pressed', MODERN_COLORS['accent_blue'])])

        style.configure("Treeview", background=MODERN_COLORS['bg_secondary'], fieldbackground=MODERN_COLORS['bg_secondary'], foreground=MODERN_COLORS['text_primary'], bordercolor=MODERN_COLORS['border'], rowheight=28, font=("Microsoft YaHei", 10))
        style.configure("Treeview.Heading", background=MODERN_COLORS['bg_tertiary'], foreground=MODERN_COLORS['accent_yellow'], bordercolor=MODERN_COLORS['border'], font=("Microsoft YaHei", 10, "bold"))
        style.map("Treeview", background=[('selected', MODERN_COLORS['selection'])], foreground=[('selected', '#ffffff')])
        style.map("Treeview.Heading", background=[('active', MODERN_COLORS['bg_active'])])

    def add_tooltip(self, widget, text):
        ToolTip(widget, text)

    def on_window_resize(self, event=None):
        if hasattr(self, 'hex_viewer'):
            self.update_hex_viewer_height()
        if hasattr(self, 'sidebar_frame') and self.sidebar_expanded:
            pass
    def _is_likely_valid_text(self, text):
        if not text or len(text) < 2:
            return False
        digit_count = sum(1 for c in text if c.isdigit())
        if digit_count > 1:
            if not (re.search(r'%\d+', text) or re.search(r'\d+\.\d+', text)):
                if re.search(r'[A-Za-z]\d[A-Za-z]\d', text) or re.search(r'\d[A-Za-z]\d[A-Za-z]', text):
                    return False
                if re.match(r'^\d+[A-Za-z]', text) and ' ' not in text[:5]:
                    return False
        letters = sum(1 for c in text if c.isalpha())
        if letters < len(text) * 0.3:
            return False
        if re.match(r'^[0-9A-Fa-f]{8,}$', text):
            return False
        special_chars = re.findall(r'[<>?^`@\\\[\]{}|;:,=+*&%$#!~]', text)
        if len(special_chars) > len(text) * 0.2:
            return False
        if len(text) >= 4:
            vowels = set('aeiouAEIOU')
            vowel_count = sum(1 for c in text if c in vowels)
            consonant_count = sum(1 for c in text if c.isalpha() and c not in vowels)
            if consonant_count > 0 and vowel_count == 0 and len(text) > 10:
                return False
            illegal_patterns = [
                r'^[A-Za-z]\d[A-Za-z]{2,}$',
                r'^\d[A-Za-z]\d[A-Za-z]+$',
                r'^[A-Za-z]{2,}\d[A-Za-z]+$',
            ]
            for pattern in illegal_patterns:
                if re.match(pattern, text):
                    return False
        words = re.findall(r'[A-Za-z]{3,}', text)
        if len(words) >= 1:
            return True
        if any(c in ' .,:;!?()' for c in text):
            return True
        return False

    def _is_basic_english(self, text):
        if not text or len(text) < 2:
            return False
        digit_count = sum(1 for c in text if c.isdigit())
        if digit_count > 1:
            if not (re.search(r'%\d+', text) or re.search(r'\d+\.\d+', text)):
                if re.search(r'[A-Za-z]\d[A-Za-z]\d', text):
                    return False
        letters = sum(1 for c in text if c.isalpha())
        if letters < 2:
            return False
        if re.match(r'^[0-9]+$', text) or re.match(r'^[0-9A-Fa-f]{8,}$', text):
            return False
        if len(text) >= 4:
            vowels = set('aeiouAEIOU')
            vowel_count = sum(1 for c in text if c in vowels)
            if vowel_count == 0 and len(text) > 8:
                return False
            special_chars = re.findall(r'[\\\/@#$%^&*()\[\]{}=+|<>?~`;:]', text)
            if len(special_chars) > len(text) * 0.15:
                return False
        has_spaces = ' ' in text
        has_punctuation = any(c in '.,:;!?()' for c in text)
        if has_spaces or has_punctuation:
            return True
        if letters >= len(text) * 0.6:
            return True
        return False

    def find_strings_simple(self, min_length=2):
        segments = []
        data_length = len(self.file_data)
        delimiters = {0x00, 0x09, 0x0A, 0x0D}
        current_pos = 0
        while current_pos < data_length:
            while current_pos < data_length and self.file_data[current_pos] in delimiters:
                current_pos += 1
            if current_pos >= data_length:
                break
            segment_start = current_pos
            segment_bytes = bytearray()
            while current_pos < data_length and self.file_data[current_pos] not in delimiters:
                segment_bytes.append(self.file_data[current_pos])
                current_pos += 1
            if len(segment_bytes) >= min_length:
                try:
                    text = segment_bytes.decode('ascii')
                    if self._is_basic_english(text):
                        if len(text) > 200:
                            continue
                        is_printable = all(32 <= ord(c) <= 126 for c in text)
                        if not is_printable:
                            continue
                        hex_chars = sum(1 for c in text if c in '0123456789ABCDEFabcdef')
                        if hex_chars / len(text) > 0.7:
                            continue
                        letters = sum(1 for c in text if c.isalpha())
                        letter_ratio = letters / len(text) if len(text) > 0 else 0
                        if letter_ratio < 0.3:
                            continue
                        vowels = set('aeiouAEIOU')
                        vowel_count = sum(1 for c in text if c in vowels)
                        if vowel_count == 0 and len(text) > 8:
                            continue
                        special_chars = re.findall(r'[\\\/@#$%^&*()\[\]{}=+|<>?~`;:]', text)
                        if len(special_chars) > len(text) * 0.15:
                            continue
                        segments.append({
                            "start": segment_start,
                            "end": current_pos - 1,
                            "length": len(segment_bytes),
                            "text": text,
                            "bytes": segment_bytes
                        })
                except:
                    pass
        return segments

    def _extract_utf16_with_gaps(self, segments, data_length):
        i = 0
        while i < data_length - 1:
            if self.file_data[i] == 0x00 and i + 1 < data_length and 32 <= self.file_data[i+1] <= 126:
                start = i
                bytes_collected = bytearray()
                valid_count = 0
                while i < data_length - 1:
                    if self.file_data[i] == 0x00 and 32 <= self.file_data[i+1] <= 126:
                        bytes_collected.extend([self.file_data[i+1], self.file_data[i]])
                        valid_count += 1
                        i += 2
                    elif self.file_data[i] == 0x00 and i + 2 < data_length and self.file_data[i+2] == 0x00:
                        bytes_collected.extend([0x00, 0x00])
                        i += 2
                    else:
                        break
                if valid_count >= 2:
                    try:
                        text = bytes_collected.decode('utf-16le').rstrip('\x00')
                        if text and self._is_likely_valid_text(text):
                            segments.append({
                                "start": start,
                                "end": i - 1,
                                "length": len(bytes_collected),
                                "text": text,
                                "bytes": bytes_collected,
                                "encoding": "utf-16le"
                            })
                    except:
                        pass
            else:
                i += 1

    def setup_drag_and_drop(self):
        try:
            import tkinterdnd2
            DND_FILES = tkinterdnd2.DND_FILES
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.on_drop_advanced)
            print("使用tkinterdnd2拖拽支持")
        except Exception as e:
            print(f"拖拽功能初始化失败:{e}")

    def on_drop_advanced(self, event):
        try:
            file_path = event.data.strip('{}')
            self.process_dropped_file(file_path)
        except Exception as e:
            messagebox.showerror("错误", f"处理拖拽文件时出错:{str(e)}")

    def process_dropped_file(self, file_path):
        if os.path.isfile(file_path):
            self.open_file_with_path(file_path)
        else:
            messagebox.showerror("错误", "请拖拽有效的文件")

    def find_unicode_strings(self, min_length=2, encoding_type="le"):
        segments = []
        data_length = len(self.file_data)
        ansi_occupied = set()

        def mark_ansi_segments():
            i = 0
            while i < data_length:
                if 32 <= self.file_data[i] <= 126 and (i+1 >= data_length or self.file_data[i+1] != 0x00):
                    start = i
                    while i < data_length and 32 <= self.file_data[i] <= 126:
                        i += 1
                    ansi_length = i - start
                    if ansi_length >= 3:
                        ansi_text = bytes(self.file_data[start:i]).decode('ascii', errors='ignore')
                        if self._is_likely_valid_text(ansi_text):
                            for pos in range(start, i):
                                ansi_occupied.add(pos)
                else:
                    i += 1

        mark_ansi_segments()

        if encoding_type == "le":
            i = 0
            while i < data_length - 1:
                if i % 2 != 0 or i in ansi_occupied or (i+1) in ansi_occupied:
                    i += 1
                    continue
                if self.file_data[i+1] != 0x00 or not (32 <= self.file_data[i] <= 126):
                    i += 1
                    continue
                conflict = False
                if i > 0:
                    ansi_end = i - 1
                    while ansi_end >= max(0, i-20):
                        if self.file_data[ansi_end] == 0x00:
                            ansi_start_candidate = ansi_end + 1
                            ansi_len_candidate = i - ansi_start_candidate
                            if ansi_len_candidate >= 3:
                                ansi_chars = self.file_data[ansi_start_candidate:i]
                                printable_rate = sum(1 for b in ansi_chars if 32 <= b <= 126) / ansi_len_candidate
                                if printable_rate >= 0.8:
                                    conflict = True
                                    break
                        ansi_end -= 1
                if conflict:
                    i += 1
                    continue
                start = i
                bytes_collected = bytearray()
                unicode_count = 0
                valid_continuous = True

                while i < data_length - 1 and valid_continuous:
                    if i in ansi_occupied or (i+1) in ansi_occupied:
                        break
                    if self.file_data[i+1] == 0x00 and (32 <= self.file_data[i] <= 126):
                        bytes_collected.extend([self.file_data[i], self.file_data[i+1]])
                        unicode_count += 1
                        i += 2
                        if i < data_length - 1:
                            if i % 2 != 0:
                                valid_continuous = False
                            elif not (self.file_data[i+1] == 0x00 and (32 <= self.file_data[i] <= 126)):
                                valid_continuous = False
                    else:
                        valid_continuous = False
                if unicode_count >= min_length:
                    try:
                        text = bytes_collected.decode('utf-16le').rstrip('\x00')
                        if text and self._is_likely_valid_text(text) and len(text) == unicode_count:
                            segments.append({
                                "start": start,
                                "end": i - 1,
                                "length": len(bytes_collected),
                                "text": text,
                                "bytes": bytes_collected,
                                "encoding": "utf-16le"
                            })
                    except:
                        pass
                else:
                    i = start + 1

        else:
            i = 0
            while i < data_length - 1:
                if i % 2 != 0 or i in ansi_occupied or (i+1) in ansi_occupied:
                    i += 1
                    continue
                if self.file_data[i] != 0x00 or not (32 <= self.file_data[i+1] <= 126):
                    i += 1
                    continue
                conflict = False
                if i > 0:
                    ansi_end = i - 1
                    while ansi_end >= max(0, i-20):
                        if self.file_data[ansi_end] == 0x00:
                            ansi_start_candidate = ansi_end + 1
                            ansi_len_candidate = i - ansi_start_candidate
                            if ansi_len_candidate >= 3:
                                ansi_chars = self.file_data[ansi_start_candidate:i]
                                printable_rate = sum(1 for b in ansi_chars if 32 <= b <= 126) / ansi_len_candidate
                                if printable_rate >= 0.8:
                                    conflict = True
                                    break
                        ansi_end -= 1
                if conflict:
                    i += 1
                    continue
                start = i
                bytes_collected = bytearray()
                unicode_count = 0
                valid_continuous = True

                while i < data_length - 1 and valid_continuous:
                    if i in ansi_occupied or (i+1) in ansi_occupied:
                        break
                    if self.file_data[i] == 0x00 and (32 <= self.file_data[i+1] <= 126):
                        bytes_collected.extend([self.file_data[i], self.file_data[i+1]])
                        unicode_count += 1
                        i += 2
                        if i < data_length - 1:
                            if i % 2 != 0:
                                valid_continuous = False
                            elif not (self.file_data[i] == 0x00 and (32 <= self.file_data[i+1] <= 126)):
                                valid_continuous = False
                    else:
                        valid_continuous = False
                if unicode_count >= min_length:
                    try:
                        text = bytes_collected.decode('utf-16be').rstrip('\x00')
                        if text and self._is_likely_valid_text(text) and len(text) == unicode_count:
                            segments.append({
                                "start": start,
                                "end": i - 1,
                                "length": len(bytes_collected),
                                "text": text,
                                "bytes": bytes_collected,
                                "encoding": "utf-16be"
                            })
                    except:
                        pass
                else:
                    i = start + 1

        return segments

    def _find_utf16be_strings(self, data_length, min_length):
        segments = []
        current_pos = 0
        while current_pos < data_length - 1:
            while current_pos < data_length - 1:
                byte1 = self.file_data[current_pos]
                byte2 = self.file_data[current_pos + 1]
                if (byte1, byte2) in {(0x00, 0x00), (0x00, 0x09), (0x00, 0x0A), (0x00, 0x0D)}:
                    current_pos += 2
                else:
                    break
            if current_pos >= data_length - 1:
                break
            byte1 = self.file_data[current_pos]
            byte2 = self.file_data[current_pos + 1]
            if not (byte1 == 0 and 32 <= byte2 <= 126):
                current_pos += 1
                continue
            segment_start = current_pos
            segment_bytes = bytearray()
            while current_pos < data_length - 1:
                byte1 = self.file_data[current_pos]
                byte2 = self.file_data[current_pos + 1]
                if (byte1, byte2) in {(0x00, 0x00), (0x00, 0x09), (0x00, 0x0A), (0x00, 0x0D)}:
                    break
                if not (byte1 == 0 and 32 <= byte2 <= 126):
                    break
                segment_bytes.extend([byte1, byte2])
                current_pos += 2
            if len(segment_bytes) >= min_length * 2:
                try:
                    segment_text = segment_bytes.decode('utf-16be')
                    segment_text = segment_text.rstrip('\x00')
                    if segment_text and self._is_likely_valid_text(segment_text):
                        segments.append({
                            "start": segment_start,
                            "end": current_pos - 1,
                            "length": len(segment_bytes),
                            "text": segment_text,
                            "bytes": segment_bytes,
                            "encoding": "utf-16be"
                        })
                except:
                    pass
        return segments

    def get_mapping_file_path(self, scan_mode):
        if not self.file_path:
            return None

        dir_path = os.path.dirname(self.file_path)
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]

        if scan_mode == "ansi":
            suffix = "_ansi"
        elif scan_mode == "unicode_le":
            suffix = "_unicode_le"
        elif scan_mode == "unicode_be":
            suffix = "_unicode_be"
        else:
            suffix = ""

        mapping_file = os.path.join(dir_path, f"{base_name}{suffix}_mapping.json")
        return mapping_file

    def load_mapping_from_file(self, scan_mode):
        mapping_file = self.get_mapping_file_path(scan_mode)
        if not mapping_file or not os.path.exists(mapping_file):
            return None

        try:
            import json
            with open(mapping_file, 'r', encoding='utf-8') as f:
                mapping_data = json.load(f)

            if mapping_data.get('file_size') != len(self.file_data):
                self.update_status(f"映射文件与当前文件大小不匹配,将重新扫描")
                return None

            self.update_status(f"已加载本地映射文件:{os.path.basename(mapping_file)}")
            return mapping_data

        except Exception as e:
            self.update_status(f"加载映射文件失败:{str(e)}")
            return None

    def save_mapping_to_file(self, scan_mode, segments):
        mapping_file = self.get_mapping_file_path(scan_mode)
        if not mapping_file:
            return

        try:
            import json

            mapping_data = {
                'file_path': self.file_path,
                'file_name': os.path.basename(self.file_path),
                'file_size': len(self.file_data),
                'scan_mode': scan_mode,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'encoding': self.get_encoding_for_scan_mode(scan_mode),
                'strings': []
            }

            for i, segment in enumerate(segments):
                mapping_data['strings'].append({
                    'id': i + 1,
                    'address': segment['start'],
                    'address_hex': f"0x{segment['start']:08X}",
                    'length': segment['length'],
                    'original_text': segment['text'],
                    'translated_text': '',
                    'bytes_hex': bytes_to_hex(segment.get('bytes', b'')),
                    'encoding': segment.get('encoding', 'unknown')
                })

            with open(mapping_file, 'w', encoding='utf-8') as f:
                json.dump(mapping_data, f, ensure_ascii=False, indent=2)

            self.update_status(f"映射已保存:{os.path.basename(mapping_file)}")

        except Exception as e:
            self.update_status(f"保存映射文件失败:{str(e)}")

    def get_encoding_for_scan_mode(self, scan_mode):
        if scan_mode == "ansi":
            return self.encoding_var.get() if hasattr(self, 'encoding_var') else "utf-8"
        elif scan_mode == "unicode_le":
            return "utf-16le"
        elif scan_mode == "unicode_be":
            return "utf-16be"
        return "unknown"

    def scan_strings_for_sidebar(self):
        if not self.file_data:
            messagebox.showwarning("警告", "请先打开文件")
            return
        scan_mode = self.scan_mode_var.get()
        self.current_scan_mode = scan_mode
        self.on_encoding_changed()
        mapping_data = self.load_mapping_from_file(scan_mode)

        if mapping_data and mapping_data.get('strings'):
            self.current_mapping_data = mapping_data
            self.load_strings_from_mapping(mapping_data)
            self.update_status(f"已从本地映射加载{len(self.string_entries)}个字符串")
            return

        self.update_status("正在扫描字符串...")
        self.root.update_idletasks()
        segments = []
        if scan_mode == "ansi":
            self.update_status("ANSI扫描模式:请手动选择编码,UTF-8或GBK")
            segments = self.find_strings_simple(min_length=2)
        elif scan_mode == "unicode_le":
            self.encoding_var.set("utf-16le")
            self.update_status("正在扫描UTF-16LE编码字符串")
            segments = self.find_unicode_strings(min_length=2, encoding_type="le")
        elif scan_mode == "unicode_be":
            self.encoding_var.set("utf-16be")
            self.update_status("正在扫描UTF-16BE编码字符串")
            segments = self.find_unicode_strings(min_length=2, encoding_type="be")

        if not segments:
            messagebox.showinfo("无结果", "未找到有效字符串")
            return

        self.current_segments = segments
        self.load_strings_to_sidebar(segments, scan_mode)
        self.save_mapping_to_file(scan_mode, segments)
        self.update_status(f"扫描完成,找到{len(segments)}个字符串,映射文件已保存")

    def load_strings_to_sidebar(self, segments, scan_mode):
        self.string_entries = []
        for item in self.string_tree.get_children():
            self.string_tree.delete(item)

        segments.sort(key=lambda x: x["start"])

        for i, segment in enumerate(segments):
            segment_length = segment.get("length", segment["end"] - segment["start"] + 1)
            if scan_mode == "ansi":
                encoding = self.encoding_var.get()
            elif scan_mode == "unicode_le":
                encoding = "utf-16le"
            elif scan_mode == "unicode_be":
                encoding = "utf-16be"
            else:
                encoding = "utf-8"

            self.string_entries.append({
                "id": i + 1,
                "address": segment["start"],
                "length": segment["length"],
                "text": segment["text"],
                "original_text": segment["text"],
                "translated_text": "",
                "bytes": segment.get("bytes", b""),
                "encoding": encoding
            })

            display_text = segment["text"]
            if len(display_text) > 20:
                display_text = display_text[:17] + "..."

            self.string_tree.insert("", tk.END, values=(
                i + 1,
                f"0x{segment['start']:08X}",
                segment["length"],
                display_text
            ))

        if self.string_tree.get_children():
            self.string_tree.selection_set(self.string_tree.get_children()[0])

    def load_strings_from_mapping(self, mapping_data):
        self.string_entries = []
        for item in self.string_tree.get_children():
            self.string_tree.delete(item)
    
        if hasattr(self, 'hex_viewer'):
            self.hex_viewer.highlight_start = -1
            self.hex_viewer.highlight_end = -1
            self.hex_viewer.update_view()
    
        self.current_string_index = -1
    
        strings = mapping_data.get('strings', [])
        self.current_mapping_data = mapping_data
        self.current_segments = []
    
        self.string_tree.configure(yscrollcommand=lambda *args: None)
    
        for str_info in strings:
            original_text = str_info.get('original_text', '')
            translated_text = str_info.get('translated_text', '')
        
            display_text = translated_text if translated_text else original_text
            bytes_hex = str_info.get('bytes_hex', '')
            if bytes_hex:
                try:
                    bytes_data = bytes.fromhex(bytes_hex.replace(' ', ''))
                except:
                    bytes_data = b''
            else:
                bytes_data = b''
        
            segment = {
                "id": str_info['id'],
                "address": str_info['address'],
                "length": str_info['length'],
                "text": display_text,
                "original_text": original_text,
                "translated_text": translated_text,
                 "bytes": bytes_data,
                "encoding": str_info.get('encoding', 'unknown')
            }
        
            self.string_entries.append(segment)
            self.current_segments.append(segment)
        
            truncated_display = display_text
            if len(truncated_display) > 20:
                truncated_display = truncated_display[:17] + "..."
        
            self.string_tree.insert("", tk.END, values=(
                str_info['id'],
                str_info.get('address_hex', f"0x{str_info['address']:08X}"),
                str_info['length'],
                truncated_display
            ))
    
        tree_scrollbar = None
        for child in self.sidebar_frame._content_frame.winfo_children():
            if isinstance(child, ttk.Scrollbar):
                tree_scrollbar = child
                break
    
        if tree_scrollbar:
            self.string_tree.configure(yscrollcommand=tree_scrollbar.set)
    
        if self.string_tree.get_children():
            self.string_tree.selection_set(self.string_tree.get_children()[0])
            self.current_string_index = 0
    
        translated_count = sum(1 for e in self.string_entries if e.get('translated_text'))
        untranslated_count = len(self.string_entries) - translated_count
    
        if translated_count > 0:
            self.update_status(f"已加载{len(self.string_entries)}个字符串(已翻译:{translated_count},未翻译:{untranslated_count})")
        else:
            self.update_status(f"已加载{len(self.string_entries)}个字符串")
    
        self.root.update_idletasks()

    def on_scan_mode_changed(self, event=None):
        scan_mode = self.scan_mode_var.get()
        if scan_mode == "unicode_le":
            self.encoding_var.set("utf-16le")
            self.update_status("已切换到UTF-16LE扫描模式")
        elif scan_mode == "unicode_be":
            self.encoding_var.set("utf-16be")
            self.update_status("已切换到UTF-16BE扫描模式")
        else:
            self.update_status("ANSI扫描模式:请手动选择编码,UTF-8或GBK")
        self.on_encoding_changed()

    def show_cp932_converter(self):
        converter_window = tk.Toplevel(self.root)
        converter_window.title("CP932乱码修复器")
        converter_window.geometry("600x400")
        converter_window.minsize(500, 300)
        main_frame = ttk.Frame(converter_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        input_frame = ttk.LabelFrame(main_frame, text="输入乱码的GBK字符串")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        input_text = tk.Text(input_frame, height=5, wrap=tk.WORD)
        input_text.pack(fill=tk.X, padx=5, pady=5)
        output_frame = ttk.LabelFrame(main_frame, text="转换后的CP932日语字符串")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        output_text = tk.Text(output_frame, height=5, wrap=tk.WORD)
        output_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        def convert_cp932():
            try:
                gbk_str = input_text.get("1.0", tk.END).strip()
                if not gbk_str:
                    output_text.delete("1.0", tk.END)
                    return
                gbk_bytes = gbk_str.encode('gbk', errors='ignore')
                cp932_str = gbk_bytes.decode('cp932', errors='ignore')
                output_text.delete("1.0", tk.END)
                output_text.insert("1.0", cp932_str)
            except Exception as e:
                messagebox.showerror("转换错误", f"转换失败:{str(e)}")
        def copy_result():
            result = output_text.get("1.0", tk.END).strip()
            if result:
                self.root.clipboard_clear()
                self.root.clipboard_append(result)
                self.update_status("已复制CP932转换结果到剪贴板")

        def clear_all():
            input_text.delete("1.0", tk.END)
            output_text.delete("1.0", tk.END)
        def on_input_change(event=None):
            converter_window.after(100, convert_cp932)
        ttk.Button(button_frame, text="转换", command=convert_cp932).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="复制", command=copy_result).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清空", command=clear_all).pack(side=tk.LEFT, padx=5)
        info_label = ttk.Label(main_frame, 
                          text="此工具用于把日本软件在Windows系统上显示乱码的字符串还原成日语,方便用户汉化",
                          foreground="blue", font=("Microsoft YaHei", 11))
        info_label.pack(pady=(5, 0))   
        input_text.focus_set()

    def show_clipboard_converter(self):
        converter_window = tk.Toplevel(self.root)
        converter_window.title("UTF-16字符串转换器")
        converter_window.geometry("600x500")
        converter_window.minsize(500, 300)

        main_frame = ttk.Frame(converter_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.LabelFrame(main_frame, text="输入字符串")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="输入UTF16点分隔文本(自动转换为正常文本):").pack(anchor=tk.W, padx=5, pady=5)

        input_text = tk.Text(input_frame, height=4, wrap=tk.WORD)
        input_text.pack(fill=tk.X, padx=5, pady=5)

        result_frame = ttk.LabelFrame(main_frame, text="转换结果")
        result_frame.pack(fill=tk.BOTH, expand=True)

        result_text = tk.Text(result_frame, height=10, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        def update_conversion():
            input_str = input_text.get("1.0", tk.END).strip()
            if not input_str:
                result_text.delete("1.0", tk.END)
                return
            result = self.convert_utf16_exe_text(input_str)
            result_text.delete("1.0", tk.END)
            result_text.insert("1.0", result)

        def copy_result():
            result = result_text.get("1.0", tk.END).strip()
            if result:
                self.root.clipboard_clear()
                self.root.clipboard_append(result)
                self.update_status("已复制转换结果到剪贴板")

        def clear_all():
            input_text.delete("1.0", tk.END)
            result_text.delete("1.0", tk.END)
        ttk.Button(button_frame, text="清空", command=clear_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="关闭", command=converter_window.destroy).pack(side=tk.RIGHT, padx=5)

        input_text.bind("<KeyRelease>", lambda e: update_conversion())
        input_text.focus_set()

    def convert_utf16_exe_text(self, text):
        original_text = text
        cleaned = re.sub(r'[\n\r\t]', '', text)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        cleaned = re.sub(r'\.\.', '\n', cleaned)
        cleaned = re.sub(r'\.', '', cleaned)
        cleaned = re.sub('\n', '.', cleaned)
        if original_text != cleaned:
            print(f"UTF-16点分隔文本转换:{original_text}->{cleaned}")
        return cleaned
    def open_file_with_path(self, file_path):
        try:
            with open(file_path, "rb") as f:
                self.file_data = bytearray(f.read())

            self.file_path = file_path
            self.original_data = copy.copy(self.file_data)

            self.file_path_label.config(text=os.path.basename(file_path), foreground="green")
            self.file_size_label.config(text=f"{len(self.file_data)}字节")

            self.clear_matches()
            self.hex_viewer.start_address = 0 
            self.hex_viewer.highlight_start = -1 
            self.hex_viewer.highlight_end = -1
            self.hex_viewer.set_data(self.file_data) 

            self.history = [copy.copy(self.file_data)]
            self.history_index = 0
            self.current_mapping_data = {}
            self.current_segments = []
            self.current_scan_mode = None
            self.pending_changes = False
            self.string_entries = []
            self.current_string_index = -1
            for item in self.string_tree.get_children():
                self.string_tree.delete(item)
            self.root.after(50, self.auto_load_mapping)
            self.update_status(f"已加载文件:{os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件:{str(e)}")
            self.update_status(f"错误:无法打开文件 - {str(e)}")

    def confirm_new_find_text(self):
        new_text = self.find_text.get("1.0", tk.END).strip()
        if new_text != self.current_find_text:
            self.current_find_text = new_text
            self.find_matches()
        self.replace_button.config(state=tk.NORMAL)
        self.replace_all_button.config(state=tk.NORMAL)
        self.replace_text.config(state=tk.NORMAL)
        self.replace_hex_entry.config(state=tk.NORMAL)
        self.replace_buttons_disabled = False

    def on_encoding_changed(self, event=None):
        self.hex_viewer.highlight_start = -1
        self.hex_viewer.highlight_end = -1   
        self.clear_matches()
        self.update_display()
        current_encoding = self.encoding_var.get()
        if current_encoding in ['utf-16le', 'utf-16be']:
            self.update_status(f"已切换到{current_encoding}模式,框选状态已重置,粘贴点分隔文本将自动转换")
        else:
            self.update_status(f"已切换到{current_encoding}模式,框选状态已重置")
        self.hex_viewer.update_view()

    def reset_find_mode(self):
        self.find_text.delete("1.0", tk.END)
        self.find_hex_entry.delete(0, tk.END)
        self.replace_text.delete("1.0", tk.END)
        self.replace_hex_entry.delete(0, tk.END)
        self.clear_matches()
        self.input_type_var.set("字符串")
        self.find_mode = "text"
        self.update_input_fields_state()
        if hasattr(self, 'hex_viewer'):
            self.hex_viewer.highlight_start = -1
            self.hex_viewer.highlight_end = -1
            self.hex_viewer.update_view()
        self.update_status("编码/输入类型已切换,查找模式和框选状态已重置")

    def create_widgets(self):
        menubar = tk.Menu(self.root, bg=MODERN_COLORS['bg_secondary'], fg=MODERN_COLORS['text_primary'],
                          activebackground=MODERN_COLORS['accent_blue'], activeforeground='#ffffff',
                          font=("Microsoft YaHei", 10), tearoff=0)

        file_menu = tk.Menu(menubar, tearoff=0, bg=MODERN_COLORS['bg_secondary'],
                           fg=MODERN_COLORS['text_primary'], activebackground=MODERN_COLORS['accent_blue'],
                           activeforeground='#ffffff', font=("Microsoft YaHei", 10))
        file_menu.add_command(label="📂 打开文件", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="💾 保存", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="📁 另存为", command=self.save_file_as, accelerator="Ctrl+T")
        file_menu.add_separator()
        file_menu.add_command(label="❌ 退出", command=self.root.quit, accelerator="Ctrl+Q")
        menubar.add_cascade(label="📁 文件", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0, bg=MODERN_COLORS['bg_secondary'],
                           fg=MODERN_COLORS['text_primary'], activebackground=MODERN_COLORS['accent_blue'],
                           activeforeground='#ffffff', font=("Microsoft YaHei", 10))
        edit_menu.add_command(label="↩️ 撤销", command=self.undo, accelerator="Ctrl+Z")
        edit_menu.add_command(label="↪️ 重做", command=self.redo, accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="🎨 亮色主题", command=lambda: self.switch_theme('light'))
        edit_menu.add_command(label="🌙 暗色主题", command=lambda: self.switch_theme('dark'))
        edit_menu.add_separator()
        edit_menu.add_command(label="🔧 CP932乱码修复器", command=self.show_cp932_converter, accelerator="F7")
        edit_menu.add_command(label="🔧 UTF-16字符串转换器", command=self.show_clipboard_converter, accelerator="F8")
        menubar.add_cascade(label="🔧 选择功能", menu=edit_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=MODERN_COLORS['bg_secondary'],
                           fg=MODERN_COLORS['text_primary'], activebackground=MODERN_COLORS['accent_blue'],
                           activeforeground='#ffffff', font=("Microsoft YaHei", 10))
        help_menu.add_command(label="ℹ️ 关于此工具", command=self.show_about)
        menubar.add_cascade(label="📖 查看说明", menu=help_menu)

        self.root.config(menu=menubar)
        self.root.bind("<Control-z>", lambda e: self.undo())
        self.root.bind("<Control-y>", lambda e: self.redo())
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_file_as())
        self.root.bind("<F1>", lambda e: self.find_prev())
        self.root.bind("<F2>", lambda e: self.find_next())
        self.root.bind("<F7>", lambda e: self.show_cp932_converter())
        self.root.bind("<F8>", lambda e: self.show_clipboard_converter())
        self.root.bind("<Control-S>", lambda e: self.save_file())
        self.root.bind("<Control-T>", lambda e: self.save_file_as())
        self.root.bind("<Control-Up>", lambda e: self.prev_string())
        self.root.bind("<Control-Down>", lambda e: self.next_string())

        toolbar_frame = tk.Frame(self.root, bg=MODERN_COLORS['bg_secondary'], relief=tk.FLAT, height=45)
        toolbar_frame.pack(side=tk.TOP, fill=tk.X, padx=0, pady=0)

        title_label = tk.Label(toolbar_frame, text="⚡ 汉化辅助编辑器", bg=MODERN_COLORS['bg_secondary'],
                              fg=MODERN_COLORS['accent_green'], font=("Microsoft YaHei", 14, "bold"), padx=15)
        title_label.pack(side=tk.LEFT, pady=8)

        zoom_frame = tk.Frame(toolbar_frame, bg=MODERN_COLORS['bg_secondary'])
        zoom_frame.pack(side=tk.RIGHT, padx=15, pady=8)
        tk.Label(zoom_frame, text="缩放:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['text_secondary'], font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=(0, 5))
        self.zoom_var = tk.StringVar(value="100%")
        zoom_combo = ttk.Combobox(zoom_frame, textvariable=self.zoom_var,
                             values=["90%", "100%"],
                             state="readonly", width=7)
        zoom_combo.pack(side=tk.LEFT, padx=2)
        zoom_combo.bind("<<ComboboxSelected>>", self.on_zoom_changed)
        tk.Button(zoom_frame, text="−", width=2, height=1, bg=MODERN_COLORS['bg_tertiary'],
                 fg=MODERN_COLORS['text_primary'], relief=tk.FLAT, command=self.zoom_out,
                 activebackground=MODERN_COLORS['accent_blue'], font=("Arial", 12)).pack(side=tk.LEFT, padx=2)
        tk.Button(zoom_frame, text="+", width=2, height=1, bg=MODERN_COLORS['bg_tertiary'],
                 fg=MODERN_COLORS['text_primary'], relief=tk.FLAT, command=self.zoom_in,
                 activebackground=MODERN_COLORS['accent_blue'], font=("Arial", 12)).pack(side=tk.LEFT, padx=2)

        info_frame = tk.Frame(toolbar_frame, bg=MODERN_COLORS['bg_secondary'])
        info_frame.pack(side=tk.RIGHT, padx=20, pady=8)

        file_icon = tk.Label(info_frame, text="📄", bg=MODERN_COLORS['bg_secondary'], font=("Segoe UI Emoji", 11))
        file_icon.pack(side=tk.LEFT, padx=(0, 2))
        self.file_path_label = tk.Label(info_frame, text="未选择文件", bg=MODERN_COLORS['bg_secondary'],
                                        fg=MODERN_COLORS['text_secondary'], font=("Microsoft YaHei", 10))
        self.file_path_label.pack(side=tk.LEFT, padx=(0, 15))

        size_icon = tk.Label(info_frame, text="📊", bg=MODERN_COLORS['bg_secondary'], font=("Segoe UI Emoji", 11))
        size_icon.pack(side=tk.LEFT, padx=(0, 2))
        self.file_size_label = tk.Label(info_frame, text="0字节", bg=MODERN_COLORS['bg_secondary'],
                                        fg=MODERN_COLORS['text_secondary'], font=("Microsoft YaHei", 10))
        self.file_size_label.pack(side=tk.LEFT)

        separator = tk.Frame(self.root, bg=MODERN_COLORS['border'], height=1)
        separator.pack(side=tk.TOP, fill=tk.X)

        main_container = tk.Frame(self.root, bg=MODERN_COLORS['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        main_container.bind("<MouseWheel>", self.on_mousewheel)
        main_container.bind("<Button-4>", self.on_mousewheel)
        main_container.bind("<Button-5>", self.on_mousewheel)

        left_container = tk.Frame(main_container, bg=MODERN_COLORS['bg_primary'])
        left_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        left_container.grid_rowconfigure(0, weight=0)
        left_container.grid_rowconfigure(1, weight=1)
        left_container.grid_columnconfigure(0, weight=1)

        file_info_frame = ModernLabelFrame(left_container, text="文件信息", bg=MODERN_COLORS['bg_primary'])
        file_info_frame.grid(row=0, column=0, sticky=tk.EW, pady=(0, 2))

        hex_frame = ModernLabelFrame(left_container, text="十六进制视图", bg=MODERN_COLORS['bg_primary'])
        hex_frame.grid(row=1, column=0, sticky=tk.NSEW, pady=(0, 2))

        zoomed_height = int(20 * self.zoom_level)
        self.hex_viewer = HexViewer(hex_frame, width=70, height=zoomed_height, app=self)
        self.hex_viewer.hex_text.bind("<Button-1>", self.on_hex_click)
        self.hex_viewer.ascii_text.bind("<Button-1>", self.on_ascii_click)
        self.hex_viewer.hex_text.bind("<Button-3>", self.hex_viewer.on_hex_right_click)
        self.hex_viewer.ascii_text.bind("<Button-3>", self.hex_viewer.on_ascii_right_click)

        v_scrollbar = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=self.hex_viewer.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.hex_viewer.set_scroll_command(v_scrollbar.set)

        search_frame = ModernLabelFrame(left_container, text="查找和替换", bg=MODERN_COLORS['bg_primary'])
        search_frame.grid(row=2, column=0, sticky=tk.EW)

        search_frame_inner = search_frame._content_frame
        search_frame_inner.grid_rowconfigure(0, weight=0)
        search_frame_inner.grid_rowconfigure(1, weight=0)
        search_frame_inner.grid_rowconfigure(2, weight=0)
        search_frame_inner.grid_rowconfigure(3, weight=0)
        search_frame_inner.grid_rowconfigure(4, weight=0)
        search_frame_inner.grid_columnconfigure(0, weight=1)

        input_type_frame = tk.Frame(search_frame_inner, bg=MODERN_COLORS['bg_secondary'])
        input_type_frame.grid(row=0, column=0, sticky=tk.EW, padx=10, pady=(5, 0))

        tk.Label(input_type_frame, text="输入类型:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['accent_yellow'], font=("Microsoft YaHei", 10, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        input_type_menu = ttk.Combobox(input_type_frame, textvariable=self.input_type_var,
                                       values=self.input_type_options, state="readonly", width=10)
        input_type_menu.pack(side=tk.LEFT, padx=2)
        input_type_menu.bind("<<ComboboxSelected>>", self.on_input_type_changed)

        tk.Label(input_type_frame, text="编码:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['accent_yellow'], font=("Microsoft YaHei", 10, "bold")).pack(side=tk.LEFT, padx=(15, 8))
        self.encoding_menu = ttk.Combobox(input_type_frame, textvariable=self.encoding_var,
                                     values=self.encoding_options, state="readonly", width=12)
        self.encoding_menu.pack(side=tk.LEFT, padx=2)
        self.encoding_menu.bind("<<ComboboxSelected>>", self.on_encoding_changed)

        search_input_frame = tk.Frame(search_frame_inner, bg=MODERN_COLORS['bg_secondary'])
        search_input_frame.grid(row=1, column=0, sticky=tk.EW, padx=10, pady=5)

        tk.Label(search_input_frame, text="查找字符串:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['text_primary'], font=("Microsoft YaHei", 10)).pack(anchor=tk.W)
        self.find_text = ModernText(search_input_frame, height=2)
        self.find_text.pack(fill=tk.X, pady=2)
        self.find_text.bind("<KeyRelease>", self.validate_input)
        self.find_text.bind("<FocusIn>", self.on_find_focus)
        self.find_text.bind("<Control-v>", self.handle_paste)
        self.add_tooltip(self.find_text, "双击此输入框自动从16进制模式切换至字符串模式")

        tk.Label(search_input_frame, text="查找16进制字节序列:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['text_primary'], font=("Microsoft YaHei", 10)).pack(anchor=tk.W, pady=(5, 0))
        self.find_hex_entry = ModernEntry(search_input_frame)
        self.find_hex_entry.pack(fill=tk.X, pady=2)
        self.find_hex_entry.bind("<KeyRelease>", self.validate_hex_input)
        self.find_hex_entry.bind("<FocusIn>", self.on_hex_focus)
        self.add_tooltip(self.find_hex_entry, "双击此输入框自动从字符串模式切换至16进制模式")

        replace_input_frame = tk.Frame(search_frame_inner, bg=MODERN_COLORS['bg_secondary'])
        replace_input_frame.grid(row=2, column=0, sticky=tk.EW, padx=10, pady=5)

        tk.Label(replace_input_frame, text="替换字符串:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['accent_green'], font=("Microsoft YaHei", 10)).pack(anchor=tk.W)
        self.replace_text = ModernText(replace_input_frame, height=2)
        self.replace_text.pack(fill=tk.X, pady=2)
        self.replace_text.bind("<KeyRelease>", self.validate_replace_input)
        self.replace_text.bind("<Control-v>", self.handle_paste)

        tk.Label(replace_input_frame, text="替换16进制字节序列:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['accent_green'], font=("Microsoft YaHei", 10)).pack(anchor=tk.W, pady=(5, 0))
        self.replace_hex_entry = ModernEntry(replace_input_frame)
        self.replace_hex_entry.pack(fill=tk.X, pady=2)
        self.replace_hex_entry.bind("<KeyRelease>", self.validate_replace_hex_input)
        self.replace_hex_entry.bind("<Control-v>", self.handle_paste)

        button_frame = tk.Frame(search_frame_inner, bg=MODERN_COLORS['bg_tertiary'])
        button_frame.grid(row=3, column=0, sticky=tk.EW, padx=10, pady=(5, 5))

        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)
        button_frame.grid_columnconfigure(3, weight=1)
        button_frame.grid_columnconfigure(4, weight=1)

        ModernButton(button_frame, text="查找", command=self.confirm_new_find_text).grid(row=0, column=0, padx=4, pady=4)
        ModernButton(button_frame, text="上一个(F1)", command=self.find_prev).grid(row=0, column=1, padx=4, pady=4)
        ModernButton(button_frame, text="下一个(F2)", command=self.find_next).grid(row=0, column=2, padx=4, pady=4)
        self.replace_button = ModernButton(button_frame, text="替换当前", command=self.replace_current)
        self.replace_button.grid(row=0, column=3, padx=4, pady=4)
        self.replace_all_button = ModernButton(button_frame, text="替换全部", command=self.replace_all)
        self.replace_all_button.grid(row=0, column=4, padx=4, pady=4)

        self.sidebar_frame = ModernLabelFrame(main_container, text="字符串列表", bg=MODERN_COLORS['bg_primary'])
        self.sidebar_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(0, 5), pady=5)

        sidebar_inner = self.sidebar_frame._content_frame

        filter_frame = tk.Frame(sidebar_inner, bg=MODERN_COLORS['bg_secondary'])
        filter_frame.pack(fill=tk.X, padx=8, pady=(8, 5))

        tk.Label(filter_frame, text="🔍", bg=MODERN_COLORS['bg_secondary'], font=("Segoe UI Emoji", 11)).pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar()
        self.filter_entry = ModernEntry(filter_frame, textvariable=self.filter_var)
        self.filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        self.case_sensitive_var = tk.BooleanVar(value=True)
        self.case_checkbox = tk.Checkbutton(filter_frame, text="大小写敏感",
                                        variable=self.case_sensitive_var, bg=MODERN_COLORS['bg_secondary'],
                                        fg=MODERN_COLORS['text_primary'], selectcolor=MODERN_COLORS['bg_tertiary'],
                                        activebackground=MODERN_COLORS['bg_secondary'],
                                        command=self.on_filter_changed)
        self.case_checkbox.pack(side=tk.LEFT, padx=5)
        self.filter_var.trace_add('write', self.on_filter_changed)

        sidebar_controls = tk.Frame(sidebar_inner, bg=MODERN_COLORS['bg_secondary'])
        sidebar_controls.pack(fill=tk.X, padx=8, pady=5)

        mode_frame = tk.Frame(sidebar_controls, bg=MODERN_COLORS['bg_secondary'])
        mode_frame.pack(side=tk.LEFT)
        tk.Label(mode_frame, text="模式:", bg=MODERN_COLORS['bg_secondary'],
                fg=MODERN_COLORS['accent_yellow'], font=("Microsoft YaHei", 10, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        self.scan_mode_var = tk.StringVar(value=config.get('scan_mode', "ansi"))
        self.scan_mode_menu = ttk.Combobox(mode_frame, textvariable=self.scan_mode_var,
                           values=["ansi", "unicode_le", "unicode_be"],
                           state="readonly", width=12)
        self.scan_mode_menu.pack(side=tk.LEFT, padx=2)
        self.scan_mode_menu.bind("<<ComboboxSelected>>", self.on_scan_mode_changed)

        nav_frame = tk.Frame(sidebar_controls, bg=MODERN_COLORS['bg_secondary'])
        nav_frame.pack(side=tk.RIGHT)
        ModernButton(nav_frame, text="◀ 上一个", command=self.prev_string, width=8).pack(side=tk.LEFT, padx=2)
        ModernButton(nav_frame, text="下一个 ▶", command=self.next_string, width=8).pack(side=tk.LEFT, padx=2)

        scan_btn_frame = tk.Frame(sidebar_controls, bg=MODERN_COLORS['bg_secondary'])
        scan_btn_frame.pack(side=tk.LEFT, padx=(10, 0))
        ModernButton(scan_btn_frame, text="🚀 扫描", command=self.scan_strings_for_sidebar, width=8).pack(side=tk.LEFT, padx=2)

        columns = ("ID", "地址", "长度", "内容")
        self.string_tree = ttk.Treeview(sidebar_inner, columns=columns, show="headings", height=15)
        self.string_tree.heading("ID", text="ID")
        self.string_tree.column("ID", width=40, anchor=tk.CENTER)
        self.string_tree.heading("地址", text="地址")
        self.string_tree.column("地址", width=80, anchor=tk.CENTER)
        self.string_tree.heading("长度", text="长度")
        self.string_tree.column("长度", width=50, anchor=tk.CENTER)
        self.string_tree.heading("内容", text="内容")
        self.string_tree.column("内容", width=200, anchor=tk.W)
        tree_scrollbar = ttk.Scrollbar(sidebar_inner, orient=tk.VERTICAL, command=self.string_tree.yview)
        self.string_tree.configure(yscrollcommand=tree_scrollbar.set)
        self.string_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.string_tree.bind("<<TreeviewSelect>>", self.on_string_selected)
        self.string_tree.bind("<Double-1>", self.on_string_double_click)

        self.create_context_menu()

        status_frame = tk.Frame(self.root, bg=MODERN_COLORS['accent_blue'], height=28)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        status_frame.pack_propagate(False)
        self.status_bar = tk.Label(status_frame, text="就绪", anchor=tk.NW,
                                   bg=MODERN_COLORS['accent_blue'], fg='#ffffff', font=("Microsoft YaHei", 10))
        self.status_bar.pack(fill=tk.X, side=tk.TOP, padx=8, pady=4)

        self.find_mode = "text"
        self.update_input_fields_state()

    def zoom_in(self):
        current_idx = self.zoom_factors.index(self.zoom_level)
        if current_idx < len(self.zoom_factors) - 1:
            new_zoom = self.zoom_factors[current_idx + 1]
            self.set_zoom(new_zoom)

    def zoom_out(self):
        current_idx = self.zoom_factors.index(self.zoom_level)
        if current_idx > 0:
            new_zoom = self.zoom_factors[current_idx - 1]
            self.set_zoom(new_zoom)

    def on_zoom_changed(self, event=None):
        zoom_str = self.zoom_var.get()
        zoom_map = {"90%": 0.9, "100%": 1.0}
        if zoom_str in zoom_map:
            self.set_zoom(zoom_map[zoom_str])

    def set_zoom(self, zoom_factor):
        self.zoom_level = zoom_factor
        self.zoom_var.set(f"{int(zoom_factor * 100)}%")    
        new_font_size = int(self.base_font_size * zoom_factor)
        font_name = "SimSun"  
        new_font = f"{font_name} {new_font_size}"  
        self.update_all_fonts(new_font)   
        self.adjust_window_height()   
        if hasattr(self, 'hex_viewer'):
            self.update_hex_viewer_height()   
        self.update_status(f"已缩放至{int(zoom_factor * 100)}%")

    def update_hex_viewer_height(self):
        if not hasattr(self, 'hex_viewer'):
            return  
        hex_frame = self.hex_viewer.master
        hex_frame.update_idletasks()
        frame_height = hex_frame.winfo_height()   
        if frame_height <= 0:
            return  
        font = tkfont.Font(font=self.hex_viewer.hex_text.cget("font"))
        line_height = font.metrics("linespace")   
        if line_height <= 0:
            line_height = 20   
        max_lines = max(10, frame_height // line_height - 2)
        self.hex_viewer.height = max_lines
        self.hex_viewer.update_view()

    def update_all_fonts(self, font):
        self.root.option_add("*Font", "Microsoft YaHei 10")
        widgets_to_update = [
            self.file_path_label, self.file_size_label,
            self.status_bar
        ]
        for widget in widgets_to_update:
            try:
                if hasattr(widget, 'config'):
                    widget.config(font="Microsoft YaHei 10")
            except:
                pass
        entry_widgets = [self.find_hex_entry, self.replace_hex_entry]
        for entry in entry_widgets:
            try:
                entry.config(font="Consolas 10")
            except:
                pass
        try:
            style = ttk.Style()
            style.configure("Treeview", font="Microsoft YaHei 10")
            style.configure("Treeview.Heading", font="Microsoft YaHei 10 bold")
        except:
            pass
        if hasattr(self, 'hex_viewer'):
            self.hex_viewer.set_font("Consolas 10")

    def adjust_window_height(self):
        if not self.root.winfo_exists():
            return  
        current_width = self.root.winfo_width()   
        base_height = 1000
        min_height = 600  
        scaled_height = int(base_height * self.scale_factor * self.zoom_level)
        scaled_height = max(int(min_height * self.scale_factor), scaled_height)   
        self.root.geometry(f"{current_width}x{scaled_height}")  
        self.root.minsize(
            int(800 * self.scale_factor * 0.8),
            int(min_height * self.scale_factor * 0.8)
        )

    def on_mousewheel(self, event):
        if event.num == 4 or (hasattr(event, 'delta') and event.delta > 0):
            self.hex_viewer._on_mousewheel(event)
        else:
            self.hex_viewer._on_mousewheel(event)
        return "break"

    def on_string_selected(self, event):
        selected = self.string_tree.selection()
        if not selected:
            return
        item = selected[0]
        values = self.string_tree.item(item, "values")
        if len(values) >= 4:
            try:
                address = int(values[1], 16)
                entry_index = int(values[0]) - 1
                entry = self.string_entries[entry_index]
                text = entry.get("translated_text", "")
                if not text:
                    text = entry.get("original_text", entry.get("text", ""))
                encoding = entry.get("encoding", "utf-8")
                self.hex_viewer.scroll_to_address(address)
                actual_length = entry.get("length", 0)
                if actual_length > 0:
                    self.hex_viewer.highlight_range(address, address + actual_length - 1)
                self.find_mode = "text"
                self.input_type_var.set("字符串")
                current_encoding = self.encoding_var.get()
                current_scan_mode = self.scan_mode_var.get()
                if current_scan_mode == "ansi":
                    self.update_status(f"ANSI字符串已选中,当前编码:{current_encoding},请确认编码是否正确")
                else:
                    self.update_status(f"字符串已选中,当前编码:{current_encoding}")
                self.find_text.delete("1.0", tk.END)
                self.find_text.insert("1.0", text)
                try:
                    find_bytes = text.encode(current_encoding, errors='ignore')
                    self.find_hex_entry.delete(0, tk.END)
                    self.find_hex_entry.insert(0, bytes_to_hex(find_bytes))
                except Exception as e:
                    print(f"更新十六进制显示时出错:{e}")

                self.find_text.config(state=tk.NORMAL)
                self.find_hex_entry.config(state=tk.NORMAL)
                self.replace_text.config(state=tk.NORMAL)
                self.replace_hex_entry.config(state=tk.NORMAL)
                self.current_find_text = text
                find_bytes = text.encode(current_encoding, errors='ignore')
                self.current_matches = [{"pos": address, "bytes": find_bytes}]
                self.current_match_index = 0
                self.replace_button.config(state=tk.NORMAL)
                self.replace_all_button.config(state=tk.NORMAL)
                self.replace_buttons_disabled = False
                self.update_status(f"已选中字符串({current_encoding}):{text[:50]}{'...' if len(text) > 50 else ''}")
            except (ValueError, IndexError) as e:
                self.update_status(f"选中错误:{e}")

    def on_string_double_click(self, event):
        self.on_string_selected(event)   
        selected = self.string_tree.selection()
        if selected:
            item = selected[0]
            values = self.string_tree.item(item, "values")
            if len(values) >= 4:
                entry_index = int(values[0]) - 1
                entry = self.string_entries[entry_index]
                original_text = entry.get('original_text', entry.get('text', ''))
                translated_text = entry.get('translated_text', '')
                
                if translated_text:
                    self.update_status(f"原文:{original_text[:50]}... | 已有翻译:{translated_text[:50]}...")
                else:
                    self.update_status(f"原文:{original_text[:50]}... | 尚未翻译")
        self.replace_text.focus_set()
        self.replace_text.tag_add(tk.SEL, "1.0", tk.END)
        self.replace_text.mark_set(tk.INSERT, "1.0")
        self.replace_text.see(tk.INSERT)
        self.update_status("双击选中字符串,已聚焦到替换输入框,请输入汉化内容")

    def prev_string(self):
        if not self.string_entries:
            return
        if self.current_string_index <= 0:
            self.current_string_index = len(self.string_entries) - 1
        else:
            self.current_string_index -= 1
        self.select_string_by_index()

    def next_string(self):
        if not self.string_entries:
            return
        if self.current_string_index >= len(self.string_entries) - 1:
            self.current_string_index = 0
        else:
            self.current_string_index += 1
        self.select_string_by_index()

    def select_string_by_index(self):
        if 0 <= self.current_string_index < len(self.string_entries):
            children = self.string_tree.get_children()
            if self.current_string_index < len(children):
                self.string_tree.selection_set(children[self.current_string_index])
                self.string_tree.see(children[self.current_string_index])
                entry = self.string_entries[self.current_string_index]
                self.hex_viewer.scroll_to_address(entry["address"])
                self.hex_viewer.highlight_range(entry["address"], entry["address"] + entry["length"])
                self.find_text.delete("1.0", tk.END)
                self.find_text.insert("1.0", entry["text"])
                self.update_status(f"字符串{self.current_string_index + 1}/{len(self.string_entries)}: {entry['text'][:50]}{'...' if len(entry['text']) > 50 else ''}")

    def toggle_sidebar(self):
        if self.sidebar_expanded:
            self.sidebar_frame.pack_forget()
            self.sidebar_expanded = False
        else:
            self.sidebar_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(10, 0), pady=0)
            self.sidebar_expanded = True

    def save_file(self):
        if not self.file_path:
            self.save_file_as()
            return
        try:
            with open(self.file_path, "wb") as f:
                f.write(self.file_data)
            self.original_data = copy.copy(self.file_data)
            self.save_current_mapping()
            self.update_status(f"已保存:{os.path.basename(self.file_path)}")
        except Exception as e:
            messagebox.showerror("保存失败", str(e))

    def adjust_text_height(self, text_widget):
        line_count = int(text_widget.index(tk.END).split('.')[0]) - 1
        max_lines = max(line_count, self.initial_height)
        self.update_input_height(text_widget, max_lines)

    def update_input_height(self, text_widget, lines):
        current_height = int(text_widget.cget('height'))
        if current_height != lines:
            text_widget.config(height=lines)

    def check_long_text(self, text_widget):
        text = text_widget.get("1.0", tk.END).strip()
        length = len(text)
        if length > self.max_input_length:
            truncated_text = text[:self.max_input_length]
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", truncated_text)
            self.update_status(f"输入内容已截断为{self.max_input_length}字符")
            messagebox.showwarning("长文本提示", 
                f"输入内容超过{self.max_input_length}字符,已自动截断\n"
                "如需输入更长内容,请分批次操作或使用十六进制模式")
        elif length > self.extended_threshold:
            self.update_status(f"输入内容较长({length}字符),可能影响性能")

    def create_context_menu(self):
        pass

    def insert_bytes(self):
        if not hasattr(self.hex_viewer, 'right_click_pos') or self.hex_viewer.right_click_pos is None:
            return
        count = simpledialog.askinteger("插入字节", "请输入要插入的字节数量:", 
                                       initialvalue=1, minvalue=1, maxvalue=1000)
        if count is None: 
            return
        byte_value = simpledialog.askstring("字节值", "请输入要插入的字节值(十六进制,默认为20):", 
                                          initialvalue="20")
        if byte_value is None: 
            return
        try:
            if byte_value.strip() == "":
                byte_value = 0x20
            else:
                byte_value = int(byte_value, 16)
                if byte_value < 0 or byte_value > 255:
                    raise ValueError("字节值必须在00-FF之间")
        except ValueError:
            messagebox.showerror("错误", "请输入有效的十六进制字节值(00-FF)")
            return
        pos = self.hex_viewer.right_click_pos
        for i in range(count):
            self.file_data.insert(pos + i, byte_value)
        self.hex_viewer.set_data(self.file_data)
        self.hex_viewer.highlight_range(pos, pos + count - 1)
        self.save_history_state()
        self.update_status(f"已在位置0x{pos:08X}插入了{count}个字节(值:0x{byte_value:02X})")

    def delete_bytes(self):
        if not hasattr(self.hex_viewer, 'right_click_pos') or self.hex_viewer.right_click_pos is None:
            return
        pos = self.hex_viewer.right_click_pos
        max_count = len(self.file_data) - pos
        count = simpledialog.askinteger("删除字节", f"请输入要删除的字节数量(最大{max_count}):", 
                                       initialvalue=1, minvalue=1, maxvalue=max_count)
        if count is None:
            return
        if not messagebox.askyesno("确认删除", f"确定要删除从位置0x{pos:08X}开始的{count}个字节吗?"):
            return
        del self.file_data[pos:pos + count]
        self.hex_viewer.set_data(self.file_data)
        self.save_history_state()
        self.update_status(f"已从位置0x{pos:08X}删除了{count}个字节")

    def export_range_bytes(self):
        if not self.file_data:
            messagebox.showwarning("警告", "请先打开文件")
            return

        export_window = tk.Toplevel(self.root)
        export_window.title("导出字节范围")
        export_window.geometry("500x350")
        export_window.minsize(450, 300)
        export_window.transient(self.root)
        export_window.grab_set()
        export_window.geometry(f"+{self.root.winfo_rootx()+50}+{self.root.winfo_rooty()+50}")

        main_frame = ttk.Frame(export_window, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        input_frame = ttk.LabelFrame(main_frame, text="地址范围", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(input_frame, text="起始地址(16进制):").grid(row=0, column=0, sticky=tk.W, pady=5)
        start_var = tk.StringVar(value="0x00000000")
        start_entry = ttk.Entry(input_frame, textvariable=start_var, width=18)
        start_entry.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=5)

        ttk.Label(input_frame, text="结束地址(16进制):").grid(row=1, column=0, sticky=tk.W, pady=5)
        end_var = tk.StringVar(value=f"0x{len(self.file_data)-1:08X}")
        end_entry = ttk.Entry(input_frame, textvariable=end_var, width=18)
        end_entry.grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=5)

        ttk.Label(input_frame, text="示例:0x00000100 到 0x00000200", 
             foreground="gray", font=("SimSun", 9)).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))

        format_frame = ttk.LabelFrame(main_frame, text="导出格式", padding="10")
        format_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(format_frame, text="选择格式:").pack(anchor=tk.W, pady=(0, 5))
        format_var = tk.StringVar(value="纯数字(52494646)")
        format_combo = ttk.Combobox(format_frame, textvariable=format_var,
                                 values=["纯数字(52494646)", "1字节(0x52,0x49,0x46,0x46)", "4字节小端(0x52494646)"],
                                 state="readonly", width=30)
        format_combo.pack(anchor=tk.W, fill=tk.X)

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        def validate_and_export():
            try:
                start_str = start_var.get().strip()
                end_str = end_var.get().strip()
         
                if start_str.lower().startswith("0x"):
                    start_str = start_str[2:]
                if end_str.lower().startswith("0x"):
                    end_str = end_str[2:]
            
                start_addr = int(start_str, 16)
                end_addr = int(end_str, 16)
        
                if start_addr < 0 or end_addr >= len(self.file_data):
                    messagebox.showerror("错误", f"地址范围无效!文件大小:0x{len(self.file_data):08X}")
                    return
                if start_addr > end_addr:
                    messagebox.showerror("错误", "起始地址不能大于结束地址!")
                    return
        
                byte_range = self.file_data[start_addr:end_addr+1]
                if not byte_range:
                    messagebox.showwarning("警告", "选择的范围内没有字节数据")
                    return
            
                format_type = format_var.get()
            
                if format_type == "纯数字(52494646)":
                    result = "".join([f"{b:02X}" for b in byte_range])
                elif format_type == "1字节(0x52,0x49,0x46,0x46)":
                    result = ", ".join([f"0x{b:02X}" for b in byte_range])
                elif format_type == "4字节小端(0x52494646)":
                    padded = byte_range.copy()
                    while len(padded) % 4 != 0:
                        padded.append(0x00)
                    groups = []
                    for i in range(0, len(padded), 4):
                        group = padded[i:i+4]
                        value = group[0] | (group[1] << 8) | (group[2] << 16) | (group[3] << 24)
                        groups.append(f"0x{value:08X}")
                    result = ", ".join(groups)
                else:
                    result = "".join([f"{b:02X}" for b in byte_range])

                result_window = tk.Toplevel(export_window)
                result_window.title("导出结果")
                result_window.geometry("800x550")
                result_window.minsize(600, 550)
        
                info_text = f"地址范围:0x{start_addr:08X} - 0x{end_addr:08X}\n"
                info_text += f"字节数量:{len(byte_range)} (0x{len(byte_range):X})\n"
                info_text += f"导出格式:{format_type}\n"
                info_text += f"输出字符数:{len(result)}\n"
                info_text += "-" * 60
            
                info_label = ttk.Label(result_window, text=info_text, justify=tk.LEFT)
                info_label.pack(anchor=tk.W, padx=10, pady=10)
        
                text_frame = ttk.Frame(result_window)
                text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
                result_text = tk.Text(text_frame, wrap=tk.NONE, font=("Consolas", 10))
                result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
                h_scrollbar = ttk.Scrollbar(text_frame, orient=tk.HORIZONTAL, command=result_text.xview)
                v_scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=result_text.yview)
                h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
                v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                result_text.config(xscrollcommand=h_scrollbar.set, yscrollcommand=v_scrollbar.set)
            
                result_text.insert("1.0", result)
                result_text.config(state=tk.NORMAL)
        
                button_frame2 = ttk.Frame(result_window)
                button_frame2.pack(fill=tk.X, padx=10, pady=(0, 10))
        
                def copy_to_clipboard():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(result)
                    messagebox.showinfo("成功", "已复制到剪贴板!")
        
                def save_to_file():
                    file_path = filedialog.asksaveasfilename(
                        title="保存导出结果",
                        defaultextension=".txt",
                        filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
                    )
                    if file_path:
                        try:
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(f"地址范围:0x{start_addr:08X} - 0x{end_addr:08X}\n")
                                f.write(f"字节数量:{len(byte_range)} (0x{len(byte_range):X})\n")
                                f.write(f"导出格式:{format_type}\n")
                                f.write(f"生成时间:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                                f.write("-" * 60 + "\n")
                                f.write(result)
                                messagebox.showinfo("成功", f"已保存到:{file_path}")
                        except Exception as e:
                            messagebox.showerror("错误", f"保存失败:{str(e)}")
        
                ttk.Button(button_frame2, text="复制到剪贴板", command=copy_to_clipboard).pack(side=tk.LEFT, padx=5)
                ttk.Button(button_frame2, text="保存到文件", command=save_to_file).pack(side=tk.LEFT, padx=5)
                ttk.Button(button_frame2, text="关闭", command=result_window.destroy).pack(side=tk.RIGHT, padx=5)
        
                self.update_status(f"已导出0x{start_addr:08X}-0x{end_addr:08X} ({format_type})")
        
            except ValueError as e:
                messagebox.showerror("错误", f"地址格式错误!请使用16进制格式,如:0x00000100\n错误:{str(e)}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败:{str(e)}")

        export_btn = ttk.Button(button_frame, text="导出", command=validate_and_export, width=15)
        export_btn.pack(side=tk.LEFT, padx=5)
    
        start_entry.focus_set()
        start_entry.select_range(0, tk.END)

    def handle_paste(self, event):
        try:
            focused_widget = self.root.focus_get()

            if focused_widget == self.find_text and self.find_text.cget('state') == tk.DISABLED:
                return "break"
            if focused_widget == self.replace_text and self.replace_text.cget('state') == tk.DISABLED:
                return "break"
            clipboard_text = self.root.clipboard_get()
            if not clipboard_text:
                return "break"

            focused_widget = self.root.focus_get()
            current_encoding = self.encoding_var.get()
            is_utf16_mode = current_encoding in ['utf-16le', 'utf-16be']
            is_text_input = focused_widget in [self.find_text, self.replace_text]
            if is_utf16_mode and is_text_input:
                cleaned_text = self.convert_utf16_exe_text(clipboard_text)
                self.input_type_var.set("字符串")
                self.find_mode = "text"
                self.update_input_fields_state()
                if focused_widget == self.find_text:
                    self.find_text.delete("1.0", tk.END)
                    self.find_text.insert("1.0", cleaned_text)
                    self.validate_input()
                elif focused_widget == self.replace_text:
                    processed_text = self.process_replace_text(cleaned_text)
                    self.replace_text.delete("1.0", tk.END)
                    self.replace_text.insert("1.0", processed_text)
                    self.validate_replace_input()
                if cleaned_text != clipboard_text:
                    self.update_status(f"UTF-16点分隔文本已转换")
                else:
                    self.update_status("已粘贴文本(UTF-16模式)")
                return "break"

            if focused_widget == self.find_text:
                cleaned_text = re.sub(r'[\n\r\t]', '', clipboard_text).strip()
                self.input_type_var.set("字符串")
                self.find_mode = "text"
                self.find_text.config(state=tk.NORMAL)
                current_pos = self.find_text.index(tk.INSERT)
                self.find_text.insert(current_pos, cleaned_text)
                self.validate_input()
                self.update_status(f"已粘贴文本到查找框")

            elif focused_widget == self.find_hex_entry:
                self.input_type_var.set("十六进制")
                self.find_mode = "hex"
                cleaned_text = re.sub(r'[^0-9A-Fa-f]', '', clipboard_text).upper()
                hex_pairs = [cleaned_text[i:i+2] for i in range(0, len(cleaned_text), 2)]
                hex_str = ' '.join(hex_pairs)
                current_pos = self.find_hex_entry.index(tk.INSERT)
                self.find_hex_entry.insert(current_pos, hex_str)
                self.validate_hex_input()

            elif focused_widget == self.replace_text:
                processed_text = self.process_replace_text(clipboard_text)
                current_pos = self.replace_text.index(tk.INSERT)
                self.replace_text.insert(current_pos, processed_text)
                self.validate_replace_input()
                self.update_status(f"已粘贴替换文本并处理标点符号")

            elif focused_widget == self.replace_hex_entry:
                cleaned_text = re.sub(r'[^0-9A-Fa-f]', '', clipboard_text).upper()
                hex_pairs = [cleaned_text[i:i+2] for i in range(0, len(cleaned_text), 2)]
                hex_str = ' '.join(hex_pairs)
                current_pos = self.replace_hex_entry.index(tk.INSERT)
                self.replace_hex_entry.insert(current_pos, hex_str)
                self.validate_replace_hex_input()

        except tk.TclError:
            pass
        return "break"

    def process_replace_text(self, text):
        cleaned_text = re.sub(r'[\n\r\t]', '', text)
        cleaned_text = re.sub(r'([\u4e00-\u9fff])\s+([A-Za-z0-9])', r'\1\2', cleaned_text)
        cleaned_text = re.sub(r'([A-Za-z0-9])\s+([\u4e00-\u9fff])', r'\1\2', cleaned_text)
        cleaned_text = re.sub(r' {2,}', ' ', cleaned_text)
        cleaned_text = cleaned_text.strip()
        translation_table = str.maketrans({
            '（': '(', '）': ')', ':': ':', '；': ';', 
            '「': '"', '」': '"', '『': '"', '』': '"',
            '《': '<', '》': '>', '【': '[', '】': ']',
            '、': ',', '．': '.', '‘': "'", '’': "'",
            '“': '"', '”': '"', '„': '"', '‟': '"',
            '‹': '<', '›': '>', '«': '"', '»': '"',
            '？': '?', '！': '!', '—': '-', '–': '-',
            '～': '~', '‧': '.', '§': '§', '€': 'EUR',
            '£': 'GBP', '¥': 'JPY', '¢': 'c', '°': 'deg',
            ',': ',', '…': '...','∶': ':', 
            '﹕': ':', '﹔': ';', '﹖': '?', '﹗': '!', 
            '﹏': '~', '﹑': ',','﹒': '.','‧': '.', 
            '，': ',', 
        })
        processed_text = cleaned_text.translate(translation_table)
        return processed_text

    def schedule_text_processing(self, event):
        self.root.after(10, lambda: self.process_text_format(event.widget))
    def process_text_format(self, text_widget):
        cursor_pos = text_widget.index(tk.INSERT)
        text = text_widget.get("1.0", tk.END).strip()
        if not text:
            return
        filtered_text = re.sub(r'[\n\r\t]', '', text)
        if filtered_text != text:
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", filtered_text)
            try:
                text_widget.mark_set(tk.INSERT, cursor_pos)
            except:
                text_widget.mark_set(tk.INSERT, tk.END)
        self.adjust_text_height(text_widget)

    def on_hex_click(self, event):
        if not self.file_data:
            return

        if not self.replace_buttons_clicked:
            return

        index = self.hex_viewer.hex_text.index(f"@{event.x},{event.y}")
        line, char = map(int, index.split('.'))
        byte_pos = (line - 1) * self.hex_viewer.bytes_per_line + char // 3
        if byte_pos < 0 or byte_pos >= len(self.file_data):
            return

        current_byte = self.file_data[byte_pos]
        self.find_text.delete("1.0", tk.END)
        self.find_text.insert("1.0", chr(current_byte) if 32 <= current_byte <= 126 else ".")
        self.find_hex_entry.delete(0, tk.END)
        self.find_hex_entry.insert(0, f"{current_byte:02X}")
        self.find_text.config(state=tk.DISABLED)
        self.find_hex_entry.config(state=tk.NORMAL)
        self.find_mode = "hex"

    def on_ascii_click(self, event):
        if not self.file_data:
            return

        if not self.replace_buttons_clicked:
            return

        index = self.hex_viewer.ascii_text.index(f"@{event.x},{event.y}")
        line, char = map(int, index.split('.'))
        byte_pos = (line - 1) * self.hex_viewer.bytes_per_line + char
        if byte_pos < 0 or byte_pos >= len(self.file_data):
            return

        current_byte = self.file_data[byte_pos]
        self.find_text.delete("1.0", tk.END)
        self.find_text.insert("1.0", chr(current_byte) if 32 <= current_byte <= 126 else ".")
        self.find_hex_entry.delete(0, tk.END)
        self.find_hex_entry.insert(0, f"{current_byte:02X}")
        self.find_text.config(state=tk.NORMAL)
        self.find_hex_entry.config(state=tk.DISABLED)
        self.find_mode = "text"
        display_char = chr(current_byte) if 32 <= current_byte <= 126 else "."
        clipboard_text = f"{display_char} [0x{current_byte:02X}]"
        self.root.clipboard_clear()
        self.root.clipboard_append(clipboard_text)
        self.update_status(f"已复制字符:{clipboard_text}")

    def on_find_focus(self, event):
        if event.widget == self.find_text:
            self.find_mode = "text"
            self.find_text.config(state=tk.NORMAL)
            self.input_type_var.set("字符串")

    def on_hex_focus(self, event):
        if event.widget == self.find_hex_entry:
            self.find_mode = "hex"
            self.input_type_var.set("十六进制")

    def update_input_fields_state(self):
        input_type = self.input_type_var.get()
        if input_type == "字符串":
            self.find_text.config(state=tk.NORMAL)
            self.find_hex_entry.config(state=tk.NORMAL)
            self.find_mode = "text"
        else:
            self.find_text.config(state=tk.NORMAL)
            self.find_hex_entry.config(state=tk.NORMAL)
            self.find_mode = "hex"
        self.replace_text.config(state=tk.NORMAL)
        self.replace_hex_entry.config(state=tk.NORMAL)

    def switch_theme(self, theme):
        global MODERN_COLORS, CURRENT_THEME
        
        input_type_value = self.input_type_var.get() if hasattr(self, 'input_type_var') else "字符串"
        encoding_value = self.encoding_var.get() if hasattr(self, 'encoding_var') else "utf-8"
        scan_mode_value = self.scan_mode_var.get() if hasattr(self, 'scan_mode_var') else "ansi"
        zoom_value = self.zoom_var.get() if hasattr(self, 'zoom_var') else "100%"
        
        if theme == 'light':
            MODERN_COLORS = MODERN_COLORS_LIGHT
            CURRENT_THEME = 'light'
        else:
            MODERN_COLORS = MODERN_COLORS_DARK
            CURRENT_THEME = 'dark'
        
        save_config({
            'theme': CURRENT_THEME,
            'encoding': encoding_value,
            'scan_mode': scan_mode_value,
            'input_type': input_type_value
        })
        
        self.root.configure(bg=MODERN_COLORS['bg_primary'])
        
        self._setup_modern_style()
        
        self.update_all_widgets_color()
        
        if hasattr(self, 'input_type_var'):
            self.input_type_var.set(input_type_value)
        if hasattr(self, 'encoding_var'):
            self.encoding_var.set(encoding_value)
        if hasattr(self, 'scan_mode_var'):
            self.scan_mode_var.set(scan_mode_value)
        if hasattr(self, 'zoom_var'):
            self.zoom_var.set(zoom_value)
        
        self.update_status(f"已切换到{('亮色' if theme == 'light' else '暗色')}主题")

    def update_all_widgets_color(self):
        for widget in self.root.winfo_children():
            self.update_widget_color(widget)
        
        if hasattr(self, 'sidebar_frame') and hasattr(self.sidebar_frame, '_content_frame'):
            self.sidebar_frame.configure(bg=MODERN_COLORS['bg_secondary'])
            self.sidebar_frame._content_frame.configure(bg=MODERN_COLORS['bg_secondary'])
        
        if hasattr(self, 'string_tree'):
            style = ttk.Style()
            style.configure('Treeview', 
                           background=MODERN_COLORS['bg_primary'],
                           foreground=MODERN_COLORS['text_primary'],
                           fieldbackground=MODERN_COLORS['bg_primary'])
            style.configure('Treeview.Heading', 
                           background=MODERN_COLORS['bg_tertiary'],
                           foreground=MODERN_COLORS['text_primary'])

    def update_widget_color(self, widget):
        try:
            widget_type = str(type(widget)).lower()
            
            if 'frame' in widget_type:
                widget.configure(bg=MODERN_COLORS['bg_secondary'], highlightbackground=MODERN_COLORS['border'], highlightthickness=1)
            elif 'label' in widget_type:
                widget.configure(bg=MODERN_COLORS['bg_secondary'], fg=MODERN_COLORS['text_primary'])
            elif 'button' in widget_type:
                widget.configure(bg=MODERN_COLORS['accent_blue'], fg='#ffffff',
                                activebackground=MODERN_COLORS['accent_blue_hover'],
                                highlightbackground=MODERN_COLORS['border'], highlightthickness=1)
            elif 'entry' in widget_type:
                widget.configure(bg=MODERN_COLORS['bg_primary'], fg=MODERN_COLORS['text_primary'],
                                insertbackground=MODERN_COLORS['text_primary'],
                                highlightbackground=MODERN_COLORS['border'], highlightthickness=1)
            elif 'text' in widget_type:
                widget.configure(bg=MODERN_COLORS['bg_primary'], fg=MODERN_COLORS['text_primary'],
                                insertbackground=MODERN_COLORS['text_primary'])
            elif 'checkbutton' in widget_type:
                widget.configure(bg=MODERN_COLORS['bg_secondary'], fg=MODERN_COLORS['text_primary'],
                                selectcolor=MODERN_COLORS['bg_primary'])
            elif 'optionmenu' in widget_type or 'combobox' in widget_type:
                style = ttk.Style()
                style.configure('TCombobox', 
                               fieldbackground=MODERN_COLORS['bg_primary'],
                               background=MODERN_COLORS['bg_secondary'],
                               foreground=MODERN_COLORS['text_primary'])
            
            for child in widget.winfo_children():
                self.update_widget_color(child)
        except Exception:
            pass

    def on_input_type_changed(self, event=None):
        input_type = self.input_type_var.get()
        self.find_mode = "hex" if input_type == "十六进制" else "text"
        self.update_input_fields_state()
        self.validate_input()

    def open_file(self):
        file_path = filedialog.askopenfilename(title="选择要编辑的文件")
        if not file_path:
            return

        try:
            with open(file_path, "rb") as f:
                self.file_data = bytearray(f.read())

            if len(self.file_data) == 0:
                messagebox.showwarning("警告", "文件为空")
                return
            if len(self.file_data) > 100 * 1024 * 1024:
                messagebox.showwarning("警告", "文件过大,可能影响性能")
            self.file_path = file_path
            self.original_data = copy.copy(self.file_data)

            self.file_path_label.config(text=os.path.basename(file_path), foreground="green")
            self.file_size_label.config(text=f"{len(self.file_data)}字节")

            self.clear_matches()
            self.hex_viewer.start_address = 0 
            self.hex_viewer.highlight_start = -1 
            self.hex_viewer.highlight_end = -1
            self.hex_viewer.set_data(self.file_data) 

            self.history = [copy.copy(self.file_data)]
            self.history_index = 0
            self.current_mapping_data = {}
            self.current_segments = []
            self.current_scan_mode = None
            self.pending_changes = False
            self.string_entries = []
            for item in self.string_tree.get_children():
                self.string_tree.delete(item)
            self.auto_load_mapping()
            self.update_status(f"已加载文件:{os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件:{str(e)}")
            self.update_status(f"错误:无法打开文件-{str(e)}")
    def auto_load_mapping(self):
        if not self.file_path:
            return
    
        scan_modes = ["ansi", "unicode_le", "unicode_be"]
    
        for scan_mode in scan_modes:
            mapping_file = self.get_mapping_file_path(scan_mode)
            if mapping_file and os.path.exists(mapping_file):
                try:
                    import json
                    with open(mapping_file, 'r', encoding='utf-8') as f:
                        mapping_data = json.load(f)
                
                    if mapping_data.get('file_size') == len(self.file_data):
                        self.current_scan_mode = scan_mode
                        self.scan_mode_var.set(scan_mode)
                    
                        if scan_mode == "ansi":
                            encoding = mapping_data.get('encoding', 'utf-8')
                            self.encoding_var.set(encoding)
                        elif scan_mode == "unicode_le":
                            self.encoding_var.set("utf-16le")
                        elif scan_mode == "unicode_be":
                            self.encoding_var.set("utf-16be")
                    
                        self.root.after(10, lambda: self.load_strings_from_mapping(mapping_data))
                        self.update_status(f"正在加载映射:{os.path.basename(mapping_file)}")
                        return
                    else:
                        self.update_status(f"映射文件大小不匹配,跳过:{os.path.basename(mapping_file)}")
                except Exception as e:
                    self.update_status(f"加载映射失败:{os.path.basename(mapping_file)} - {str(e)}")
    
        self.update_status("未找到匹配的本地映射文件,请点击扫描按钮")

    def save_file_as(self):
        if not self.file_data:
            self.update_status("没有可保存的数据")
            return

        file_path = filedialog.asksaveasfilename(title="保存文件", defaultextension=".bin")
        if not file_path:
            return

        try:
            with open(file_path, "wb") as f:
                f.write(self.file_data)

            self.file_path = file_path
            self.original_data = copy.copy(self.file_data)
            self.file_path_label.config(text=os.path.basename(file_path), foreground="green")

            self.history = [copy.copy(self.file_data)]
            self.history_index = 0
            self.current_scan_mode = None
            self.current_mapping_data = {}
            self.pending_changes = False
            self.update_status(f"文件已保存:{os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("错误", f"无法保存文件:{str(e)}")
            self.update_status(f"错误:无法保存文件-{str(e)}")

    def on_filter_changed(self, *args):
        filter_text = self.filter_var.get().strip()
        for item in self.string_tree.get_children():
            self.string_tree.delete(item)
        if filter_text:
            if not self.case_sensitive_var.get():
                filter_text = filter_text.lower()
            for i, entry in enumerate(self.string_entries):
                text_to_compare = entry["text"] if self.case_sensitive_var.get() else entry["text"].lower()
                if filter_text in text_to_compare:
                    display_text = entry["text"]
                    if len(display_text) > 20:
                        display_text = display_text[:17] + "..."
                    self.string_tree.insert("", tk.END, values=(
                        i + 1,
                        f"0x{entry['address']:08X}",
                        entry["length"],
                        display_text
                    ))
        else:
            for i, entry in enumerate(self.string_entries):
                display_text = entry["text"]
                if len(display_text) > 20:
                    display_text = display_text[:17] + "..."
                self.string_tree.insert("", tk.END, values=(
                    i + 1,
                    f"0x{entry['address']:08X}",
                    entry["length"],
                    display_text
                ))

    def reload_current_mapping(self):
        if self.current_mapping_data:
            self.load_strings_from_mapping(self.current_mapping_data)

    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("关于 汉化辅助编辑器")
        about_window.geometry("700x600")
        about_window.configure(bg=MODERN_COLORS['bg_primary'])
        about_window.resizable(True, True)

        header_frame = tk.Frame(about_window, bg=MODERN_COLORS['accent_blue'], height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(header_frame, text="汉化辅助编辑器",
                              bg=MODERN_COLORS['accent_blue'], fg='#ffffff',
                              font=("Microsoft YaHei", 18, "bold"), pady=15)
        title_label.pack()

        version_frame = tk.Frame(about_window, bg=MODERN_COLORS['bg_secondary'])
        version_frame.pack(fill=tk.X, pady=10)

        version_label = tk.Label(version_frame, text="版本 8.0  |  [B站偷吃布丁的涅普缇努制作,第四梦境协助修改]",
                                bg=MODERN_COLORS['bg_secondary'], fg=MODERN_COLORS['accent_green'],
                                font=("Microsoft YaHei", 11, "bold"))
        version_label.pack(pady=8)

        info_text = """汉化辅助编辑器

一个简单的二进制文件编辑器


我已经把所有不可打印字符全部改成紫色高亮了

目前我在汉化某些程序的时候会先把0A和0D这种字节替换成20空格,

只有把不可打印字符替换成空格才能框选整段文本,搜索到匹配结果,

此外大家需要注意某些c/c++程序里面经常会出现的%或者&,

%是占位符,占位符通常用于代指命令,会导致你无法搜素到对应文本,&经常和按钮绑定,是个非常缺德的符号,

因为它可能会随机穿插在文本中间,比如File和&可能写成&File,也可能写成F&ile或者Fi&le...


某些程序加壳后会搜索不到字符,或者能搜索到但是替换了之后无法正常显示,比如noesis这个程序,

找不到原作者的源码,替换字节根本没有用处,它的壳保护资源不被修改,所以替换了无效。

挺好的一个模型纹理查看器,可惜了。


还有些程序不支持中文字体,一汉化就乱码,比如Imgui的程序,优先修改为雅黑等支持中文的字体。

废话,编译后能改还用找我吗,在编译前改成雅黑字体,比如Fmodel的3D查看器,我就是改成雅黑后汉化的。

否则你看到的会是???也有些程序无论怎么替换字节都会乱码,比如UE Viewer,这个程序的标题栏汉化会乱码,

非标题栏汉化不会乱码,到现在我都搞不懂这个程序到底是咋回事。

有人问我有什么软件或者工具能突破字符串长度限制，我是这样回答的：

第一，逆向修改，这个我不会。第二，使用源码重新编译这是最靠谱的，但是找不到源码或者找到了源码自

己不会构建这才是一个非常困难的问题。第三，如果是RC窗体程序尝试使用resourcehacker汉化，它可以改

变字符串长度。第四，如果是NET程序，使用dnspy反编译修改，它可以改变字符串长度。第五，如果是WPF

窗体程序，使用UniTranslator可以修改字符串长度并汉化dnspy解决不了的baml二进制文件。第六，如果是

Delphi窗体程序，也可以使用resourcehacker或者localizator尝试汉化。第七，如果是命令行程序或者Qt 

C++程序可以使用我这个汉化辅助编辑器自己手动修改尝试汉化，但是不一定能成功，有些程序修改后会出

错无法运行。第八，hook汉化，内存劫持技术，它可以无视字符串长度，强行在内存中劫持并汉化。


不可打印字符及对应字节:

0x00-NUL(空)  0x01-SOH(标题)  0x02-STX(正文始)  0x03-ETX(正文终)

0x04-EOT(传输终)  0x05-ENQ(询问) 0x06-ACK(确认) 0x07-BEL(响铃)

0x08-BS(退格) 0x09-TAB(制表) 0x0A-LF(换行) 0x0B-VT(垂直制表)

0x0C-FF(换页) 0x0D-CR(回车) 0x0E-SO(移出) 0x0F-SI(移入)

0x10-DLE(转义) 0x11-DC1(设备1) 0x12-DC2(设备2) 0x13-DC3(设备3)

0x14-DC4(设备4) 0x15-NAK(否定) 0x16-SYN(同步) 0x17-ETB(块终)

0x18-CAN(取消) 0x19-EM(介质终) 0x1A-SUB(替换) 0x1B-ESC(转义)

0x1C-FS(文件分) 0x1D-GS(组分) 0x1E-RS(记录分) 0x1F-US(单元分)

0x7F-DEL(删除)


常见标点符号及对应UTF-8字节:

0x20-空格  0x21-!  0x22-"  0x23-#  0x24-$  0x25-%  0x26-&  0x27-'

0x28-(     0x29-)  0x2A-*  0x2B-+  0x2C-,  0x2D--  0x2E-.  0x2F-/

0x3A-:     0x3B-;  0x3C-<  0x3D-=  0x3E->  0x3F-?  0x40-@  0x5B-[

0x5C-\\    0x5D-]  0x5E-^  0x5F-_  0x60-`  0x7B-{  0x7C-|  0x7D-}

0x7E-~          0xA7-§(章节)   0xA9-©(版权)    0xAE-®(商标)

0xB1-±(正负)      0xB5-µ(微)      0xD7-×(乘)     0xF7-÷(除)"""

        text_frame = tk.Frame(about_window, bg=MODERN_COLORS['bg_primary'])
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        text_widget = tk.Text(text_frame, bg=MODERN_COLORS['bg_primary'], fg=MODERN_COLORS['text_primary'],
                             font=("Microsoft YaHei", 10), wrap=tk.WORD, relief=tk.FLAT,
                             highlightthickness=0)
        text_widget.insert(tk.END, info_text)
        text_widget.config(state=tk.DISABLED)
        
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        credit_frame = tk.Frame(about_window, bg=MODERN_COLORS['bg_tertiary'])
        credit_frame.pack(fill=tk.X, pady=0)

        credit_label = tk.Label(credit_frame, text="B站: 偷吃布丁的涅普缇努 | 协助: 第四梦境",
                               bg=MODERN_COLORS['bg_tertiary'], fg=MODERN_COLORS['text_secondary'],
                               font=("Microsoft YaHei", 9), pady=8)
        credit_label.pack()

        about_window.transient(self.root)
        about_window.bind("<Escape>", lambda e: about_window.destroy())
        text_widget.bind("<MouseWheel>", lambda e: text_widget.yview_scroll(int(-1*(e.delta/120)), "units"))

    def validate_input(self, event=None):
        self.update_input_fields_state()
        if self.find_mode == "hex":
            return True

        input_type = self.input_type_var.get()
        input_text = self.find_text.get("1.0", tk.END).strip()

        is_valid = True
        error_msg = ""

        if input_type == "字符串":
            focused_widget = self.root.focus_get()
            if focused_widget == self.find_text:
                is_valid = True
            elif focused_widget == self.find_hex_entry:
                is_valid = self.validate_hex_input()

        elif input_type == "十六进制":
            hex_text = input_text.replace(" ", "")
            if not re.match(r'^[0-9A-Fa-f]+$', hex_text):
                is_valid = False
                error_msg = "十六进制模式下只能输入十六进制字符(0-9,A-F)"
            elif len(hex_text) % 2 != 0:
                is_valid = False
                error_msg = "十六进制字节必须是两位一组"

        if not is_valid:
            self.find_hex_entry.config(foreground="red")
            self.find_hex_entry.delete(0, tk.END)
            self.find_hex_entry.insert(0, error_msg)
            return False
        else:
            self.find_hex_entry.config(foreground="black")
            self.update_display()
            return True

    def validate_hex_input(self, event=None):
        hex_text = self.find_hex_entry.get().strip()
        hex_str = re.sub(r'\s+', '', hex_text).upper()  

        if not hex_str:
            self.find_text.config(state=tk.NORMAL)
            self.find_text.delete("1.0", tk.END)
            self.find_text.config(state=tk.DISABLED)
            return True

        is_valid = True
        error_msg = ""

        if not re.fullmatch(r'^[0-9A-Fa-f]+$', hex_str):
            is_valid = False
            error_msg = "只能输入十六进制字符(0-9,A-F)"
        elif len(hex_str) % 2 != 0:
            is_valid = False
            error_msg = "十六进制字节必须是两位一组"

        if not is_valid:
            self.find_hex_entry.config(foreground="red")
            return False
        else:
            self.find_hex_entry.config(foreground="black")
            try:
                byte_data = bytes.fromhex(hex_str)  
                self.find_text.config(state=tk.NORMAL)
                self.find_text.delete("1.0", tk.END)
                self.find_text.insert("1.0", hex_str)
                self.find_text.config(state=tk.DISABLED)
            except Exception as e:
                self.find_text.config(state=tk.NORMAL)
                self.find_text.delete("1.0", tk.END)
                self.find_text.insert("1.0", f"无法解码:{str(e)}")
                self.find_text.config(state=tk.DISABLED)
            return True

    def validate_replace_input(self, event=None):
        input_type = self.input_type_var.get()
        input_text = self.replace_text.get("1.0", tk.END).strip()

        is_valid = True
        error_msg = ""

        if input_type == "字符串":
            focused_widget = self.root.focus_get()
            if focused_widget == self.replace_text:
                is_valid = True
            elif focused_widget == self.replace_hex_entry:
                is_valid = self.validate_replace_hex_input()

        elif input_type == "十六进制":
            hex_text = input_text.replace(" ", "")
            if not re.match(r'^[0-9A-Fa-f]+$', hex_text):
                is_valid = False
                error_msg = "十六进制模式下只能输入十六进制字符(0-9,A-F)"
            elif len(hex_text) % 2 != 0:
                is_valid = False
                error_msg = "十六进制字节必须是两位一组"

        if not is_valid:
            self.replace_hex_entry.config(foreground="red")
            self.replace_hex_entry.delete(0, tk.END)
            self.replace_hex_entry.insert(0, error_msg)
            return False
        else:
            self.replace_hex_entry.config(foreground="black")
            self.update_replace_display()
            return True

    def validate_replace_hex_input(self, event=None):
        hex_text = self.replace_hex_entry.get().strip()
        hex_text_clean = re.sub(r'\s+', '', hex_text).upper()
        if not hex_text_clean:
            self.replace_text.delete("1.0", tk.END)
            self.replace_hex_entry.config(foreground="black")
            return True

        is_valid = True
        error_msg = ""

        if not re.match(r'^[0-9A-Fa-f]+$', hex_text_clean):
            is_valid = False
            error_msg = "只能输入十六进制字符(0-9,A-F)"
        elif len(hex_text_clean) % 2 != 0:
            is_valid = False
            error_msg = "十六进制字节必须是两位一组"

        if not is_valid:
            self.replace_hex_entry.config(foreground="red")
            return False
        else:
            self.replace_hex_entry.config(foreground="black")
            try:
                formatted_hex = ' '.join([hex_text_clean[i:i+2] for i in range(0, len(hex_text_clean), 2)])
                if formatted_hex != hex_text:
                    self.replace_hex_entry.delete(0, tk.END)
                    self.replace_hex_entry.insert(0, formatted_hex)
                byte_data = bytes.fromhex(hex_text_clean)
                self.replace_text.delete("1.0", tk.END)
                self.replace_text.insert("1.0", hex_text_clean)
            except Exception as e:
                self.replace_text.delete("1.0", tk.END)
                self.replace_text.insert("1.0", f"无法解码:{str(e)}")
            return True

    def input_to_bytes(self, input_str, encoding=None):
        try:
            if self.input_type_var.get() == "字符串" or self.find_mode == "text":
                target_encoding = encoding or self.encoding_var.get()
                return input_str.encode(target_encoding)
            else:
                hex_str = re.sub(r'\s+', '', input_str).upper()  
                return bytes.fromhex(hex_str)
        except Exception as e:
            self.update_status(f"输入转换错误:{str(e)}")
            return None

    def bytes_to_display(self, byte_data, encoding=None):
        if not encoding:
            encoding = self.encoding_var.get()

        try:
            decoded = byte_data.decode(encoding)
            return f"{decoded} ({bytes_to_hex(byte_data)})"
        except UnicodeDecodeError:
            return bytes_to_hex(byte_data)

    def update_display(self, event=None):
        if self.find_mode == "hex":
            return

        input_type = self.input_type_var.get()
        find_str = self.find_text.get("1.0", tk.END).strip()
        encoding = self.encoding_var.get()

        if not find_str:
            self.find_hex_entry.delete(0, tk.END)
            return

        try:
            byte_data = self.input_to_bytes(find_str, encoding)
            if byte_data:
                self.find_hex_entry.delete(0, tk.END)
                self.find_hex_entry.insert(0, bytes_to_hex(byte_data))
        except Exception as e:
            self.find_hex_entry.delete(0, tk.END)
            self.find_hex_entry.insert(0, f"转换错误:{str(e)}")

    def update_replace_display(self, event=None):
        input_type = self.input_type_var.get()
        replace_str = self.replace_text.get("1.0", tk.END).strip()
        encoding = self.encoding_var.get()

        if not replace_str:
            self.replace_hex_entry.delete(0, tk.END)
            return

        try:
            byte_data = self.input_to_bytes(replace_str, encoding)
            if byte_data:
                self.replace_hex_entry.delete(0, tk.END)
                self.replace_hex_entry.insert(0, bytes_to_hex(byte_data))
        except Exception as e:
            self.replace_hex_entry.delete(0, tk.END)
            self.replace_hex_entry.insert(0, f"转换错误:{str(e)}")

    def find_matches(self):
        if not self.file_data:
            return
        if len(self.file_data) > 100 * 1024 * 1024:
            result = messagebox.askyesno("警告", "文件较大,搜索可能需要较长时间,是否继续？")
            if not result:
                return

        if self.find_mode == "text" and not self.validate_input():
            return
        elif self.find_mode == "hex" and not self.validate_hex_input():
            return

        find_str = self.find_text.get("1.0", tk.END).strip() if self.find_mode == "text" else self.find_hex_entry.get().strip()

        if not find_str:
            self.update_status("请输入查找内容")
            return

        encoding = self.encoding_var.get()
        find_bytes = self.input_to_bytes(find_str, encoding)

        if not find_bytes:
            self.update_status("输入内容无法转换为字节")
            return

        self.clear_matches()
        matches = []

        if isinstance(find_bytes, list) and None in find_bytes:
            pattern_length = len(find_bytes)
            data_length = len(self.file_data)
            for i in range(data_length - pattern_length + 1):
                match = True
                for j, byte in enumerate(find_bytes):
                    if byte is None:
                        continue
                    if self.file_data[i + j] != byte:
                        match = False
                        break
                if match:
                    matches.append({
                        "pos": i,
                        "bytes": self.file_data[i:i+pattern_length]
                    })
        else:
            if isinstance(find_bytes, list):
                find_bytes = bytes([b for b in find_bytes if b is not None])
            start = 0
            while True:
                pos = self.file_data.find(find_bytes, start)
                if pos == -1:
                    break
                matches.append({
                    "pos": pos,
                    "bytes": find_bytes
                })
                start = pos + 1

        self.current_matches = matches

        if matches:
            self.update_status(f"找到{len(matches)}个匹配项")
            self.current_match_index = 0
            match = self.current_matches[self.current_match_index]
            self.hex_viewer.highlight_range(match["pos"], match["pos"] + len(match["bytes"]) - 1)
            self.hex_viewer.scroll_to_address(match["pos"])
        else:
            self.update_status("未找到匹配项") 

    def find_next(self):
        if not self.current_matches:
            self.find_matches()
            return

        if self.current_match_index < len(self.current_matches) - 1:
            self.current_match_index += 1
        else:
            self.current_match_index = 0

        match = self.current_matches[self.current_match_index]
        self.hex_viewer.highlight_range(match["pos"], match["pos"] + len(match["bytes"]) - 1)
        self.hex_viewer.scroll_to_address(match["pos"])
        self.update_input_fields_state()

    def find_prev(self):
        if not self.current_matches:
            self.find_matches()
            return

        if self.current_match_index > 0:
            self.current_match_index -= 1
        else:
            self.current_match_index = len(self.current_matches) - 1

        match = self.current_matches[self.current_match_index]
        self.hex_viewer.highlight_range(match["pos"], match["pos"] + len(match["bytes"]) - 1)
        self.hex_viewer.scroll_to_address(match["pos"])
        self.update_input_fields_state()

    def clear_matches(self):
        self.current_matches = []
        self.current_match_index = -1

    def update_status(self, message):
        try:
            if hasattr(self, 'status_bar') and self.status_bar.winfo_exists():
                self.status_bar.config(text=message)

                if '错误' in message or '失败' in message:
                    self.status_bar.config(fg=MODERN_COLORS['error'], bg=MODERN_COLORS['accent_blue'])
                elif '成功' in message or '完成' in message:
                    self.status_bar.config(fg=MODERN_COLORS['success'], bg=MODERN_COLORS['accent_blue'])
                elif '警告' in message or '请' in message:
                    self.status_bar.config(fg=MODERN_COLORS['warning'], bg=MODERN_COLORS['accent_blue'])
                else:
                    self.status_bar.config(fg='#ffffff', bg=MODERN_COLORS['accent_blue'])

                self.status_bar.update_idletasks()
        except Exception as e:
            print(f"状态栏更新失败:{e}")

    def undo(self):
        if self.history_index <= 0:
            self.update_status("无法撤销:已处于最初状态")
            return
        self.history_index -= 1
        self._load_history_state()
        self.update_status(f"已撤销到状态{self.history_index + 1}/{len(self.history)}")

    def redo(self):
        if self.history_index >= len(self.history) - 1:
            self.update_status("无法重做:已处于最新状态")
            return
        self.history_index += 1
        self._load_history_state()
        self.update_status(f"已重做到状态{self.history_index + 1}/{len(self.history)}")

    def save_history_state(self):
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]
        self.history.append(copy.copy(self.file_data))
        self.history_index = len(self.history) - 1

        if self.max_history_items > 0 and len(self.history) > self.max_history_items:
            self.history.pop(0)
            self.history_index -= 1

        self.update_status(f"当前状态已保存(共{len(self.history)}个历史状态)")

    def _load_history_state(self):
        if 0 <= self.history_index < len(self.history):
            self.file_data = copy.copy(self.history[self.history_index])
            self.hex_viewer.set_data(self.file_data)
            self.hex_viewer.update_view()
            self.root.update_idletasks()
            self.update_status(f"当前状态:{self.history_index + 1}/{len(self.history)}")
        else:
            self.update_status("历史状态索引错误")

    def _replace_at_position(self, pos, find_bytes, replace_bytes):
        original_length = len(find_bytes)
        replace_length = len(replace_bytes)
        encoding = self.encoding_var.get()
        
        if encoding in ['utf-16le', 'utf-16be'] and (original_length - replace_length) % 2 != 0:
            padding_length = original_length - replace_length
            if padding_length % 2 != 0:
                padding_length += 1
        
        if replace_length > original_length:
            if encoding in ['utf-8', 'gbk', 'gb2312', 'big5']:
                excess_bytes = replace_length - original_length
                available_zero_bytes = self._count_trailing_zero_bytes(pos + original_length)
                if available_zero_bytes >= excess_bytes + 1:
                    for i in range(replace_length):
                        self.file_data[pos + i] = replace_bytes[i]
                    return True, bytes_to_hex(replace_bytes)
                else:
                    return False, f"需要{excess_bytes}字节扩展,但后面只有{available_zero_bytes}个连续00字节"
            else:
                excess_bytes = replace_length - original_length
                return False, f"替换内容比查找内容多{excess_bytes}字节"
        
        if replace_length < original_length:
            padding = self.get_padding_bytes(original_length - replace_length)
            replace_bytes = replace_bytes + padding
        
        for i in range(len(replace_bytes)):
            self.file_data[pos + i] = replace_bytes[i]
        
        return True, bytes_to_hex(replace_bytes)
    
    def _count_trailing_zero_bytes(self, start_pos):
        count = 0
        max_count = 100
        while start_pos + count < len(self.file_data) and count < max_count:
            if self.file_data[start_pos + count] == 0x00:
                count += 1
            else:
                break
        return count

    def replace_current(self):
        if self.current_match_index < 0 or self.current_match_index >= len(self.current_matches):
            self.update_status("没有选中的匹配项")
            return
        replace_str = self.replace_text.get("1.0", tk.END).strip()
        if not replace_str:
            self.update_status("请输入替换内容")
            return
        match = self.current_matches[self.current_match_index]
        pos = match["pos"]
        original_bytes = match["bytes"]
        encoding = self.encoding_var.get()
        replace_bytes = self.input_to_bytes(replace_str, encoding)
        if not replace_bytes:
            return
        success, result = self._replace_at_position(pos, original_bytes, replace_bytes)
        if not success:
            messagebox.showerror("替换失败", f"无法替换位置0x{pos:08X}的内容:\n{result}")
            self.update_status(f"替换失败:{result}")
            return
        match["bytes"] = bytes.fromhex(result.replace(" ", ""))
        self.hex_viewer.set_data(self.file_data)
        self.hex_viewer.highlight_range(pos, pos + len(match["bytes"]) - 1)
        self._clear_input_fields()
        self.update_translation_in_entries(pos, replace_str)
        self.update_status(f"已替换位置0x{pos:08X}的内容")
        self.save_history_state()
        self.pending_changes = True
        self.update_status(f"已替换,请记得保存文件以同步映射")

    def update_translation_in_entries(self, address, translated_text):
        for entry in self.string_entries:
            if entry['address'] == address:
                entry['translated_text'] = translated_text
                entry['text'] = translated_text
            
                for item in self.string_tree.get_children():
                    values = self.string_tree.item(item, "values")
                    if len(values) >= 4 and int(values[0]) == entry['id']:
                        display_text = translated_text
                        if len(display_text) > 20:
                            display_text = display_text[:17] + "..."
                        self.string_tree.item(item, values=(
                            entry['id'],
                            f"0x{entry['address']:08X}",
                            entry['length'],
                            display_text
                        ))
                        break
                break        
        self.save_current_mapping()

    def save_current_mapping(self):
        if not self.file_path or not self.current_scan_mode:
            return
        
        if not self.string_entries:
            return
        
        mapping_file = self.get_mapping_file_path(self.current_scan_mode)
        if not mapping_file:
            return
        
        try:
            import json
            
            mapping_data = {
                'file_path': self.file_path,
                'file_name': os.path.basename(self.file_path),
                'file_size': len(self.file_data),
                'scan_mode': self.current_scan_mode,
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'encoding': self.get_encoding_for_scan_mode(self.current_scan_mode),
                'strings': []
            }
            
            for entry in self.string_entries:
                mapping_data['strings'].append({
                    'id': entry['id'],
                    'address': entry['address'],
                    'address_hex': f"0x{entry['address']:08X}",
                    'length': entry['length'],
                    'original_text': entry.get('original_text', entry.get('text', '')),
                    'translated_text': entry.get('translated_text', ''),
                    'bytes_hex': bytes_to_hex(entry.get('bytes', b'')),
                    'encoding': entry.get('encoding', 'unknown')
                })
            
            with open(mapping_file, 'w', encoding='utf-8') as f:
                json.dump(mapping_data, f, ensure_ascii=False, indent=2)
            
            self.pending_changes = False
            self.update_status(f"映射已更新:{os.path.basename(mapping_file)}")
            
        except Exception as e:
            self.update_status(f"保存映射失败:{str(e)}")

    def replace_all(self):
        if not self.current_matches:
            self.update_status("没有匹配项可替换")
            return

        find_str = self.find_text.get("1.0", tk.END).strip() if self.find_mode == "text" else self.find_hex_entry.get().strip()
        replace_str = self.replace_text.get("1.0", tk.END).strip()

        if not find_str or not replace_str:
            self.update_status("请输入查找内容和替换内容")
            return

        find_bytes = self.input_to_bytes(find_str)
        replace_bytes = self.input_to_bytes(replace_str)

        if not find_bytes or not replace_bytes:
            return

        failed_positions = []
        replaced_positions = [] 
        for match in sorted(self.current_matches, key=lambda x: x["pos"], reverse=True):
            pos = match["pos"]
            original_bytes = find_bytes
            success, result = self._replace_at_position(pos, original_bytes, replace_bytes)
            if success:
                match["bytes"] = bytes.fromhex(result.replace(" ", ""))
            else:
                failed_positions.append(f"0x{pos:08X}: {result}")
        for pos, translated_text in replaced_positions:
            self.update_translation_in_entries(pos, translated_text)
        if failed_positions:
            failed_text = "\n".join(failed_positions)
            messagebox.showwarning("部分替换失败", f"以下位置无法替换:\n{failed_text}")
        self._clear_input_fields()
        self.find_matches()
        self.hex_viewer.set_data(self.file_data)
        success_count = len(self.current_matches) - len(failed_positions)
        self.update_status(f"已替换{success_count}个匹配项")
        self.save_history_state()
        if success_count > 0:
            self.pending_changes = True
            self.update_status(f"已替换{success_count}个字符串,请记得保存文件以同步映射")

    def _clear_input_fields(self):
        self.find_text.config(state=tk.NORMAL)
        self.find_text.delete("1.0", tk.END)
        self.find_hex_entry.delete(0, tk.END)
        self.replace_text.delete("1.0", tk.END)
        self.replace_hex_entry.delete(0, tk.END)
        self.find_mode = "text"
        self.input_type_var.set("字符串")
        self.update_input_fields_state()

    def get_padding_bytes(self, length):
        encoding = self.encoding_var.get()
        if encoding == 'utf-8' or encoding == 'gbk':
            return bytes([0x20] * length)
        elif encoding == 'utf-16le':
            if length % 2 != 0:
                length += 1
            return bytes([0x20, 0x00] * (length // 2))
        elif encoding == 'utf-16be':
            if length % 2 != 0:
                length += 1
            return bytes([0x00, 0x20] * (length // 2))
        return bytes([0x20] * length)

class HexViewer:
    def __init__(self, master, width=70, height=12, app=None):
        self.master = master
        self.app = app
        self.width = width
        self.height = height
        self.bytes_per_line = 16
        self.current_encoding = 'utf-8'
        self.scroll_command = None
        self.bytes_per_line_options = [16, 32, 48]
        self.byte_colors = {
            0x0A: 'blue',     
            0x0D: 'purple',   
            0x00: 'red',      
            0xFF: 'pink',    
            0x20: 'green',   
        }

        self.utf16_colors = {
            (0x0A, 0x00): 'blue',    
            (0x00, 0x0A): 'blue',    
            (0x0D, 0x00): 'purple', 
            (0x00, 0x0D): 'purple',  
            (0x00, 0x00): 'red',    
            (0xFF, 0xFF): 'pink',    
            (0x20, 0x00): 'green',  
            (0x00, 0x20): 'green',   
        }
        self.non_printable_color = 'purple'
        self.data = bytearray()
        self.base_font = ("Consolas", 9)
        self.current_font = self.base_font
        self.create_widgets()

        self.start_address = 0
        self.highlight_start = -1
        self.highlight_end = -1
        self.sidebar_width = 300
        self.hex_text.bind("<MouseWheel>", self._on_mousewheel)
        self.ascii_text.bind("<MouseWheel>", self._on_mousewheel)
        self.hex_text.bind("<Button-3>", self.on_hex_right_click)
        self.ascii_text.bind("<Button-3>", self.on_ascii_right_click)
        self.hex_text.bind("<Button-4>", self._on_mousewheel)
        self.hex_text.bind("<Button-5>", self._on_mousewheel)
        self.ascii_text.bind("<Button-4>", self._on_mousewheel)
        self.ascii_text.bind("<Button-5>", self._on_mousewheel)
        self.context_menu = None
        self.create_context_menu()
        self.right_click_pos = None
        self.right_click_byte = None
        self.window_width_config = {
            8: 800,
            16: 1000,
            32: "two_thirds",
            48: "full"
        }
        self.initial_window_size = None

    def get_available_lines(self):
        if not self.master.winfo_exists():
            return self.initial_height  
        self.master.update_idletasks()
        frame_height = self.master.winfo_height()  
        if frame_height <= 0:
            return self.initial_height   
        font = tkfont.Font(font=self.hex_text.cget("font"))
        line_height = font.metrics("linespace")   
        if line_height <= 0:
            line_height = 20   
        available_lines = max(10, (frame_height // line_height) - 2)
        return available_lines

    def set_scroll_command(self, command):
        self.scroll_command = command
        self.hex_text.config(yscrollcommand=command)
        self.address_text.config(yscrollcommand=command)
        self.ascii_text.config(yscrollcommand=command)

    def set_font(self, font):
        self.current_font = font
        self.address_text.config(font=font)
        self.hex_text.config(font=font)
        self.ascii_text.config(font=font)
        self.update_view()

    def set_data(self, data):
        self.data = data
        self.update_view()

    def set_scrollbar(self, scroll_command):
        self.hex_text.config(yscrollcommand=scroll_command)
        self.ascii_text.config(yscrollcommand=scroll_command)

    def yview(self, *args):
        self.hex_text.yview(*args)
        self.ascii_text.yview(*args)

    def create_widgets(self):
        frame = tk.Frame(self.master, bg=MODERN_COLORS['bg_secondary'])
        frame.pack(fill=tk.BOTH, expand=True)

        byte_options_frame = tk.Frame(frame, bg=MODERN_COLORS['bg_tertiary'])
        byte_options_frame.pack(fill=tk.X, pady=(0, 2))

        tk.Label(byte_options_frame, text="每行字节数:", bg=MODERN_COLORS['bg_tertiary'],
                fg=MODERN_COLORS['text_primary'], font=("Microsoft YaHei", 10)).pack(side=tk.LEFT, padx=10)

        for option in self.bytes_per_line_options:
            btn = tk.Button(byte_options_frame, text=str(option),
                           command=lambda opt=option: self.set_bytes_per_line(opt),
                           bg=MODERN_COLORS['bg_secondary'], fg=MODERN_COLORS['text_primary'],
                           relief=tk.FLAT, activebackground=MODERN_COLORS['accent_blue'],
                           activeforeground='#ffffff', font=("Consolas", 10), padx=10)
            btn.pack(side=tk.LEFT, padx=2)

        self.address_text = tk.Text(frame, width=10, height=self.height, wrap=tk.NONE,
                                    font=("Consolas", 9), state=tk.DISABLED,
                                    bg=MODERN_COLORS['bg_primary'], fg=MODERN_COLORS['accent_yellow'],
                                    insertbackground=MODERN_COLORS['accent_green'],
                                    relief=tk.FLAT, borderwidth=0)
        self.address_text.pack(side=tk.LEFT, fill=tk.Y)

        self.hex_text = tk.Text(frame, width=70, height=self.height, wrap=tk.NONE,
                                font=("Consolas", 9), state=tk.DISABLED,
                                bg=MODERN_COLORS['bg_primary'], fg=MODERN_COLORS['text_primary'],
                                insertbackground=MODERN_COLORS['accent_green'],
                                relief=tk.FLAT, borderwidth=0)
        self.hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.ascii_text = tk.Text(frame, width=self.bytes_per_line, height=self.height, wrap=tk.NONE,
                                  font=("Consolas", 9), state=tk.DISABLED,
                                  bg=MODERN_COLORS['bg_primary'], fg=MODERN_COLORS['accent_orange'],
                                  insertbackground=MODERN_COLORS['accent_green'],
                                  relief=tk.FLAT, borderwidth=0)
        self.ascii_text.pack(side=tk.LEFT, fill=tk.Y)

        self.vscrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                                        command=self._on_scroll)
        self.vscrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.hex_text.config(yscrollcommand=self._on_scrollbar)
        self.address_text.config(yscrollcommand=self.vscrollbar.set)
        self.ascii_text.config(yscrollcommand=self.vscrollbar.set)

        self.hex_text.tag_configure("highlight", background=MODERN_COLORS['highlight'], foreground='#ffffff')
        self.ascii_text.tag_configure("highlight", background=MODERN_COLORS['highlight'], foreground='#ffffff')
        self.hex_text.tag_configure("non_printable", foreground=MODERN_COLORS['accent_purple'])
        self.ascii_text.tag_configure("non_printable", foreground=MODERN_COLORS['accent_purple'])

        modern_byte_colors = {
            0x0A: '#569cd6',
            0x0D: '#c586c0',
            0x00: '#f14c4c',
            0xFF: '#ff79c6',
            0x20: '#50fa7b',
        }

        for byte_value, color in modern_byte_colors.items():
            self.hex_text.tag_configure(f"byte_{byte_value:02X}", foreground=color)
            self.ascii_text.tag_configure(f"byte_{byte_value:02X}", foreground=color)
        for (byte1, byte2), color in self.utf16_colors.items():
            self.hex_text.tag_configure(f"utf16_{byte1:02X}{byte2:02X}", foreground=color)
            self.ascii_text.tag_configure(f"utf16_{byte1:02X}{byte2:02X}", foreground=color)
    def set_bytes_per_line(self, bytes_per_line):
        current_pos = self.start_address
        self.bytes_per_line = bytes_per_line
        self.ascii_text.config(width=self.bytes_per_line)
        self.update_view()
        self.scroll_to_address(current_pos)
        self.adjust_window_width(bytes_per_line)

    def adjust_window_width(self, bytes_per_line):
        if not self.app or not hasattr(self.app, 'sidebar_frame'):
            return   
        current_window_width = self.app.root.winfo_width()
        current_window_height = self.app.root.winfo_height()  
        screen_width = self.app.root.winfo_screenwidth()
        sidebar_width = 300  
        if bytes_per_line == 48:
            left_width = screen_width - sidebar_width - 100
        elif bytes_per_line == 32:
            left_width = int(screen_width * 2 / 3)
        else:
            left_width = 1000  
        left_width = max(left_width, 600)   
        new_window_width = left_width + sidebar_width + 50
        self.app.root.geometry(f"{new_window_width}x{current_window_height}")   
        hex_width = bytes_per_line * 3
        self.hex_text.config(width=hex_width)   
        self.app.update_status(f"已切换到每行{bytes_per_line}字节模式，十六进制视图宽度已调整")

    def _on_scrollbar(self, *args):
        self.vscrollbar.set(*args)

    def set_encoding(self, encoding):
        self.current_encoding = encoding
        self.update_view()
    def update_view(self):
        if not self.data:
            return
        self.address_text.config(state=tk.NORMAL)
        self.hex_text.config(state=tk.NORMAL)
        self.ascii_text.config(state=tk.NORMAL)

        self.address_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        self.ascii_text.delete(1.0, tk.END)

        actual_height = self.get_available_lines()
        if actual_height > 0:
            self.current_height = actual_height
        max_lines = min(self.current_height, 
                       (len(self.data) - self.start_address + self.bytes_per_line - 1) // self.bytes_per_line)

        actual_data_lines = (len(self.data) + self.bytes_per_line - 1) // self.bytes_per_line
        if actual_data_lines < max_lines:
            max_lines = actual_data_lines
        for i in range(max_lines):
            line_addr = self.start_address + i * self.bytes_per_line
            self.address_text.insert(tk.END, f"{line_addr:08X}\n")

            line_data = self.data[line_addr:line_addr + self.bytes_per_line]

            for j, byte in enumerate(line_data):
                byte_addr = line_addr + j
                is_highlighted = (self.highlight_start <= byte_addr <= self.highlight_end) 

                hex_value = f"{byte:02X} "
                if self.current_encoding in ['utf-16le', 'utf-16be']:
                    if j % 2 == 0 and j + 1 < len(line_data):
                        pair = line_data[j:j+2]
                        try:
                            char = pair.decode(self.current_encoding)
                            ascii_char = char if char.isprintable() else "."
                        except UnicodeDecodeError:
                            ascii_char = "."
                    else:
                        ascii_char = ""
                else:
                    ascii_char = chr(byte) if 32 <= byte <= 126 else "."

                utf16_pair = None
                if self.current_encoding in ['utf-16le', 'utf-16be']:
                    if j + 1 < len(line_data):
                        next_byte = line_data[j + 1]
                        utf16_pair = (byte, next_byte) if (byte, next_byte) in self.utf16_colors else None

                self.hex_text.insert(tk.END, hex_value)
                if utf16_pair and self.current_encoding in ['utf-16le', 'utf-16be']:
                    self.hex_text.tag_add(f"utf16_{utf16_pair[0]:02X}{utf16_pair[1]:02X}", 
                    f"{i+1}.{j*3}", f"{i+1}.{j*3+2}")
                elif byte in self.byte_colors:
                    self.hex_text.tag_add(f"byte_{byte:02X}", 
                    f"{i+1}.{j*3}", f"{i+1}.{j*3+2}")
                else:
                    is_non_printable = not (32 <= byte <= 126) and byte != 0x20
                    if is_non_printable:
                        self.hex_text.tag_add("non_printable", 
                            f"{i+1}.{j*3}", f"{i+1}.{j*3+2}")

                self.ascii_text.insert(tk.END, ascii_char)
                if utf16_pair and self.current_encoding in ['utf-16le', 'utf-16be']:
                    self.ascii_text.tag_add(f"utf16_{utf16_pair[0]:02X}{utf16_pair[1]:02X}", 
                        f"{i+1}.{j}", f"{i+1}.{j}+1c")
                elif byte in self.byte_colors:
                    self.ascii_text.tag_add(f"byte_{byte:02X}", 
                        f"{i+1}.{j}", f"{i+1}.{j}+1c")
                else:
                    is_non_printable = not (32 <= byte <= 126) and byte != 0x20
                    if is_non_printable:
                        self.ascii_text.tag_add("non_printable", 
                            f"{i+1}.{j}", f"{i+1}.{j}+1c")
                if is_highlighted:
                    hex_start = f"{i+1}.{j*3}"
                    hex_end = f"{i+1}.{j*3+2}"
                    ascii_pos = f"{i+1}.{j}"
                    self.hex_text.tag_add("highlight", hex_start, hex_end)
                    self.ascii_text.tag_add("highlight", ascii_pos, f"{ascii_pos}+1c")

            if i < max_lines - 1:
                self.hex_text.insert(tk.END, "\n")
                self.ascii_text.insert(tk.END, "\n")

        self.address_text.config(state=tk.DISABLED)
        self.hex_text.config(state=tk.DISABLED)
        self.ascii_text.config(state=tk.DISABLED)

        total_lines = (len(self.data) + self.bytes_per_line - 1) // self.bytes_per_line
        if total_lines > 0:
            first_line = self.start_address // self.bytes_per_line
            visible_lines = self.current_height
            self.vscrollbar.set(first_line / total_lines, (first_line + visible_lines) / total_lines)

    def _on_scroll(self, *args):
        if not hasattr(self, 'data') or not self.data:
            return
        if len(args) == 2:
            action, value = args
            total_lines = (len(self.data) + self.bytes_per_line - 1) // self.bytes_per_line
            visible_lines = self.height
            if action == "moveto":
                fraction = float(value)
                new_line = int(fraction * max(0, total_lines - visible_lines))
                self.start_address = new_line * self.bytes_per_line
            elif action == "scroll":
                count, unit = value.split()
                count = int(count)
                if unit == "units":
                    scroll_amount = count * self.bytes_per_line
                elif unit == "pages":
                    scroll_amount = count * self.bytes_per_line * visible_lines
                self.start_address += scroll_amount
            self.start_address = max(0, min(self.start_address, len(self.data) - self.bytes_per_line * visible_lines))
            self.update_view()
        elif args:
            self.address_text.yview(*args)
            self.hex_text.yview(*args)
            self.ascii_text.yview(*args)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.master, tearoff=0, bg=MODERN_COLORS['bg_secondary'],
                                   fg=MODERN_COLORS['text_primary'],
                                   activebackground=MODERN_COLORS['accent_blue'],
                                   activeforeground='#ffffff',
                                   font=("Microsoft YaHei", 10))
        self.context_menu.add_command(label="✏️ 修改为空格 (0x20)", command=self.convert_to_space)
        self.context_menu.add_command(label="➕ 插入字节", command=self.insert_bytes)
        self.context_menu.add_command(label="➖ 删除字节", command=self.delete_bytes)
        self.context_menu.add_command(label="📤 导出指定范围字节", command=self.export_range_bytes)
        self.context_menu.add_separator()
    def on_hex_right_click(self, event):
        if not hasattr(self, 'data') or not self.data:
            return

        x = event.x
        y = event.y

        font = tkfont.Font(font=self.hex_text.cget("font"))
        char_width = font.measure("0") 
        line_height = font.metrics("linespace") 

        line = int(y // line_height)
        col = int(x // char_width)
        byte_index_in_line = col // 3 

        byte_pos = self.start_address + line * self.bytes_per_line + byte_index_in_line

        if 0 <= byte_pos < len(self.data):
            self.right_click_pos = byte_pos
            self.right_click_byte = self.data[byte_pos]
            self.highlight_range(byte_pos, byte_pos)
            self.context_menu.post(event.x_root, event.y_root)

    def on_ascii_right_click(self, event):
        if not hasattr(self, 'data') or not self.data:
            return

        x = event.x
        y = event.y

        font = tkfont.Font(font=self.ascii_text.cget("font"))
        char_width = font.measure("0")
        line_height = font.metrics("linespace")

        line = int(y // line_height)
        col = int(x // char_width)

        byte_pos = self.start_address + line * self.bytes_per_line + col

        if 0 <= byte_pos < len(self.data):
            self.right_click_pos = byte_pos
            self.right_click_byte = self.data[byte_pos]
            self.highlight_range(byte_pos, byte_pos)
            self.context_menu.post(event.x_root, event.y_root)
    def insert_bytes(self):
        if self.app:
            self.app.insert_bytes()

    def delete_bytes(self):
        if self.app:
            self.app.delete_bytes()

    def reset_highlight(self):
        self.highlight_start = -1
        self.highlight_end = -1
        self.update_view()
    def export_range_bytes(self):
        if self.app:
            self.app.export_range_bytes()
    def convert_to_space(self):
        if self.right_click_pos is not None:
            self.data[self.right_click_pos] = 0x20
            self.update_view()
            if hasattr(self.master, 'master') and hasattr(self.master.master, 'file_data'):
                self.master.master.file_data = self.data
                self.master.master.save_history_state()
            original_hex = f"{self.right_click_byte:02X}"
            message = f"已将位置0x{self.right_click_pos:08X}的字节{original_hex}修改为20(空格)"
            if hasattr(self.master, 'master') and hasattr(self.master.master, 'update_status'):
                self.master.master.update_status(message)
            else:
                print(message)
    def _on_mousewheel(self, event):
        if not hasattr(self, 'data') or not self.data:
            return

        if event.num == 4 or (hasattr(event, 'delta') and event.delta > 0):
            self.start_address = max(0, self.start_address - self.bytes_per_line)
        else:
            max_address = len(self.data) - self.bytes_per_line * self.height
            self.start_address = min(max_address, self.start_address + self.bytes_per_line)
        self.update_view()
        total_lines = (len(self.data) + self.bytes_per_line - 1) // self.bytes_per_line
        if total_lines > 0:
            first_line = self.start_address // self.bytes_per_line
            visible_lines = self.height
            self.vscrollbar.set(first_line / total_lines, (first_line + visible_lines) / total_lines)
        return "break"

    def scroll_to_address(self, address):
        line_num = address // self.bytes_per_line
        visible_lines = self.height

        new_start_line = max(0, line_num - visible_lines // 2)
        self.start_address = new_start_line * self.bytes_per_line

        self.update_view()

    def highlight_range(self, start, end):
        if end < start:
            end = start
        if self.current_encoding in ['utf-16le', 'utf-16be']:
            if start % 2 != 0:
                start = max(0, start - 1)
            if (end + 1) % 2 != 0:
                end = min(len(self.data) - 1, end + 1)
        self.highlight_start = start
        self.highlight_end = end
        self.update_view()

def bytes_to_hex(byte_data):
    return ' '.join([f"{b:02X}" for b in byte_data])

def get_config_file_path():
    app_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(app_dir, 'editor_config.json')

def load_config():
    config_file = get_config_file_path()
    default_config = {
        'theme': 'dark',
        'encoding': 'utf-8',
        'scan_mode': 'ansi',
        'input_type': '字符串'
    }
    if os.path.exists(config_file):
        try:
            import json
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return {**default_config, **config}
        except Exception:
            return default_config
    return default_config

def save_config(config):
    config_file = get_config_file_path()
    try:
        import json
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存配置失败: {e}")

if __name__ == "__main__":
    config = load_config()
    
    if config.get('theme') == 'light':
        MODERN_COLORS = MODERN_COLORS_LIGHT
        CURRENT_THEME = 'light'
    else:
        MODERN_COLORS = MODERN_COLORS_DARK
        CURRENT_THEME = 'dark'
    
    try:
        tkinterdnd2 = __import__('tkinterdnd2')
        TkinterDnD = getattr(tkinterdnd2, 'TkinterDnD')
        root = TkinterDnD.Tk()
    except ImportError:
        import tkinter as tk
        root = tk.Tk()
        print("警告:tkinterdnd2未安装,拖拽功能将不可用")
    
    app = BinaryEditorApp(root, config=config)
    
    app.switch_theme(CURRENT_THEME)
    
    root.mainloop()
