import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import re
import copy
from datetime import datetime
import tkinter.font as tkfont
from tkinter import simpledialog

class BinaryEditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("汉化辅助编辑器")
        self.root.geometry("1200x1000")
        self.root.minsize(800, 600)
        self.root.option_add("*Font", "SimSun 11")

        self.max_input_length = 500      
        self.extended_threshold = 200  
        self.max_extended_lines = 10      
        self.initial_height = 4

        self.file_path = ""
        self.file_data = bytearray()
        self.original_data = None
        self.history = []
        self.history_index = 0
        self.max_history_items = 50

        self.current_matches = []
        self.current_match_index = -1
        self.current_find_text = "" 
        self.find_mode = "text"

        self.replace_buttons_disabled = False
        self.replace_buttons_clicked = False 

        self.input_type_options = ['字符串', '十六进制']
        self.input_type_var = tk.StringVar(value=self.input_type_options[0])
        self.replace_type_var = tk.StringVar(value=self.input_type_options[0])

        self.encoding_options = [
        'utf-8', 'gbk', 'utf-16le', 'utf-16be', 
        'shift_jis', 'euc-jp', 'big5', 'gb2312', 
        'iso-8859-1', 'utf-7', 'ascii', 'latin1'
        ]
        self.encoding_var = tk.StringVar(value=self.encoding_options[0])

        self.menubar = tk.Menu(self.root)
        self.root.config(menu=self.menubar)
        self.create_widgets()

        self.setup_drag_and_drop()
    
        self.update_status("就绪-请打开文件或拖拽文件到窗口") 

    def setup_drag_and_drop(self):
        try:
            from tkinterdnd2 import DND_FILES
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self.on_drop_advanced)
            print("使用tkinterdnd2拖拽支持")
        
        except ImportError:
            print("tkinterdnd2未安装，拖拽功能不可用")
        except Exception as e:
            print(f"拖拽功能初始化失败:{e}")

    def on_drag_enter(self, event):
        self.root.config(cursor='hand2')
        return tk.ACTION_COPY

    def on_drag_leave(self, event):
        self.root.config(cursor='')
        return tk.ACTION_COPY

    def on_drop_basic(self, event):
        self.root.config(cursor='')
        files = self.root.tk.splitlist(event.data)
        if files:
            self.process_dropped_file(files[0])

    def on_drop_advanced(self, event):
        try:
            file_path = event.data.strip('{}')
            self.process_dropped_file(file_path)
        except Exception as e:
            messagebox.showerror("错误", f"处理拖拽文件时出错: {str(e)}")

    def process_dropped_file(self, file_path):
        if os.path.isfile(file_path):
            self.open_file_with_path(file_path)
        else:
            messagebox.showerror("错误", "请拖拽有效的文件")

    def export_ascii_text(self):
        if not self.file_data:
            messagebox.showwarning("警告", "请先打开文件")
            return
    
        file_path = filedialog.asksaveasfilename(
            title="导出ASCII文本",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
    
        if not file_path:
            return
    
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("# 汉化辅助编辑器-ASCII文本导出\n")
                f.write(f"# 文件:{os.path.basename(self.file_path)}\n")
                f.write(f"# 导出时间:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 编码:{self.encoding_var.get()}\n")
                f.write("# 格式:地址|长度|文本内容\n")
                f.write("#" + "="*50 + "\n\n")
            
                text_segments = self.find_all_text_segments()
            
                for segment in text_segments:
                    start_addr = segment["start"]
                    end_addr = segment["end"]
                    text_content = segment["text"]
                    byte_length = segment["length"]
                
                    f.write(f"{start_addr:08X}|{byte_length:04d}|{text_content}\n")
        
            self.update_status(f"已导出{len(text_segments)}个文本段到:{os.path.basename(file_path)}")
            messagebox.showinfo("导出成功", f"已成功导出{len(text_segments)}个文本段")
        
        except Exception as e:
            messagebox.showerror("导出错误", f"导出失败: {str(e)}")

    def export_selected_range(self):
        if not self.file_data:
            messagebox.showwarning("警告", "请先打开文件")
            return
    
        range_dialog = tk.Toplevel(self.root)
        range_dialog.title("导出选定范围")
        range_dialog.geometry("400x250")
        range_dialog.minsize(350, 220)    
        range_dialog.resizable(True, True) 
    
        main_frame = ttk.Frame(range_dialog)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
        main_frame.grid_columnconfigure(1, weight=1)
    
        ttk.Label(main_frame, text="起始地址(十六进制):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        start_entry = ttk.Entry(main_frame)
        start_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        start_entry.insert(0, "00000000")
    
        ttk.Label(main_frame, text="结束地址(十六进制):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        end_entry = ttk.Entry(main_frame)
        end_entry.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)
        end_entry.insert(0, f"{len(self.file_data)-1:08X}")
    
        info_label = ttk.Label(main_frame, 
                          text=f"文件范围:0x00000000 - 0x{len(self.file_data)-1:08X}",
                          foreground="blue")
        info_label.grid(row=2, column=0, columnspan=2, pady=10)
    
        if self.file_path:
            base_name = os.path.splitext(os.path.basename(self.file_path))[0]
            auto_save_name = f"{base_name}导出.txt"
            auto_save_path = os.path.join(os.path.dirname(self.file_path), auto_save_name)
        
            ttk.Label(main_frame, text="自动保存路径:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
            path_label = ttk.Label(main_frame, text=auto_save_path, foreground="green", wraplength=300)
            path_label.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
    
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=2, pady=15, sticky=tk.EW)
    
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)

        def do_export():
            try:
                start_addr = int(start_entry.get(), 16)
                end_addr = int(end_entry.get(), 16)
            
                if start_addr > end_addr:
                    messagebox.showerror("错误", "起始地址不能大于结束地址")
                    return
            
                if end_addr >= len(self.file_data):
                    messagebox.showerror("错误", "结束地址超出文件范围")
                    return
            
                if self.file_path:
                    base_name = os.path.splitext(os.path.basename(self.file_path))[0]
                    auto_save_name = f"{base_name}导出.txt"
                    auto_save_path = os.path.join(os.path.dirname(self.file_path), auto_save_name)
                
                    if os.path.exists(auto_save_path):
                        result = messagebox.askyesno("文件已存在", f"文件{auto_save_name}已存在，是否覆盖？")
                        if not result:
                            file_path = filedialog.asksaveasfilename(
                                title="导出选定范围",
                                defaultextension=".txt",
                                initialfile=auto_save_name,
                                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
                            )
                            if not file_path:
                                return
                            self.export_range_to_file(start_addr, end_addr, file_path)
                        else:
                            self.export_range_to_file(start_addr, end_addr, auto_save_path)
                    else:
                        self.export_range_to_file(start_addr, end_addr, auto_save_path)
                else:
                    file_path = filedialog.asksaveasfilename(
                        title="导出选定范围",
                        defaultextension=".txt",
                        filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
                    )
                    if not file_path:
                        return
                    self.export_range_to_file(start_addr, end_addr, file_path)
            
                range_dialog.destroy()
            
            except ValueError:
                messagebox.showerror("错误", "请输入有效的十六进制地址")
    
        ttk.Button(button_frame, text="导出", command=do_export).grid(row=0, column=1, padx=10)
        ttk.Button(button_frame, text="取消", command=range_dialog.destroy).grid(row=0, column=2, padx=10)
        ttk.Label(button_frame, text="").grid(row=0, column=0)

    def export_range_to_file(self, start_addr, end_addr, file_path=None):
        if file_path is None:
            file_path = filedialog.asksaveasfilename(
                title="导出选定范围",
                defaultextension=".txt",
                filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
            )
    
        if not file_path:
            return
    
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write("# 汉化辅助编辑器-选定范围导出\n")
                f.write(f"# 文件:{os.path.basename(self.file_path)}\n")
                f.write(f"# 范围:0x{start_addr:08X}- 0x{end_addr:08X}\n")
                f.write(f"# 导出时间:{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# 编码:{self.encoding_var.get()}\n")
                f.write("# 格式:地址|长度|文本内容\n")
                f.write("#" + "="*50 + "\n\n")
        
                current_pos = start_addr
                segment_count = 0
        
                while current_pos <= end_addr:
                    segment = self.find_next_text_segment(current_pos, end_addr)
                    if not segment:
                        break
            
                    f.write(f"{segment['start']:08X}|{segment['length']:04d}|{segment['text']}\n")
                    current_pos = segment["end"] + 1
                    segment_count += 1
    
            self.update_status(f"已导出{segment_count}个文本段到:{os.path.basename(file_path)}")
            messagebox.showinfo("导出成功", f"已成功导出{segment_count}个文本段")
    
        except Exception as e:
            messagebox.showerror("导出错误", f"导出失败: {str(e)}")

    def find_all_text_segments(self, min_length=2):
        segments = []
        current_pos = 0
        data_length = len(self.file_data)
        encoding = self.encoding_var.get()
    
        if encoding in ['utf-8', 'gbk']:
            while current_pos < data_length:
                while (current_pos < data_length and 
                       not (32 <= self.file_data[current_pos] <= 126 or 
                            self.file_data[current_pos] >= 0x80)):
                    current_pos += 1
            
                if current_pos >= data_length:
                    break
                
                segment_start = current_pos
                segment_bytes = bytearray()
            
                while (current_pos < data_length and 
                       (32 <= self.file_data[current_pos] <= 126 or 
                        self.file_data[current_pos] >= 0x80)):
                    segment_bytes.append(self.file_data[current_pos])
                    current_pos += 1
            
                if len(segment_bytes) >= min_length:
                    try:
                        segment_text = segment_bytes.decode(encoding)
                        segments.append({
                            "start": segment_start,
                            "end": current_pos - 1,
                            "length": len(segment_bytes),
                            "text": segment_text,
                            "bytes": segment_bytes
                        })
                    except UnicodeDecodeError:
                        pass
                    
        elif encoding in ['utf-16le', 'utf-16be']:
            while current_pos < data_length - 1:
                valid_chars_found = 0
                segment_start = current_pos
                segment_bytes = bytearray()
            
                while current_pos < data_length - 1:
                    byte1 = self.file_data[current_pos]
                    byte2 = self.file_data[current_pos + 1]
                
                    is_valid = False
                    if encoding == 'utf-16le':
                        is_valid = (byte1 == 0 and 32 <= byte2 <= 126) or (byte2 == 0 and 32 <= byte1 <= 126)
                    else:
                        is_valid = (byte2 == 0 and 32 <= byte1 <= 126) or (byte1 == 0 and 32 <= byte2 <= 126)
                
                    if is_valid:
                        segment_bytes.extend([byte1, byte2])
                        current_pos += 2
                        valid_chars_found += 1
                    else:
                        break
            
                if valid_chars_found >= min_length:
                    try:
                        segment_text = segment_bytes.decode(encoding)
                        segments.append({
                            "start": segment_start,
                            "end": current_pos - 1,
                            "length": len(segment_bytes),
                            "text": segment_text,
                            "bytes": segment_bytes
                        })
                    except UnicodeDecodeError:
                        pass
                else:
                    current_pos += 1
    
        return segments

    def find_next_text_segment(self, start_pos, end_pos, min_length=2):
        encoding = self.encoding_var.get()
        current_pos = start_pos
    
        while current_pos <= end_pos:
            segment_start = current_pos
            segment_text = ""
            segment_bytes = bytearray()
        
            while current_pos <= end_pos:
                byte = self.file_data[current_pos]
            
                if encoding in ['utf-8', 'gbk']:
                    if 32 <= byte <= 126 or byte >= 0x80:
                        segment_text += chr(byte)
                        segment_bytes.append(byte)
                        current_pos += 1
                    else:
                        break
                elif encoding in ['utf-16le', 'utf-16be']:
                    if current_pos + 1 > end_pos:
                        break
                
                    byte1 = self.file_data[current_pos]
                    byte2 = self.file_data[current_pos + 1]
                
                    if (byte1 == 0 and 32 <= byte2 <= 126) or (byte2 == 0 and 32 <= byte1 <= 126):
                        try:
                            char_bytes = bytes([byte1, byte2])
                            char = char_bytes.decode(encoding)
                            segment_text += char
                            segment_bytes.extend(char_bytes)
                            current_pos += 2
                        except:
                            break
                    else:
                        break
        
            if len(segment_text) >= min_length:
                return {
                    "start": segment_start,
                    "end": current_pos - 1,
                    "length": len(segment_bytes),
                    "text": segment_text,
                    "bytes": segment_bytes
                }
        
            current_pos += 1
    
        return None

    def import_replace_file(self):
        if not self.file_data:
            messagebox.showwarning("警告", "请先打开文件")
            return
    
        file_path = filedialog.askopenfilename(
            title="选择替换文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
    
        if not file_path:
            return
    
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        
            replace_entries = []
            successful_replacements = []
            failed_replacements = []
        
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
            
                parts = line.split('|', 2)
                if len(parts) != 3:
                    failed_replacements.append(f"第{line_num}行:格式错误")
                    continue
            
                try:
                    address = int(parts[0], 16)
                    original_length = int(parts[1])
                    replace_text = parts[2]
                
                    replace_entries.append({
                        'address': address,
                        'original_length': original_length,
                        'replace_text': replace_text,
                        'line_num': line_num
                    })
                except ValueError:
                    failed_replacements.append(f"第{line_num}行:数据格式错误")
        
            for entry in replace_entries:
                success = self.apply_replacement(entry)
                if success:
                    successful_replacements.append(entry)
                else:
                    failed_replacements.append(f"第{entry['line_num']}行:替换失败")
        
            self.hex_viewer.set_data(self.file_data)
        
            result_message = f"替换完成!\n成功:{len(successful_replacements)}条\n失败:{len(failed_replacements)}条"
        
            if failed_replacements:
                result_message += "\n\n失败详情:\n" + "\n".join(failed_replacements[:10])
                if len(failed_replacements) > 10:
                    result_message += f"\n...还有{len(failed_replacements) - 10}条失败记录"
        
            messagebox.showinfo("替换结果", result_message)
            self.update_status(f"批量替换完成:成功{len(successful_replacements)}条, 失败{len(failed_replacements)}条")
        
        except Exception as e:
            messagebox.showerror("导入错误", f"导入失败: {str(e)}")

    def apply_replacement(self, entry):
        try:
            address = entry['address']
            original_length = entry['original_length']
            replace_text = entry['replace_text']
        
            if address < 0 or address >= len(self.file_data):
                return False
        
            encoding = self.encoding_var.get()
            replace_bytes = replace_text.encode(encoding)
        
            if len(replace_bytes) > original_length:
                return False 
        
            for i in range(len(replace_bytes)):
                self.file_data[address + i] = replace_bytes[i]
        
            if len(replace_bytes) < original_length:
                padding_length = original_length - len(replace_bytes)
                padding_bytes = self.get_padding_bytes(padding_length)
            
                for i in range(padding_length):
                    self.file_data[address + len(replace_bytes) + i] = padding_bytes[i]
        
            return True
        
        except Exception:
            return False
    
    def show_clipboard_converter(self):
        converter_window = tk.Toplevel(self.root)
        converter_window.title("UTF-16剪贴板字符串转换器")
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
        cleaned = re.sub(r'[\n\r\t]', '', text)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        cleaned = re.sub(r'\.\.', '\n', cleaned)
        cleaned = re.sub(r'\.', '', cleaned)
        cleaned = re.sub('\n', '.', cleaned)
        return cleaned
    
    def show_encoding_converter(self):
        converter_window = tk.Toplevel(self.root)
        converter_window.title("实时编码转换器")
        converter_window.geometry("900x600")
        converter_window.minsize(700, 400)
    
        main_frame = ttk.Frame(converter_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
    
        input_frame = ttk.LabelFrame(main_frame, text="输入字符串")
        input_frame.pack(fill=tk.X, pady=(0, 10))
    
        ttk.Label(input_frame, text="输入要转换的字符串:").pack(anchor=tk.W, padx=5, pady=5)
    
        input_text = tk.Text(input_frame, height=4, wrap=tk.WORD)
        input_text.pack(fill=tk.X, padx=5, pady=5)
    
        result_frame = ttk.LabelFrame(main_frame, text="编码结果")
        result_frame.pack(fill=tk.BOTH, expand=True)
    
        columns = ("编码格式", "字节序列", "长度")
        result_tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=15)
    
        result_tree.heading("编码格式", text="编码格式")
        result_tree.column("编码格式", width=120, anchor=tk.W)
    
        result_tree.heading("字节序列", text="字节序列")
        result_tree.column("字节序列", width=400, anchor=tk.W)
    
        result_tree.heading("长度", text="长度")
        result_tree.column("长度", width=80, anchor=tk.CENTER)
    
        scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=result_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        result_tree.configure(yscrollcommand=scrollbar.set)
    
        result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
    
        def on_tree_right_click(event):
            item = result_tree.identify_row(event.y)
            if item:
                result_tree.selection_set(item)
                context_menu.post(event.x_root, event.y_root)

        result_tree.bind("<Button-3>", on_tree_right_click)

        def get_unicode_codepoints(text):
            codepoints = []
            for char in text:
                codepoint = ord(char)
                codepoints.append(f"0x{codepoint:04X}")
            return ', '.join(codepoints)
    
        def update_conversion(event=None):
            for item in result_tree.get_children():
                result_tree.delete(item)
        
            text = input_text.get("1.0", tk.END).strip()
            if not text:
                return
        
            unicode_codepoints = get_unicode_codepoints(text)
            result_tree.insert("", tk.END, values=(
                "Unicode码点",
                unicode_codepoints,
                f"{len(text)} 字符"
            ))
        
            encoding_groups = [
                {
                    'name': '中文编码',
                    'encodings': ['gbk', 'gb2312', 'big5']
                },
                {
                    'name': 'Unicode编码',
                    'encodings': ['utf-8', 'utf-16le', 'utf-16be', 'utf-7']
                },
                {
                    'name': '日文编码',
                    'encodings': ['shift_jis', 'euc-jp']
                },
                {
                    'name': '西欧编码',
                    'encodings': ['iso-8859-1', 'latin1', 'ascii']
                }
            ]
        
            for group in encoding_groups:
                result_tree.insert("", tk.END, values=(
                    f"--- {group['name']} ---",
                    "",
                    ""
                ))
            
                for encoding in group['encodings']:
                    try:
                        encoded_bytes = text.encode(encoding, errors='replace')
                        hex_representation = ' '.join(f"{b:02X}" for b in encoded_bytes)
                        byte_length = len(encoded_bytes)
                    
                        result_tree.insert("", tk.END, values=(
                            encoding.upper(),
                            hex_representation,
                            f"{byte_length}字节"
                        ))
                    
                    except Exception as e:
                        result_tree.insert("", tk.END, values=(
                            encoding.upper(),
                            f"编码错误: {str(e)}",
                            "N/A"
                        ))
    
        input_text.bind("<KeyRelease>", update_conversion)
    
        update_conversion()
    
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
    
        def copy_selected():
            selected = result_tree.selection()
            if not selected:
                return
            values = result_tree.item(selected[0], "values")
            if len(values) >= 2 and values[1]:
                converter_window.clipboard_clear()
                converter_window.clipboard_append(values[1])
    
        context_menu = tk.Menu(converter_window, tearoff=0)
        context_menu.add_command(label="复制", command=copy_selected)

        def copy_all():
            results = []
            for item in result_tree.get_children():
                values = result_tree.item(item, "values")
                if values and len(values) >= 3 and not values[0].startswith('---'):
                    results.append(f"{values[0]}: {values[1]} ({values[2]})")
        
            if results:
                all_text = "\n".join(results)
                self.root.clipboard_clear()
                self.root.clipboard_append(all_text)
                self.update_status("已复制所有编码结果")
           
        ttk.Button(button_frame, text="复制全部", command=copy_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="关闭", command=converter_window.destroy).pack(side=tk.RIGHT, padx=5)
    
        info_label = ttk.Label(main_frame, 
                              text="unicode显示字符码点(如:0x0020)，其他编码只显示字节序列(如:20 2B 1E)，鼠标右键点击复制",
                              foreground="blue", font=("Microsoft YaHei", 11))
        info_label.pack(pady=(5, 0))
    
        input_text.focus_set()


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
            self.update_status(f"已加载文件:{os.path.basename(file_path)}")
        
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件: {str(e)}")
            self.update_status(f"错误: 无法打开文件 - {str(e)}")

    def confirm_new_find_text(self):
        new_text = self.find_text.get("1.0", tk.END).strip()
        if new_text != self.current_find_text:
            self.current_find_text = new_text
            self.find_matches()
        if self.replace_buttons_disabled:
            self.replace_button.config(state=tk.NORMAL)
            self.replace_all_button.config(state=tk.NORMAL)
            self.replace_text.config(state=tk.NORMAL)
            self.replace_hex_entry.config(state=tk.NORMAL)
            self.replace_buttons_disabled = False

    def on_encoding_changed(self, event=None):
        self.update_display()
        self.reset_find_mode()

    def reset_find_mode(self):
        self.find_text.delete("1.0", tk.END)
        self.find_hex_entry.delete(0, tk.END)
        self.replace_text.delete("1.0", tk.END)
        self.replace_hex_entry.delete(0, tk.END)
        self.clear_matches()
        self.update_status("编码/输入类型已切换，查找模式已重置")

    def create_widgets(self):
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="打开文件", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="保存", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="另存为", command=self.save_file_as, accelerator="Ctrl+T")
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self.root.quit, accelerator="Ctrl+Q")
        menubar.add_cascade(label="文件", menu=file_menu)
        

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="撤销", command=self.undo, accelerator="Ctrl+Z")
        edit_menu.add_command(label="重做", command=self.redo, accelerator="Ctrl+Y")
        edit_menu.add_separator()
        edit_menu.add_command(label="查找上一个", command=self.find_prev, accelerator="F1")
        edit_menu.add_command(label="查找下一个", command=self.find_next, accelerator="F2") 
        edit_menu.add_command(label="替换当前搜索内容", command=self.replace_current, accelerator="F3")
        edit_menu.add_command(label="替换全部搜索内容", command=self.replace_all, accelerator="F4")
        edit_menu.add_separator()
        edit_menu.add_command(label="导出所有ASCII", command=self.export_ascii_text, accelerator="F5")
        edit_menu.add_command(label="导出指定范围ASCII", command=self.export_selected_range, accelerator="F6")
        edit_menu.add_command(label="导入ASCII", command=self.import_replace_file, accelerator="F7")
        edit_menu.add_separator()
        edit_menu.add_command(label="实时编码转换器", command=self.show_encoding_converter, accelerator="F8")
        edit_menu.add_command(label="剪贴板字符串转换器", command=self.show_clipboard_converter, accelerator="F9")
        edit_menu.add_separator()
        menubar.add_cascade(label="选择功能", menu=edit_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于此工具", command=self.show_about)
        menubar.add_cascade(label="查看说明", menu=help_menu)

        self.root.config(menu=menubar)
        self.root.bind("<Control-z>", lambda e: self.undo())
        self.root.bind("<Control-y>", lambda e: self.redo())
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_file_as())       
        self.root.bind("<F1>", lambda e: self.find_prev())
        self.root.bind("<F2>", lambda e: self.find_next())
        self.root.bind("<F3>", lambda e: self.replace_current())
        self.root.bind("<F4>", lambda e: self.replace_all())
        self.root.bind("<F5>", lambda e: self.export_ascii_text())
        self.root.bind("<F6>", lambda e: self.export_selected_range())
        self.root.bind("<F7>", lambda e: self.import_replace_file())
        self.root.bind("<F8>", lambda e: self.show_encoding_converter())
        self.root.bind("<F9>", lambda e: self.show_clipboard_converter())
        self.root.bind("<Control-S>", lambda e: self.save_file())
        self.root.bind("<Control-T>", lambda e: self.save_file_as())
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        file_info_frame = ttk.LabelFrame(main_frame, text="文件信息")
        file_info_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(file_info_frame, text="当前文件:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=10)
        self.file_path_label = ttk.Label(file_info_frame, text="未选择文件", foreground="red")
        self.file_path_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)

        ttk.Label(file_info_frame, text="文件大小:").grid(row=0, column=2, sticky=tk.W, padx=10, pady=10)
        self.file_size_label = ttk.Label(file_info_frame, text="0 字节")
        self.file_size_label.grid(row=0, column=3, sticky=tk.W, padx=5, pady=5)

        hex_frame = ttk.LabelFrame(main_frame, text="十六进制视图")
        hex_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.hex_viewer = HexViewer(hex_frame, width=80, height=16, app=self)
        self.hex_viewer.hex_text.bind("<Button-1>", self.on_hex_click)
        self.hex_viewer.ascii_text.bind("<Button-1>", self.on_ascii_click)
        self.hex_viewer.hex_text.bind("<Button-3>", self.hex_viewer.on_hex_right_click)
        self.hex_viewer.ascii_text.bind("<Button-3>", self.hex_viewer.on_ascii_right_click)

        v_scrollbar = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=self.hex_viewer.yview)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.hex_viewer.set_scroll_command(v_scrollbar.set)

        search_frame = ttk.LabelFrame(self.root, text="查找和替换")
        search_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        search_frame.grid_columnconfigure(1, weight=0)
        search_frame.grid_columnconfigure(2, weight=0)
        search_frame.grid_columnconfigure(3, weight=1)
        search_frame.grid_rowconfigure(2, weight=1)
        search_frame.grid_rowconfigure(3, weight=1)
        search_frame.grid_rowconfigure(4, weight=1)
        search_frame.grid_rowconfigure(5, weight=1)

        ttk.Label(search_frame, text="输入类型:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=10)
        input_type_menu = ttk.Combobox(search_frame, textvariable=self.input_type_var,
                                       values=self.input_type_options, state="readonly", width=8)
        input_type_menu.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        input_type_menu.bind("<<ComboboxSelected>>", self.on_input_type_changed)

        ttk.Label(search_frame, text="编码:").grid(row=1, column=2, sticky=tk.W, padx=(10, 5), pady=10)
        self.encoding_menu = ttk.Combobox(search_frame, textvariable=self.encoding_var,
                                     values=self.encoding_options, state="readonly", width=10)
        self.encoding_menu.grid(row=1, column=3, sticky=tk.W, padx=(0, 5), pady=5)
        self.encoding_menu.bind("<<ComboboxSelected>>", self.on_encoding_changed)

        ttk.Label(search_frame, text="查找字符串:").grid(row=2, column=0, sticky=tk.NW, padx=10, pady=10)
        self.find_text = tk.Text(search_frame, wrap=tk.NONE)
        self.find_text.grid(row=2, column=1, columnspan=3, sticky=tk.NSEW, padx=5, pady=5)
        self.find_text.bind("<KeyRelease>", self.validate_input)
        self.find_text.bind("<FocusIn>", self.on_find_focus)
        self.find_text.bind("<Control-v>", self.handle_paste)
        self.find_text.bind("<Key>", lambda e: self.schedule_text_processing(e))
        self.update_input_height(self.find_text, 4)

        ttk.Label(search_frame, text="查找16进制字节:").grid(row=3, column=0, sticky=tk.W, padx=10, pady=10)
        self.find_hex_entry = ttk.Entry(search_frame)
        self.find_hex_entry.grid(row=3, column=1, columnspan=3, sticky=tk.NSEW, padx=5, pady=5)
        self.find_hex_entry.bind("<KeyRelease>", self.validate_hex_input)
        self.find_hex_entry.bind("<FocusIn>", self.on_hex_focus)

        ttk.Label(search_frame, text="替换字符串:").grid(row=4, column=0, sticky=tk.NW, padx=10, pady=10)
        self.replace_text = tk.Text(search_frame, wrap=tk.WORD)
        self.replace_text.grid(row=4, column=1, columnspan=3, sticky=tk.NSEW, padx=5, pady=5)
        self.replace_text.bind("<KeyRelease>", self.validate_replace_input)
        self.replace_text.bind("<Control-v>", self.handle_paste)
        self.update_input_height(self.replace_text, 4)

        ttk.Label(search_frame, text="替换16进制字节:").grid(row=5, column=0, sticky=tk.W, padx=10, pady=10)
        self.replace_hex_entry = ttk.Entry(search_frame)
        self.replace_hex_entry.grid(row=5, column=1, columnspan=3, sticky=tk.NSEW, padx=5, pady=5)
        self.replace_hex_entry.bind("<KeyRelease>", self.validate_replace_hex_input)
        self.replace_hex_entry.bind("<Control-v>", self.handle_paste)

        button_frame = ttk.Frame(search_frame)
        button_frame.grid(row=6, column=0, columnspan=6, sticky=tk.EW, padx=10, pady=10)

        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)
        button_frame.grid_columnconfigure(3, weight=1)
        button_frame.grid_columnconfigure(4, weight=1)
        
        find_other_button = ttk.Button(button_frame, text="查找字符串或字节序列", command=self.confirm_new_find_text)
        find_other_button.grid(row=0, column=0, padx=5, pady=5)

        find_prev_button = ttk.Button(button_frame, text="查找上一个", command=self.find_prev)
        find_prev_button.grid(row=0, column=1, padx=5, pady=5)

        find_next_button = ttk.Button(button_frame, text="查找下一个", command=self.find_next)
        find_next_button.grid(row=0, column=2, padx=5, pady=5)

        self.replace_button = ttk.Button(button_frame, text="替换当前搜索内容", command=self.replace_current)
        self.replace_button.grid(row=0, column=3, padx=5, pady=5)

        self.replace_all_button = ttk.Button(button_frame, text="替换全部搜索内容", command=self.replace_all)
        self.replace_all_button.grid(row=0, column=4, padx=5, pady=5)

        results_frame = ttk.LabelFrame(main_frame, text="匹配结果")
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.results_count_label = ttk.Label(results_frame, text="匹配数量:0")
        self.results_count_label.pack(anchor=tk.W, padx=5, pady=2)

        columns = ("位置", "字节")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=5)
        self.results_tree.heading("位置", text="位置(可复制)")
        self.results_tree.column("位置", width=120, anchor=tk.CENTER)
        self.results_tree.heading("字节", text="字节")
        self.results_tree.column("字节", width=600, anchor=tk.W)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.create_context_menu()

        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_tree.configure(yscroll=scrollbar.set)

        self.results_tree.bind("<<TreeviewSelect>>", self.on_result_select)
        self.results_tree.bind("<ButtonRelease-1>", self.on_result_click)

        status_frame = ttk.Frame(self.root, height=20)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        status_frame.pack_propagate(False)
        self.status_bar = ttk.Label(status_frame, text="就绪", anchor=tk.W)
        self.status_bar.pack(side=tk.TOP, fill=tk.X)

        self.find_mode = "text"
        self.update_input_fields_state()

    def save_file(self):
        if not self.file_path:
            self.save_file_as()
            return
        try:
            with open(self.file_path, "wb") as f:
                f.write(self.file_data)
            self.original_data = copy.copy(self.file_data)
            self.update_status(f"已保存：{os.path.basename(self.file_path)}")
        except Exception as e:
            messagebox.showerror("保存失败", str(e))

    def on_find_key_release(self, event):
        self.adjust_text_height(self.find_text)
        self.validate_input(event)
        self.check_long_text(self.find_text)
        self.process_text_format(self.find_text)
        return "break"

    def on_replace_key_release(self, event):
        self.adjust_text_height(self.replace_text)
        self.validate_replace_input(event)
        self.check_long_text(self.replace_text)
        self.process_text_format(self.replace_text)

    def adjust_text_height(self, text_widget):
        line_count = int(text_widget.index(tk.END).split('.')[0]) - 1
        max_lines = max(line_count, self.initial_height)
        self.update_input_height(text_widget, max_lines)

    def update_input_height(self, text_widget, lines):
        text_widget.config(height=lines)
        text_widget.master.update_idletasks()

    def check_long_text(self, text_widget):
        text = text_widget.get("1.0", tk.END).strip()
        length = len(text)
    
        if length > self.max_input_length:
            truncated_text = text[:self.max_input_length]
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", truncated_text)
            self.update_status(f"输入内容已截断为{self.max_input_length}字符")
            messagebox.showwarning("长文本提示", 
                f"输入内容超过{self.max_input_length}字符，已自动截断。\n"
                "如需输入更长内容，请分批次操作或使用十六进制模式。")
        elif length > self.extended_threshold:
            self.update_status(f"输入内容较长({length}字符)，可能影响性能")

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="复制位置", command=self.copy_position)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="插入字节", command=self.insert_bytes)
        self.context_menu.add_command(label="删除字节", command=self.delete_bytes)
        self.context_menu.add_separator()
        self.results_tree.bind("<Button-3>", self.show_context_menu)
        self.results_tree.bind("<Control-c>", self.copy_position_event)

    def insert_bytes(self):
        if not hasattr(self.hex_viewer, 'right_click_pos') or self.hex_viewer.right_click_pos is None:
            return
            
        count = simpledialog.askinteger("插入字节", "请输入要插入的字节数量:", 
                                       initialvalue=1, minvalue=1, maxvalue=1000)
        if count is None: 
            return
            
        byte_value = simpledialog.askstring("字节值", "请输入要插入的字节值(十六进制, 默认为20):", 
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
            
        if not messagebox.askyesno("确认删除", f"确定要删除从位置0x{pos:08X}开始的{count}个字节吗？"):
            return
            
        del self.file_data[pos:pos + count]
        
        self.hex_viewer.set_data(self.file_data)
        self.save_history_state()
        
        self.update_status(f"已从位置0x{pos:08X}删除了{count}个字节")

    def show_context_menu(self, event):
        item = self.results_tree.identify_row(event.y)
        if item:
            self.results_tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_position_event(self, event):
        self.copy_position()
        return "break"

    def copy_position(self):
        selected = self.results_tree.selection()
        if not selected:
            return

        position = self.results_tree.item(selected[0], "values")[0]
        self.root.clipboard_clear()
        self.root.clipboard_append(position)
        self.update_status(f"已复制位置: {position}")

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

            if (focused_widget == self.find_text and 
                self.encoding_var.get() in ['utf-16le', 'utf-16be']):
    
                cleaned_text = self.convert_utf16_exe_text(clipboard_text)
        
                self.input_type_var.set("字符串")
                self.find_mode = "text"
                self.find_text.config(state=tk.NORMAL)
                current_pos = self.find_text.index(tk.INSERT)
                self.find_text.insert(current_pos, cleaned_text)
                self.validate_input()
        
                if cleaned_text != clipboard_text:
                    self.update_status(f"UTF-16模式：已转换'{clipboard_text[:30]}{'...' if len(clipboard_text) > 30 else ''}' -> '{cleaned_text}'")
                else:
                    self.update_status(f"UTF-16模式：已粘贴文本")
                return "break"

            if focused_widget == self.find_text:
                cleaned_text = re.sub(r'[\n\r\t]', '', clipboard_text).strip()
                self.input_type_var.set("字符串")
                self.find_mode = "text"
                self.find_text.config(state=tk.NORMAL)
                current_pos = self.find_text.index(tk.INSERT)
                self.find_text.insert(current_pos, cleaned_text)
                self.validate_input()

            elif focused_widget == self.find_hex_entry:
                self.input_type_var.set("十六进制")
                self.find_mode = "hex"

                cleaned_text = re.sub(r'[^0-9A-Fa-f]', '', clipboard_text).upper()
                hex_pairs = [cleaned_text[i:i+2] for i in range(0, len(cleaned_text), 2)]
                hex_str = ' '.join(hex_pairs)

                current_pos = self.find_hex_entry.index(tk.INSERT)
                self.find_hex_entry.insert(current_pos, hex_str)
                self.validate_hex_input()

                try:
                    byte_data = bytes.fromhex(cleaned_text)
                    self.find_text.config(state=tk.NORMAL)
                    current_pos = self.find_text.index(tk.INSERT)
                    self.find_text.insert(current_pos, byte_data.decode('latin1'))
                    self.find_text.config(state=tk.DISABLED)
                except Exception:
                    self.find_text.config(state=tk.NORMAL)
                    current_pos = self.find_text.index(tk.INSERT)
                    self.find_text.insert(current_pos, "无法解码为字符串")
                    self.find_text.config(state=tk.DISABLED)
        
            elif focused_widget == self.replace_text:
                cleaned_text = re.sub(r'[\n\r\t]', '', clipboard_text)

                cleaned_text = re.sub(r'([\u4e00-\u9fff])\s+', r'\1', cleaned_text)
                cleaned_text = re.sub(r'\s+([\u4e00-\u9fff])', r'\1', cleaned_text) 

                cleaned_text = re.sub(r' {2,}', ' ', cleaned_text)

                cleaned_text = cleaned_text.strip()

                translation_table = str.maketrans({
                '（': '(', '）': ')', '：': ':', '；': ';', 
                '「': '"', '」': '"', '『': '"', '』': '"',
                '《': '<', '》': '>', '【': '[', '】': ']',
                '、': ',', '．': '.', '‘': "'", '’': "'",
                '“': '"', '”': '"', '„': '"', '‟': '"',
                '‹': '<', '›': '>', '«': '"', '»': '"',
                '？': '?', '！': '!', '—': '-', '–': '-',
                '～': '~', '‧': '.', '§': '§', '€': 'EUR',
                '£': 'GBP', '¥': 'JPY', '¢': 'c', '°': 'deg'
                })
            
                processed_text = cleaned_text.translate(translation_table)

                current_pos = self.replace_text.index(tk.INSERT)
                self.replace_text.insert(current_pos, processed_text)
                self.validate_replace_input()

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
        self.update_status(f"已复制字符：{clipboard_text}")

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

    def on_input_type_changed(self, event=None):
        input_type = self.input_type_var.get()
        self.find_mode = "hex" if input_type == "十六进制" else "text"
        self.update_input_fields_state()
        self.validate_input()
        self.reset_find_mode()

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
                messagebox.showwarning("警告", "文件过大，可能影响性能")
            self.file_path = file_path
            self.original_data = copy.copy(self.file_data)

            self.file_path_label.config(text=os.path.basename(file_path), foreground="green")
            self.file_size_label.config(text=f"{len(self.file_data)} 字节")

            self.clear_matches()
            self.hex_viewer.start_address = 0 
            self.hex_viewer.highlight_start = -1 
            self.hex_viewer.highlight_end = -1
            self.hex_viewer.set_data(self.file_data) 

            self.history = [copy.copy(self.file_data)]
            self.history_index = 0

            self.update_status(f"已加载文件:{os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("错误", f"无法打开文件: {str(e)}")
            self.update_status(f"错误:无法打开文件 - {str(e)}")

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

            self.update_status(f"文件已保存: {os.path.basename(file_path)}")
        except Exception as e:
            messagebox.showerror("错误", f"无法保存文件: {str(e)}")
            self.update_status(f"错误: 无法保存文件 - {str(e)}")

    def show_about(self):
        about_text = """汉化辅助编辑器
版本6.0    [B站偷吃布丁的涅普缇努制作]

一个简单的二进制文件编辑器

我已经把所有不可打印字符全部改成紫色高亮了
目前我在汉化某些程序的时候会先把0A和0D这种字节替换成20空格，
只有把不可打印字符替换成空格才能框选整段文本，搜索到匹配结果，
此外大家需要注意某些c/c++程序里面经常会出现的%或者&，
%是占位符，占位符通常用于代指命令，会导致你无法搜素到对应文本，&经常和按钮绑定，是个非常缺德的符号，
因为它可能会随机穿插在文本中间，比如File和&可能写成&File，也可能写成F&ile或者Fi&le...

某些程序加壳后会搜索不到字符，或者能搜索到但是替换了之后无法正常显示，比如noesis这个程序，
找不到原作者的源码，替换字节根本没有用处，它的壳保护资源不被修改，所以替换了无效。
挺好的一个模型纹理查看器，可惜了。

还有些程序不支持中文字体，一汉化就乱码，比如Imgui的程序，优先修改为雅黑等支持中文的字体。
废话，编译后能改还用找我吗，在编译前改成雅黑字体，比如Fmodel的3D查看器，我就是改成雅黑后汉化的。
否则你看到的会是???也有些程序无论怎么替换字节都会乱码，比如UE Viewer，这个程序的标题栏汉化会乱码，
非标题栏汉化不会乱码，到现在我都搞不懂这个程序到底是咋回事。

自求多福吧，有了我这个工具你可以省很大的力气，在ResourceHacker这类本地化工具无法显示菜单、对话框
和字串表的时候再使用我这个工具去汉化，能使用傻瓜式的本地化工具尽量使用，至于c# NET程序可以尝试使用
dnspy、UniTranslator这种工具，dnspy是反编译工具，我已经用它汉化很多程序了，UniTranslator是某大佬
制作的一个专门对付XAML/BAML这种WPF程序的汉化工具，能用就用，不能用再用我这个工具。Delphi程序可以试
试localizator，这个工具是给Delphi程序制作汉化补丁的，生成的补丁文件是.CHS格式的，千万不要删了。

不可打印字符及对应字节：
0x00-NUL(空)  0x01-SOH(标题)  0x02-STX(正文始)  0x03-ETX(正文终)
0x04-EOT(传输终)  0x05-ENQ(询问) 0x06-ACK(确认) 0x07-BEL(响铃)
0x08-BS(退格) 0x09-TAB(制表) 0x0A-LF(换行) 0x0B-VT(垂直制表)
0x0C-FF(换页) 0x0D-CR(回车) 0x0E-SO(移出) 0x0F-SI(移入)
0x10-DLE(转义) 0x11-DC1(设备1) 0x12-DC2(设备2) 0x13-DC3(设备3)
0x14-DC4(设备4) 0x15-NAK(否定) 0x16-SYN(同步) 0x17-ETB(块终)
0x18-CAN(取消) 0x19-EM(介质终) 0x1A-SUB(替换) 0x1B-ESC(转义)
0x1C-FS(文件分) 0x1D-GS(组分) 0x1E-RS(记录分) 0x1F-US(单元分)
0x7F-DEL(删除)  0xB0-°(度)

常见标点符号及对应字节：
0x20-空格  0x21-!  0x22-"  0x23-#  0x24-$  0x25-%  0x26-&  0x27-'
0x28-(     0x29-)  0x2A-*  0x2B-+  0x2C-,  0x2D--  0x2E-.  0x2F-/
0x3A-:     0x3B-;  0x3C-<  0x3D-=  0x3E->  0x3F-?  0x40-@  0x5B-[
0x5C-\\    0x5D-]  0x5E-^  0x5F-_  0x60-`  0x7B-{  0x7C-|  0x7D-}
0x7E-~          0xA7-§(章节)   0xA9-©(版权)    0xAE-®(商标)
0xB1-±(正负)      0xB5-µ(微)      0xD7-×(乘)     0xF7-÷(除)"""


        messagebox.showinfo("关于", about_text)

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
                error_msg = "十六进制模式下只能输入十六进制字符(0-9, A-F)"
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
            error_msg = "只能输入十六进制字符(0-9、A-F)"
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
                self.find_text.insert("1.0", f"无法解码: {str(e)}")
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
                error_msg = "十六进制模式下只能输入十六进制字符(0-9, A-F)"
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
                self.replace_text.insert("1.0", f"无法解码: {str(e)}")
    
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
            self.update_status(f"输入转换错误: {str(e)}")
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
            self.find_hex_entry.insert(0, f"转换错误: {str(e)}")

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
            self.replace_hex_entry.insert(0, f"转换错误: {str(e)}")

    def find_matches(self):
        if not self.file_data:
            return
    
        if len(self.file_data) > 100 * 1024 * 1024:
            result = messagebox.askyesno("警告", "文件较大，搜索可能需要较长时间，是否继续？")
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
        for match in matches:
            self.results_tree.insert("", tk.END, values=(
                f"0x{match['pos']:08X}",
                bytes_to_hex(match['bytes'])
            ))

        self.results_count_label.config(text=f"匹配数量: {len(matches)}")

        if matches:
            self.update_status(f"找到{len(matches)}个匹配项")
            self.results_tree.selection_set(self.results_tree.get_children()[0])
            self.results_tree.focus(self.results_tree.get_children()[0])
            self.on_result_select(None)
        else:
            self.update_status("未找到匹配项")

    def find_utf16_matches(self, text, encoding):
        try:
            if encoding == 'utf-16le':
                find_bytes = text.encode('utf-16le')
            elif encoding == 'utf-16be':
                find_bytes = text.encode('utf-16be')
            else:
                return []
            
            matches = []
            start = 0
            
            while True:
                pos = self.file_data.find(find_bytes, start)
                if pos == -1:
                    break
                
                matches.append({
                    "pos": pos,
                    "bytes": find_bytes,
                    "text": text
                })
                start = pos + 1
            
            return matches
            
        except Exception as e:
            self.update_status(f"UTF-16查找错误:{str(e)}")
            return []    

    def find_next(self):
        if not self.current_matches:
            self.find_matches()
            return

        if not self.results_tree.get_children():
            return

        selected = self.results_tree.selection()
        if not selected:
            self.results_tree.selection_set(self.results_tree.get_children()[0])
            self.results_tree.focus(self.results_tree.get_children()[0])
            return

        children = list(self.results_tree.get_children())
        current_idx = children.index(selected[0])

        next_idx = (current_idx + 1) % len(children)
        self.results_tree.selection_set(children[next_idx])
        self.results_tree.focus(children[next_idx])
        match = self.current_matches[next_idx]
        self.hex_viewer.highlight_range(match["pos"], match["pos"] + len(match["bytes"]))
        self.hex_viewer.scroll_to_address(match["pos"])
        self.update_input_fields_state()

    def find_prev(self):
        if not self.current_matches:
            self.find_matches()
            return

        if not self.results_tree.get_children():
            return

        selected = self.results_tree.selection()
        if not selected:
            self.results_tree.selection_set(self.results_tree.get_children()[-1])
            self.results_tree.focus(self.results_tree.get_children()[-1])
            return

        children = list(self.results_tree.get_children())
        current_idx = children.index(selected[0])

        prev_idx = (current_idx - 1) % len(children)
        self.results_tree.selection_set(children[prev_idx])
        self.results_tree.focus(children[prev_idx])
        match = self.current_matches[prev_idx]
        self.hex_viewer.highlight_range(match["pos"], match["pos"] + len(match["bytes"]))
        self.hex_viewer.scroll_to_address(match["pos"])
        self.update_input_fields_state()

    def on_result_select(self, event):
        selected = self.results_tree.selection()
        if not selected:
            return

        children = list(self.results_tree.get_children())
        self.current_match_index = children.index(selected[0])

        match = self.current_matches[self.current_match_index]
        self.hex_viewer.highlight_range(match["pos"], match["pos"] + len(match["bytes"]))
        self.hex_viewer.scroll_to_address(match["pos"])

    def on_result_click(self, event):
        self.on_result_select(None)

    def clear_matches(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.current_matches = []
        self.current_match_index = -1
        self.results_count_label.config(text="匹配数量:0")

    def update_status(self, message):
        self.status_bar.config(text=message)
        self.root.update_idletasks()

    def undo(self):
        if self.history_index <= 0:
            self.update_status("无法撤销：已处于最初状态")
            return
        
        self.history_index -= 1
        self._load_history_state()
        self.update_status(f"已撤销到状态{self.history_index + 1}/{len(self.history)}")

    def redo(self):
        if self.history_index >= len(self.history) - 1:
            self.update_status("无法重做：已处于最新状态")
            return
        
        self.history_index += 1
        self._load_history_state()
        self.update_status(f"已重做到状态 {self.history_index + 1}/{len(self.history)}")

    def _load_history_state(self):
        self.file_data = copy.copy(self.history[self.history_index])
        self.hex_viewer.set_data(self.file_data)
    
        self.hex_viewer.update_view()
        self.root.update_idletasks()

    def save_history_state(self):
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]
    
        self.history.append(copy.copy(self.file_data))
        self.history_index = len(self.history) - 1

        if len(self.history) > self.max_history_items:
            self.history.pop(0)
            self.history_index -= 1

        self.update_status(f"当前状态已保存(共{len(self.history)}个历史状态)")

    def replace_current(self):
        if self.current_match_index < 0 or self.current_match_index >= len(self.current_matches):
            self.update_status("没有选中的匹配项")
            return

        if self.find_mode == "text":
            find_str = self.find_text.get("1.0", tk.END).strip()
        else:
            find_str = self.find_hex_entry.get().strip()

        replace_str = self.replace_text.get("1.0", tk.END).strip()

        if not find_str or not replace_str:
            self.update_status("请输入查找内容和替换内容")
            return

        find_bytes = self.input_to_bytes(find_str)
        replace_bytes = self.input_to_bytes(replace_str)

        if not find_bytes or not replace_bytes:
            return

        original_length = len(find_bytes)
        replace_length = len(replace_bytes)
        encoding = self.encoding_var.get()
        if encoding in ['utf-16le', 'utf-16be'] and (original_length - replace_length) % 2 != 0:
            padding_length = original_length - replace_length
            if padding_length % 2 != 0:
                padding_length += 1
        if replace_length > original_length:
            excess_bytes = replace_length - original_length
            messagebox.showerror("替换失败", f"替换内容比查找内容多{excess_bytes}字节，无法直接替换\n请修改替换内容长度或使用其他方式处理。")
            self.update_status(f"替换失败：字节数超出{excess_bytes}")
            return

        match = self.current_matches[self.current_match_index]
        pos = match["pos"]
        original_length = len(find_bytes)
        replace_length = len(replace_bytes)

        if replace_length < original_length:
            padding = self.get_padding_bytes(original_length - replace_length)
            replace_bytes = replace_bytes + padding
            self.update_status(f"替换内容较短，已使用填充字节: {bytes_to_hex(padding)}")
        
        for i in range(len(replace_bytes)):
            self.file_data[pos + i] = replace_bytes[i]

        match["bytes"] = replace_bytes
        self.results_tree.item(self.results_tree.get_children()[self.current_match_index],
             values=(f"0x{pos:08X}", bytes_to_hex(replace_bytes)))

        self.hex_viewer.set_data(self.file_data)
        self.hex_viewer.highlight_range(pos, pos + len(replace_bytes))

        self.find_text.config(state=tk.NORMAL)
        self.find_text.delete("1.0", tk.END)
        self.find_text.config(state=tk.DISABLED)

        self.find_hex_entry.delete(0, tk.END)
        self.replace_text.delete("1.0", tk.END)
        self.replace_hex_entry.delete(0, tk.END)

        self.update_status(f"已替换位置0x{pos:08X}的内容")
        self.replace_button.config(state=tk.DISABLED)
        self.replace_all_button.config(state=tk.DISABLED)
        self.replace_text.config(state=tk.DISABLED)
        self.replace_hex_entry.config(state=tk.DISABLED)
        self.replace_buttons_disabled = True
        self.save_history_state()

    def replace_all(self):
        if not self.current_matches:
            self.update_status("没有匹配项可替换")
            return

        if self.find_mode == "text":
            find_str = self.find_text.get("1.0", tk.END).strip()
        else:
            find_str = self.find_hex_entry.get().strip()

        replace_str = self.replace_text.get("1.0", tk.END).strip()

        if not find_str or not replace_str:
            self.update_status("请输入查找内容和替换内容")
            return

        find_bytes = self.input_to_bytes(find_str)
        replace_bytes = self.input_to_bytes(replace_str)

        if not find_bytes or not replace_bytes:
            return

        original_length = len(find_bytes)
        replace_length = len(replace_bytes)
        encoding = self.encoding_var.get()
        if encoding in ['utf-16le', 'utf-16be'] and (original_length - replace_length) % 2 != 0:
            padding_length = original_length - replace_length
            if padding_length % 2 != 0:
                padding_length += 1
    
        if replace_length > original_length:
            excess_bytes = replace_length - original_length
            messagebox.showerror("替换失败", f"替换内容比查找内容多{excess_bytes}字节，无法直接替换。\n请修改替换内容长度或使用其他方式处理。")
            self.update_status(f"替换失败：字节数超出{excess_bytes}")
            return

        for match in sorted(self.current_matches, key=lambda x: x["pos"], reverse=True):
            pos = match["pos"]
            original_length = len(find_bytes)
            replace_length = len(replace_bytes)

            if replace_length < original_length:
                padding = self.get_padding_bytes(original_length - replace_length)
                replace_bytes = replace_bytes + padding
            elif replace_length > original_length:
                new_pos = self.find_free_space(replace_length)
                if new_pos != -1:
                    self.move_data(pos, new_pos, original_length)
                    match["pos"] = new_pos
                    pos = new_pos
                else:
                    self.update_status("没有足够的空白区域，跳过替换位置0x{pos:08X}")
                    continue

            for i in range(len(replace_bytes)):
                self.file_data[pos + i] = replace_bytes[i]

            match["bytes"] = replace_bytes

        self.find_text.config(state=tk.NORMAL)
        self.find_text.delete("1.0", tk.END)
        self.find_text.config(state=tk.DISABLED)

        self.find_hex_entry.delete(0, tk.END)
        self.replace_text.delete("1.0", tk.END)
        self.replace_hex_entry.delete(0, tk.END)

        self.find_matches()
        self.hex_viewer.set_data(self.file_data)
        self.update_status(f"已替换所有匹配项")
        self.save_history_state()

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

    def find_free_space(self, length):
        target = bytes([0x20] * length)
        return self.file_data.find(target)

    def move_data(self, src_pos, dest_pos, length):
        if src_pos == dest_pos:
            return

        data = self.file_data[src_pos:src_pos + length]

        if dest_pos > src_pos:
            for i in range(length - 1, -1, -1):
                self.file_data[dest_pos + i] = data[i]
        else:
            for i in range(length):
                self.file_data[dest_pos + i] = data[i]

class HexViewer:
    def __init__(self, master, width=80, height=16, app=None):
        self.master = master
        self.app = app
        self.width = width
        self.height = height
        self.bytes_per_line = 16
        self.current_encoding = 'utf-8'
        self.scroll_command = None
        self.bytes_per_line_options = [8, 16, 32, 48]
        self.byte_colors = {
            0x0A: 'blue',     # 0A 换行符 蓝色
            0x0D: 'purple',   # 0D 回车符 紫色
            0x00: 'red',      # 00 终止符 红色
            0xFF: 'pink',    # FF  内存填充 粉色
            0x20: 'green',   # 20 空格 绿色
        }

        self.utf16_colors = {
            (0x0A, 0x00): 'blue',    # UTF-16LE 0A00 蓝色
            (0x00, 0x0A): 'blue',    # UTF-16BE 000A 蓝色
            (0x0D, 0x00): 'purple', # UTF-16LE 0D00 紫色
            (0x00, 0x0D): 'purple',  # UTF-16BE 000D 紫色
            (0x00, 0x00): 'red',    # UTF-16 0000 红色
            (0xFF, 0xFF): 'pink',    # UTF-16 FFFF 粉色
            (0x20, 0x00): 'green',  # UTF-16LE 2000 绿色
            (0x00, 0x20): 'green',   # UTF-16BE 0020 绿色
        }
        self.non_printable_color = 'purple'
        self.create_widgets()

        self.start_address = 0
        self.highlight_start = -1
        self.highlight_end = -1

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
        
    def set_scroll_command(self, command):
        self.scroll_command = command
        self.hex_text.config(yscrollcommand=command)
        self.address_text.config(yscrollcommand=command)
        self.ascii_text.config(yscrollcommand=command)

    def set_data(self, data):
        self.hex_text.delete('1.0', tk.END)
        self.ascii_text.delete('1.0', tk.END)
        for i in range(0, len(data), self.bytes_per_line):
            line = data[i:i + self.bytes_per_line]
            hex_line = ' '.join(f'{b:02X}' for b in line).ljust(self.bytes_per_line * 3)
            ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line).ljust(self.bytes_per_line)
            self.hex_text.insert(tk.END, hex_line + '\n')
            self.ascii_text.insert(tk.END, ascii_line + '\n')

    def set_scrollbar(self, scroll_command):
        self.hex_text.config(yscrollcommand=scroll_command)
        self.ascii_text.config(yscrollcommand=scroll_command)

    def yview(self, *args):
        self.hex_text.yview(*args)
        self.ascii_text.yview(*args)

    def create_widgets(self):
        frame = ttk.Frame(self.master)
        frame.pack(fill=tk.BOTH, expand=True)

        byte_options_frame = ttk.Frame(frame)
        byte_options_frame.pack(fill=tk.X, pady=(0, 5))

        ttk.Label(byte_options_frame, text="每行字节数:").pack(side=tk.LEFT, padx=5)

        for option in self.bytes_per_line_options:
            btn = ttk.Button(byte_options_frame, text=str(option),
                             command=lambda opt=option: self.set_bytes_per_line(opt))
            btn.pack(side=tk.LEFT, padx=2)

        self.address_text = tk.Text(frame, width=10, height=self.height, wrap=tk.NONE,
                                    font=("Consolas", 10), state=tk.DISABLED)
        self.address_text.pack(side=tk.LEFT, fill=tk.Y)

        self.hex_text = tk.Text(frame, width=self.width, height=self.height, wrap=tk.NONE,
                                font=("Consolas", 10), state=tk.DISABLED)
        self.hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.ascii_text = tk.Text(frame, width=self.bytes_per_line, height=self.height, wrap=tk.NONE,
                                  font=("Consolas", 10), state=tk.DISABLED)
        self.ascii_text.pack(side=tk.LEFT, fill=tk.Y)

        self.vscrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                                        command=self._on_scroll)
        self.vscrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.hex_text.config(yscrollcommand=self._on_scrollbar)
        self.address_text.config(yscrollcommand=self.vscrollbar.set)
        self.ascii_text.config(yscrollcommand=self.vscrollbar.set)

        self.hex_text.tag_configure("highlight", background="orange")
        self.ascii_text.tag_configure("highlight", background="skyblue")
        self.hex_text.tag_configure("non_printable", foreground="purple")
        self.ascii_text.tag_configure("non_printable", foreground="purple")

        for byte_value, color in self.byte_colors.items():
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

    def set_data(self, data):
        self.data = data
        self.update_view()

    def _on_scrollbar(self, *args):

        self.vscrollbar.set(*args)

    def set_encoding(self, encoding):
        self.current_encoding = encoding
        self.update_view()
    def update_view(self):
        self.address_text.config(state=tk.NORMAL)
        self.hex_text.config(state=tk.NORMAL)
        self.ascii_text.config(state=tk.NORMAL)

        self.address_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        self.ascii_text.delete(1.0, tk.END)

        max_lines = min(self.height, (len(self.data) - self.start_address + self.bytes_per_line - 1) // self.bytes_per_line)

        for i in range(max_lines):
            line_addr = self.start_address + i * self.bytes_per_line
            self.address_text.insert(tk.END, f"{line_addr:08X}\n")

            line_data = self.data[line_addr:line_addr + self.bytes_per_line]

            for j, byte in enumerate(line_data):
                byte_addr = line_addr + j
                is_highlighted = (self.highlight_start <= byte_addr < self.highlight_end)

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
            visible_lines = min(self.height, total_lines)
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
        self.context_menu = tk.Menu(self.master, tearoff=0)
        self.context_menu.add_command(label="修改为空格(0x20)", command=self.convert_to_space)
        self.context_menu.add_command(label="插入字节", command=self.insert_bytes)
        self.context_menu.add_command(label="删除字节", command=self.delete_bytes)
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
        self.highlight_start = start
        self.highlight_end = end
        self.update_view()

def bytes_to_hex(byte_data):
    return ' '.join([f"{b:02X}" for b in byte_data])

if __name__ == "__main__":
    try:
        from tkinterdnd2 import TkinterDnD
        root = TkinterDnD.Tk()
    except ImportError:
        root = tk.Tk()
        print("警告:tkinterdnd2未安装，拖拽功能将不可用")
    app = BinaryEditorApp(root)
    root.mainloop()
