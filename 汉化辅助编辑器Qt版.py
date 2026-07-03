# -*- coding: utf-8 -*-
import os
import sys
import copy
import re
import json
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
from datetime import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QFileDialog, QMessageBox, QMenu,
    QToolBar, QLabel, QTreeWidget, QTreeWidgetItem,
    QLineEdit, QPushButton, QComboBox, QTextEdit, QDialog,
    QProgressDialog, QStyle, QAbstractItemView,
    QGroupBox, QFormLayout, QInputDialog
)
from PySide6.QtCore import Qt, QTimer, QSettings, QFile, QPoint
from PySide6.QtGui import QFont, QColor, QPalette, QCursor
from PySide6.QtWidgets import QStyleFactory

from pyhexedit import PyHexEdit
from pyhexedit.pyhexedit import _isInvisibleChar


class UTF16TextEdit(QTextEdit):
    def __init__(self, converter_func, parent=None):
        super().__init__(parent)
        self.converter_func = converter_func

    def insertFromMimeData(self, source):
        if source.hasText():
            text = source.text()
            converted = self.converter_func(text)
            self.insertPlainText(converted)
        else:
            super().insertFromMimeData(source)


class HexEditor(PyHexEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._is_dark_theme = False
        self.setAcceptDrops(True)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        self._scroll_timer = QTimer()
        self._scroll_timer.timeout.connect(self._auto_scroll)
        self._scroll_direction = 0

    def show_context_menu(self, pos):
        menu = QMenu(self)
        menu.setToolTipsVisible(True)

        select_all_action = menu.addAction("全选(Ctrl+A)")
        select_all_action.triggered.connect(lambda: self.window().select_all())

        copy_hex_action = menu.addAction("复制为十六进制")
        copy_hex_action.setToolTip("框选一段内容,仅复制十六进制字节序列")
        copy_hex_action.triggered.connect(lambda: self.window().copy_as_hex())

        copy_ascii_action = menu.addAction("复制为ASCII")
        copy_ascii_action.setToolTip("框选一段内容,仅复制ASCII字符串")
        copy_ascii_action.triggered.connect(lambda: self.window().copy_as_ascii())

        copy_utf16_action = menu.addAction("复制Unicode为ASCII")
        copy_utf16_action.setToolTip("复制UTF-16点分隔文本并自动转换为ASCII")
        copy_utf16_action.triggered.connect(lambda: self.window().copy_as_utf16_to_ascii())

        menu.addSeparator()

        modify_space_action = menu.addAction("✏️ 修改为空格(0x20)")
        modify_space_action.setToolTip("选择你要修改的不可打印字符对应的字节(如回车、换行、制表),将其改成0x20(空格)")
        modify_space_action.triggered.connect(lambda: self.window().convert_selection_to_space())

        insert_bytes_action = menu.addAction("➕ 插入字节")
        insert_bytes_action.setToolTip("在当前光标位置插入指定数量的字节")
        insert_bytes_action.triggered.connect(lambda: self.window().insert_bytes_at_cursor())

        delete_bytes_action = menu.addAction("➖ 删除字节")
        delete_bytes_action.setToolTip("从当前光标位置删除指定数量的字节")
        delete_bytes_action.triggered.connect(lambda: self.window().delete_bytes_at_cursor())

        export_action = menu.addAction("📤 导出范围字节")
        export_action.setToolTip("如果你想导出一个游戏文件里面的一段数据进行研究,不妨试试此功能")
        export_action.triggered.connect(lambda: self.window().show_export_dialog())

        menu.addSeparator()

        find_action = menu.addAction("查找替换(Ctrl+F)")
        find_action.setToolTip("查找要汉化的文本或十六进制,替换原始内容为你的汉化内容")
        find_action.triggered.connect(lambda: self.window().show_find_dialog())

        menu.exec(QCursor.pos())

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        event.accept()

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if file_path:
                    self.window().load_file(file_path, show_message=False)
                    event.acceptProposedAction()
                    return
        event.ignore()

    def setSelection(self, start, end):
        if end < start:
            end, start = start, end
        if not hasattr(self, '_data') or self._data is None:
            return

        bytes_per_line = 16
        start_line = start // bytes_per_line
        end_line = end // bytes_per_line

        start_col = (start % bytes_per_line) * 3
        end_col = ((end % bytes_per_line) + 1) * 3 - 1

        self._invalidateSelection()
        self._cursor.moveTo(start_line, start_col, False)
        self._cursor.selectTo(end_line, end_col)
        self._invalidateSelection()
        self.selectionChanged.emit()

    def getSelection(self):
        if not self._cursor.hasSelection():
            return None, None

        begin = (self._cursor.beginPos() + 1) // 3
        end = (self._cursor.endPos() + 1) // 3
        begin += self._cursor.beginLine() * self._bytesPerLine
        end += self._cursor.endLine() * self._bytesPerLine
        return begin, end

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if event.button() == Qt.LeftButton:
            self._scroll_direction = 0

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        if event.buttons() != Qt.LeftButton:
            return
        viewport_height = self.viewport().height()
        mouse_y = event.position().y()
        edge_size = 30

        if mouse_y < edge_size:
            self._scroll_direction = -1
            self._scroll_timer.start(20)
        elif mouse_y > viewport_height - edge_size:
            self._scroll_direction = 1
            self._scroll_timer.start(20)
        else:
            self._scroll_direction = 0
            self._scroll_timer.stop()

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self._scroll_timer.stop()
        self._scroll_direction = 0

    def _auto_scroll(self):
        if self._scroll_direction == 0:
            return
        current = self.verticalScrollBar().value()
        max_val = self.verticalScrollBar().maximum()
        if self._scroll_direction == -1:
            new_val = max(0, current - 1)
            self.verticalScrollBar().setValue(new_val)
        elif self._scroll_direction == 1:
            new_val = min(max_val, current + 1)
            self.verticalScrollBar().setValue(new_val)
        if hasattr(self, '_cursor') and self._data:
            pos = QPoint(self.viewport().width() // 2, 
                        30 if self._scroll_direction == -1 else self.viewport().height() - 30)
            self._invalidateSelection()
            content_pos = self.mapToContents(pos)
            r, c = self.rowColForPos(content_pos, self._cursor.inAsciiView())
            self._cursor.selectTo(r, c)
            self._invalidateSelection()
            self.selectionChanged.emit()

    def scrollToAddress(self, address):
        if not self._data or address < 0 or address >= len(self._data):
            return
        row = address // self._bytesPerLine
        scrollbar = self.verticalScrollBar()
        lines_per_page = self.linesPerPage()
        target_value = max(0, row - (lines_per_page // 2))
        scrollbar.setValue(target_value)

    def setTheme(self, theme):
        self._is_dark_theme = (theme == "dark")
        self.setDarkTheme(self._is_dark_theme)
        if self._is_dark_theme:
            self.setStyleSheet("""
                QAbstractScrollArea {
                    background-color: rgb(35, 35, 35);
                }
            """)
        else:
            self.setStyleSheet("""
                QAbstractScrollArea {
                    background-color: rgb(255, 255, 255);
                }
            """)
        self.viewport().update()

    def paintEvent(self, event):
        from PySide6.QtGui import QPainter, QPen

        if not self._data or len(self._data) == 0:
            return

        painter = QPainter(self.viewport())
        painter.setFont(self._font)

        offset = self.contentOffset()
        eventRect = event.rect()

        if eventRect.isValid():
            startLine = self.rowForPos(eventRect.topLeft())
            endLine = self.rowForPos(eventRect.bottomRight()) + 1
        else:
            startLine = self.firstVisibleLine()
            endLine = startLine + self.linesPerPage() + 1
        endLine = min(self.lineCount(), endLine)

        viewportRect = self.viewport().rect()
        painter.setClipRect(eventRect)

        oldPen = painter.pen()
        painter.setPen(QPen(Qt.gray))
        spaceWidth = self._charWidth // 2
        painter.drawLine(self._addrWidth + spaceWidth, 0,
                         self._addrWidth + spaceWidth, viewportRect.height())
        xAscii = self._asciiPosX + offset.x()
        xAsciiLine = xAscii - spaceWidth
        painter.drawLine(xAsciiLine, 0, xAsciiLine, viewportRect.height())
        painter.setPen(oldPen)

        self._drawSelection(painter, startLine, endLine)

        x = offset.x() + self._hexPosX
        y = self._ascent + (startLine - self.firstVisibleLine()) * self._lineHeight
        start = startLine * self._bytesPerLine
        end = min(endLine * self._bytesPerLine, len(self._data))
        lineNum = startLine

        self._drawAddress(painter, spaceWidth, y, lineNum)

        for i in range(start, end):
            if i != start and i % self._bytesPerLine == 0:
                y += self._lineHeight
                x = offset.x() + self._hexPosX
                xAscii = self._asciiPosX + offset.x()
                lineNum += 1
                self._drawAddress(painter, spaceWidth, y, lineNum)

            if y > self.viewport().height():
                break

            ch = self._data[i]
            oldClip = painter.clipRegion()
            painter.setClipRect(self._hexPosX, y - self._ascent,
                                viewportRect.width(), self._lineHeight)
            color = self._byteColor(ch)
            if color:
                painter.setPen(color)

            strHex = format(ch, "02X")
            painter.drawText(x, y, strHex)
            x += self._charWidth * 3

            if color:
                painter.setPen(oldPen)
            painter.setClipRegion(oldClip)
            if _isInvisibleChar(ch):
                strAscii = "."
                painter.setPen(self._byteColor(ch) or Qt.gray)
            else:
                strAscii = chr(ch)
                if color:
                    painter.setPen(color)
            painter.drawText(xAscii, y, strAscii)
            painter.setPen(oldPen)
            xAscii += self._charWidth

        self._drawCursor(painter, startLine, endLine)

    @staticmethod
    def _byteColor(ch):
        colors = {
            0x00: QColor(241, 76, 76),   # 红
            0x0A: QColor(86, 156, 214),  # 蓝
            0x0D: QColor(197, 134, 192), # 紫
            0x20: QColor(80, 250, 123),  # 绿
            0xFF: QColor(255, 121, 196), # 粉
        }
        return colors.get(ch)

    def _drawSelection(self, painter, startLine, endLine):
        if not self._cursor.hasSelection() and not self._cursor.isValid():
            return
        if not self._cursor.hasSelection():
            cursorLine = self._cursor.beginLine()
            if cursorLine < startLine or cursorLine > endLine:
                return
            cursorCol = self._cursor.beginPos()
            byteIndex = (cursorCol + 1) // 3
            brush = QColor(80, 120, 180) if self._is_dark_theme else QColor(180, 210, 240)
            xOffset = self.contentOffset().x()
            y = (cursorLine - self.firstVisibleLine()) * self._lineHeight
            xHex = self._hexPosX + xOffset + cursorCol * self._charWidth
            painter.fillRect(xHex, y, self._charWidth * 2, self._lineHeight, brush)
            xAscii = self._asciiPosX + xOffset + byteIndex * self._charWidth
            painter.fillRect(xAscii, y, self._charWidth, self._lineHeight, brush)
            return
        brush = QColor(30, 100, 200) if self._is_dark_theme else QColor(51, 133, 255)

        beginRow = self._cursor.beginLine()
        endRow = self._cursor.endLine()
        beginCol = self._cursor.beginPos()
        endCol = self._cursor.endPos()

        def _calcX(col, forHex):
            if forHex:
                return col * self._charWidth
            return (col + 1) // 3 * self._charWidth

        def _calcWidth(col, forHex):
            if forHex:
                return col * self._charWidth
            return (col + 1) // 3 * self._charWidth

        oldClip = painter.clipRegion()
        rc = self.viewport().rect()
        painter.setClipRect(self._hexPosX, 0, rc.width(), rc.height())

        if self._cursor.hasMultiLines():
            def _doDraw(xOffset, forHex):
                x = xOffset + _calcX(beginCol, forHex)
                w = _calcWidth(self._charsPerLine - beginCol, forHex)
                y = (beginRow - self.firstVisibleLine()) * self._lineHeight
                h = self._lineHeight
                painter.fillRect(x, y, w, h, brush)

                if (endRow - 1) > beginRow:
                    x = xOffset
                    y += self._lineHeight
                    w = _calcWidth(self._charsPerLine, forHex)
                    h = (endRow - 1 - beginRow) * self._lineHeight
                    painter.fillRect(x, y, w, h, brush)

                x = xOffset
                y = (endRow - self.firstVisibleLine()) * self._lineHeight
                w = _calcWidth(endCol, forHex)
                h = self._lineHeight
                painter.fillRect(x, y, w, h, brush)

            xOffset = self.contentOffset().x()
            _doDraw(self._hexPosX + xOffset, True)
            _doDraw(self._asciiPosX + xOffset, False)
        else:
            def _doDraw(xOffset, forHex):
                x = xOffset + _calcX(beginCol, forHex)
                y = (beginRow - self.firstVisibleLine()) * self._lineHeight
                w = _calcWidth(endCol - beginCol, forHex)
                h = self._lineHeight
                painter.fillRect(x, y, w, h, brush)

            xOffset = self.contentOffset().x()
            _doDraw(self._hexPosX + xOffset, True)
            _doDraw(self._asciiPosX + xOffset, False)

        painter.setClipRegion(oldClip)

APP_NAME = "汉化辅助编辑器"
APP_VERSION = "1.0 Qt版"


def get_config_file_path():
    app_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(app_dir, 'editor_config.json')


def load_config():
    config_file = get_config_file_path()
    default_config = {
        'theme': 'dark',
        'encoding': 'utf-8',
        'scan_mode': 'ansi',
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return {**default_config, **config}
        except Exception:
            return default_config
    return default_config


def save_config(config):
    config_file = get_config_file_path()
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存配置失败:{e}")


def is_likely_valid_text(text):
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
    words = re.findall(r'[A-Za-z]{3,}', text)
    if len(words) >= 1:
        return True
    if any(c in ' .,:;!?()' for c in text):
        return True
    return False


def is_basic_english(text):
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


def bytes_to_hex(byte_data):
    return ' '.join([f"{b:02X}" for b in byte_data])


class StringEntry:
    def __init__(self, id, address, length, text, original_text, translated_text, bytes_data, encoding):
        self.id = id
        self.address = address
        self.length = length
        self.text = text
        self.original_text = original_text
        self.translated_text = translated_text
        self.bytes = bytes_data
        self.encoding = encoding


class BinaryEditorQt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.file_path = ""
        self.file_data = bytearray()
        self.original_data = None
        self.history = []
        self.history_index = 0
        self.max_history_items = 100
        self.string_entries = []
        self.current_string_index = -1
        self.current_scan_mode = None
        self.current_segments = []
        self.current_mapping_data = {}
        self.pending_changes = False
        self.find_matches = []
        self.current_match_index = -1

        self.encoding_options = [
            'utf-8', 'gbk', 'utf-16le', 'utf-16be',
            'shift_jis', 'euc-jp', 'big5', 'gb2312',
            'iso-8859-1', 'utf-7', 'ascii', 'latin1'
        ]

        self.scan_mode_options = ['ansi', 'unicode_le', 'unicode_be']

        self.settings = QSettings("BinaryEditorQt", "Settings")
        self.config = load_config()

        self.init_ui()
        self.apply_theme(self.config.get("theme", "dark"))
        self.setAcceptDrops(True)
        self.update_status("就绪-请打开文件")

    def init_ui(self):
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setGeometry(100, 100, 1400, 900)

        self.setup_ui_components()
        self.setup_dock_widgets()
        self.setup_connections()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(5, 5, 5, 5)

        self.main_splitter = QSplitter(Qt.Horizontal)

        self.sidebar_widget = self.create_sidebar()
        self.main_splitter.addWidget(self.sidebar_widget)

        self.hex_editor_container = QWidget()
        hex_layout = QVBoxLayout(self.hex_editor_container)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.addWidget(self.hex_editor)
        self.main_splitter.addWidget(self.hex_editor_container)

        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 3)

        main_layout.addWidget(self.main_splitter)

        self.statusBar().showMessage("就绪")

        QTimer.singleShot(100, self.restore_ui_state)

    def setup_ui_components(self):
        toolbar = QToolBar("主工具栏")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel("扫描模式:"))
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItems(['ansi', 'unicode_le', 'unicode_be'])
        self.scan_mode_combo.setCurrentText(self.config.get("scan_mode", "ansi"))
        self.scan_mode_combo.currentIndexChanged.connect(self.on_scan_mode_changed)
        toolbar.addWidget(self.scan_mode_combo)

        toolbar.addSeparator()

        toolbar.addWidget(QLabel("编码:"))
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems(self.encoding_options)
        self.encoding_combo.setCurrentText(self.config.get("encoding", "utf-8"))
        toolbar.addWidget(self.encoding_combo)

        toolbar.addSeparator()

        self.scan_button = QPushButton("扫描字符串")
        self.scan_button.clicked.connect(self.scan_strings)
        toolbar.addWidget(self.scan_button)

        toolbar.addSeparator()

        toolbar.addWidget(QLabel("文件:"))
        self.file_label = QLabel("未选择文件")
        toolbar.addWidget(self.file_label)

        toolbar.addSeparator()
        self.drop_hint = QLabel("拖放文件到此处打开文件")
        self.drop_hint.setStyleSheet("color: gray;")
        toolbar.addWidget(self.drop_hint)

        self.hex_editor = HexEditor()
        self.hex_editor.setData(bytearray())

        self.setup_menu_bar()
        from PySide6.QtGui import QShortcut, QKeySequence
        QShortcut(QKeySequence("Ctrl+O"), self, self.open_file)
        QShortcut(QKeySequence("Ctrl+S"), self, self.save_file)
        QShortcut(QKeySequence("Ctrl+Shift+S"), self, self.save_file_as)
        QShortcut(QKeySequence("Ctrl+Q"), self, self.close)
        QShortcut(QKeySequence("Ctrl+Z"), self, self.undo)
        QShortcut(QKeySequence("Ctrl+Y"), self, self.redo)
        QShortcut(QKeySequence("Ctrl+F"), self, self.show_find_dialog)
        QShortcut(QKeySequence("F7"), self, self.show_cp932_converter)
        QShortcut(QKeySequence("F8"), self, self.show_utf16_converter)
        QShortcut(QKeySequence("Ctrl+I"), self, self.insert_bytes_at_cursor)
        QShortcut(QKeySequence("Ctrl+D"), self, self.delete_bytes_at_cursor)

    def setup_menu_bar(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("📁 文件")
        file_menu.addAction("📂 打开文件", self.open_file, "Ctrl+O")
        file_menu.addAction("💾 保存", self.save_file, "Ctrl+S")
        file_menu.addAction("📁 另存为", self.save_file_as, "Ctrl+Shift+S")
        file_menu.addSeparator()
        file_menu.addAction("❌ 退出", self.close, "Ctrl+Q")
        edit_menu = menubar.addMenu("🔧 工具")
        edit_menu.addAction("↩️ 撤销", self.undo, "Ctrl+Z")
        edit_menu.addAction("↪️ 重做", self.redo, "Ctrl+Y")
        edit_menu.addSeparator()
        edit_menu.addAction("🎨 亮色主题", lambda: self.apply_theme('light'))
        edit_menu.addAction("🌙 暗色主题", lambda: self.apply_theme('dark'))
        edit_menu.addSeparator()
        edit_menu.addAction("🔧 CP932乱码修复器", self.show_cp932_converter, "F7")
        edit_menu.addAction("🔧 UTF-16字符串转换器", self.show_utf16_converter, "F8")
        help_menu = menubar.addMenu("📖 帮助")
        help_menu.addAction("ℹ️ 关于此工具", self.show_about)

    def setup_dock_widgets(self):
        pass

    def create_sidebar(self):
        sidebar = QWidget()
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        filter_layout = QHBoxLayout()
        filter_layout.setContentsMargins(2, 2, 2, 2)
        filter_label = QLabel("🔍 筛选:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("输入关键词实时筛选字符串列表")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self.on_filter_changed)
        self.case_sensitive_checkbox = QPushButton("Aa")
        self.case_sensitive_checkbox.setCheckable(True)
        self.case_sensitive_checkbox.setChecked(True)
        self.case_sensitive_checkbox.setFixedWidth(32)
        self.case_sensitive_checkbox.setToolTip("大小写敏感(按下为开启)")
        self.case_sensitive_checkbox.clicked.connect(lambda checked: self.on_filter_changed(self.filter_input.text()))
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.case_sensitive_checkbox)
        layout.addLayout(filter_layout)

        self.string_tree = QTreeWidget()
        self.string_tree.setHeaderLabels(["ID", "地址", "长度", "内容"])
        self.string_tree.setColumnWidth(0, 50)
        self.string_tree.setColumnWidth(1, 100)
        self.string_tree.setColumnWidth(2, 60)
        self.string_tree.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.string_tree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.string_tree.itemClicked.connect(self.on_string_clicked)
        self.string_tree.itemDoubleClicked.connect(self.on_string_double_clicked)
        layout.addWidget(self.string_tree)

        translate_frame = QWidget()
        translate_layout = QVBoxLayout(translate_frame)
        translate_layout.setContentsMargins(5, 5, 5, 5)

        translate_layout.addWidget(QLabel("原始文本:"))
        self.original_text_edit = QTextEdit()
        self.original_text_edit.setMaximumHeight(80)
        self.original_text_edit.setReadOnly(True)
        translate_layout.addWidget(self.original_text_edit)

        translate_layout.addWidget(QLabel("翻译文本:"))
        self.translated_text_edit = QTextEdit()
        self.translated_text_edit.setMaximumHeight(80)
        self.translated_text_edit.textChanged.connect(self.on_translation_changed)
        translate_layout.addWidget(self.translated_text_edit)

        button_layout = QHBoxLayout()
        self.apply_button = QPushButton("替换")
        self.apply_button.clicked.connect(self.apply_translation)
        button_layout.addWidget(self.apply_button)

        self.prev_button = QPushButton("上一条")
        self.prev_button.clicked.connect(self.prev_string)
        button_layout.addWidget(self.prev_button)

        self.next_button = QPushButton("下一条")
        self.next_button.clicked.connect(self.next_string)
        button_layout.addWidget(self.next_button)

        translate_layout.addLayout(button_layout)

        layout.addWidget(translate_frame)

        return sidebar

    def setup_connections(self):
        self.scan_mode_combo.currentIndexChanged.connect(self.on_scan_mode_changed)
        self.encoding_combo.currentIndexChanged.connect(self.on_encoding_changed)

    def restore_ui_state(self):
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)

    def apply_theme(self, theme):
        self.current_theme = theme
        self.settings.setValue("theme", theme)
        self.config["theme"] = theme
        save_config(self.config)

        if theme == "dark":
            QApplication.setStyle(QStyleFactory.create("Fusion"))
            palette = QPalette()
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, Qt.white)
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
            palette.setColor(QPalette.HighlightedText, Qt.black)
            QApplication.setPalette(palette)
        else:
            QApplication.setStyle(QStyleFactory.create("Fusion"))
            QApplication.setPalette(QApplication.style().standardPalette())

        self.hex_editor.setTheme(theme)
        self.update_status(f"已切换到{theme}主题")

    def open_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "打开文件", "", "所有文件(*.*)"
        )
        if path:
            self.load_file(path)

    def load_file(self, file_path, show_message=True):
        try:
            with open(file_path, "rb") as f:
                self.file_data = bytearray(f.read())

            self.file_path = file_path
            self.original_data = copy.copy(self.file_data)

            self.hex_editor.setData(self.file_data)

            base_name = os.path.basename(file_path)
            self.file_label.setText(f"{base_name} ({len(self.file_data)}字节)")

            self.history = [copy.copy(self.file_data)]
            self.history_index = 0
            self.string_entries = []
            self.all_string_entries = []
            self.current_string_index = -1
            self.string_tree.clear()
            self.find_matches = []
            self.current_match_index = -1

            self.save_ui_state()

            self.update_status(f"已加载文件:{base_name}")
            QTimer.singleShot(50, self.auto_load_mapping)

            if show_message:
                QMessageBox.information(self, "成功", f"文件已加载:\n{base_name}\n大小:{len(self.file_data)}字节")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"无法打开文件:\n{str(e)}")
            self.update_status(f"错误:{str(e)}")

    def auto_load_mapping(self):
        if not self.file_path:
            return

        scan_modes = ["ansi", "unicode_le", "unicode_be"]

        for scan_mode in scan_modes:
            mapping_file = self.get_mapping_file_path(scan_mode)
            if mapping_file and os.path.exists(mapping_file):
                try:
                    with open(mapping_file, 'r', encoding='utf-8') as f:
                        mapping_data = json.load(f)

                    if mapping_data.get('file_size') == len(self.file_data):
                        self.scan_mode_combo.setCurrentText(scan_mode)

                        if scan_mode == "ansi":
                            encoding = mapping_data.get('encoding', 'utf-8')
                            index = self.encoding_combo.findText(encoding)
                            if index >= 0:
                                self.encoding_combo.setCurrentIndex(index)
                        elif scan_mode == "unicode_le":
                            index = self.encoding_combo.findText("utf-16le")
                            if index >= 0:
                                self.encoding_combo.setCurrentIndex(index)
                        elif scan_mode == "unicode_be":
                            index = self.encoding_combo.findText("utf-16be")
                            if index >= 0:
                                self.encoding_combo.setCurrentIndex(index)

                        QTimer.singleShot(10, lambda: self.load_strings_from_mapping(mapping_data))
                        self.update_status(f"正在加载映射:{os.path.basename(mapping_file)}")
                        return
                    else:
                        self.update_status(f"映射文件大小不匹配,跳过:{os.path.basename(mapping_file)}")
                except Exception as e:
                    self.update_status(f"加载映射失败:{str(e)}")

    def save_file(self):
        if not self.file_path:
            self.save_file_as()
            return

        try:
            with open(self.file_path, "wb") as f:
                f.write(self.file_data)

            self.original_data = copy.copy(self.file_data)
            self.pending_changes = False
            self.update_status(f"文件已保存:{os.path.basename(self.file_path)}")
            QMessageBox.information(self, "成功", "文件已保存")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存文件失败:\n{str(e)}")

    def save_file_as(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "另存为", "", "所有文件(*.*)"
        )
        if path:
            self.file_path = path
            self.save_file()

    def get_mapping_file_path(self, scan_mode):
        if not self.file_path:
            return None
        dir_path = os.path.dirname(self.file_path)
        base_name = os.path.splitext(os.path.basename(self.file_path))[0]
        suffix = f"_{scan_mode}"
        mapping_file = os.path.join(dir_path, f"{base_name}{suffix}_mapping.json")
        return mapping_file

    def load_mapping_from_file(self, scan_mode):
        mapping_file = self.get_mapping_file_path(scan_mode)
        if not mapping_file or not os.path.exists(mapping_file):
            return None

        try:
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
            return self.encoding_combo.currentText()
        elif scan_mode == "unicode_le":
            return "utf-16le"
        elif scan_mode == "unicode_be":
            return "utf-16be"
        return "unknown"

    def save_current_mapping(self):
        if not self.file_path or not self.string_entries:
            return

        scan_mode = self.scan_mode_combo.currentText()
        mapping_file = self.get_mapping_file_path(scan_mode)
        if not mapping_file:
            return

        try:
            mapping_data = {
                'file_path': self.file_path,
                'file_name': os.path.basename(self.file_path),
                'file_size': len(self.file_data),
                'scan_mode': scan_mode,
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'encoding': self.get_encoding_for_scan_mode(scan_mode),
                'strings': []
            }

            for entry in self.string_entries:
                mapping_data['strings'].append({
                    'id': entry.id,
                    'address': entry.address,
                    'address_hex': f"0x{entry.address:08X}",
                    'length': entry.length,
                    'original_text': entry.original_text,
                    'translated_text': entry.translated_text,
                    'bytes_hex': bytes_to_hex(entry.bytes),
                    'encoding': entry.encoding
                })

            with open(mapping_file, 'w', encoding='utf-8') as f:
                json.dump(mapping_data, f, ensure_ascii=False, indent=2)

            self.pending_changes = False
            self.update_status(f"映射已更新:{os.path.basename(mapping_file)}")

        except Exception as e:
            self.update_status(f"保存映射失败:{str(e)}")

    def load_strings_from_mapping(self, mapping_data):
        self.string_entries = []
        self.all_string_entries = []
        self.string_tree.clear()

        for i, string_data in enumerate(mapping_data['strings']):
            entry = StringEntry(
                id=string_data['id'],
                address=string_data['address'],
                length=string_data['length'],
                text=string_data['original_text'],
                original_text=string_data['original_text'],
                translated_text=string_data.get('translated_text', ''),
                bytes_data=bytes.fromhex(string_data['bytes_hex'].replace(' ', '')) if string_data.get('bytes_hex') else b'',
                encoding=string_data.get('encoding', 'unknown')
            )
            self.string_entries.append(entry)
            self.all_string_entries.append(entry)

            display_text = string_data['original_text']
            if len(display_text) > 30:
                display_text = display_text[:27] + "..."

            item = QTreeWidgetItem([
                str(string_data['id']),
                string_data['address_hex'],
                str(string_data['length']),
                display_text
            ])
            self.string_tree.addTopLevelItem(item)

        if self.string_entries:
            self.string_tree.setCurrentItem(self.string_tree.topLevelItem(0))
            self.current_string_index = 0

    def on_scan_mode_changed(self, index=None):
        scan_mode = self.scan_mode_combo.currentText()
        self.settings.setValue("scan_mode", scan_mode)
        self.config["scan_mode"] = scan_mode
        save_config(self.config)

        if scan_mode == "unicode_le":
            index = self.encoding_combo.findText("utf-16le")
            if index >= 0:
                self.encoding_combo.setCurrentIndex(index)
            self.update_status("已切换到UTF-16LE扫描模式")
        elif scan_mode == "unicode_be":
            index = self.encoding_combo.findText("utf-16be")
            if index >= 0:
                self.encoding_combo.setCurrentIndex(index)
            self.update_status("已切换到UTF-16BE扫描模式")
        else:
            self.update_status("ANSI扫描模式:请手动选择编码,UTF-8或GBK")

        if self.file_data:
            QTimer.singleShot(10, self.scan_strings)

    def undo(self):
        if self.history_index > 0:
            self.history_index -= 1
            self.file_data = copy.copy(self.history[self.history_index])
            self.hex_editor.setData(self.file_data)
            self.update_status(f"已撤销到状态{self.history_index + 1}/{len(self.history)}")
        else:
            self.update_status("无法撤销:已处于最初状态")

    def redo(self):
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self.file_data = copy.copy(self.history[self.history_index])
            self.hex_editor.setData(self.file_data)
            self.update_status(f"已重做到状态{self.history_index + 1}/{len(self.history)}")
        else:
            self.update_status("无法重做:已处于最新状态")

    def select_all(self):
        if self.file_data:
            self.hex_editor.setSelection(0, len(self.file_data) - 1)

    def copy_as_hex(self):
        begin, end = self.hex_editor.getSelection()
        if begin is None or end is None:
            return
        selected_data = self.file_data[begin:end]
        hex_str = ' '.join(f'{b:02X}' for b in selected_data)
        clipboard = QApplication.clipboard()
        clipboard.setText(hex_str)
        self.update_status(f"已复制{end - begin}字节为十六进制")

    def convert_utf16_exe_text(self, text):
        if re.search(r'[0-9A-Fa-f]{2}\.[0-9A-Fa-f]{2}', text):
            cleaned = re.sub(r'[\n\r\t]', '', text)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            cleaned = re.sub(r'\.\.', '\n', cleaned)
            cleaned = re.sub(r'\.', '', cleaned)
            cleaned = re.sub('\n', '.', cleaned)
            return cleaned
        return text

    def copy_as_utf16_to_ascii(self):
        begin, end = self.hex_editor.getSelection()
        if begin is None or end is None:
            return
        selected_data = self.file_data[begin:end]
        length = end - begin
        if length % 2 != 0:
            QMessageBox.warning(self, "非法复制", "您正在进行非法操作,无法粘贴,请重试\nUTF-16文本必须是偶数个字节")
            return
        for i in range(0, length, 2):
            if i + 1 < length and selected_data[i] == 0x00 and selected_data[i+1] == 0x00:
                QMessageBox.warning(self, "非法复制", "您正在进行非法操作,无法粘贴,请重试\n选中内容包含无效的UTF-16序列")
                return
        
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in selected_data)
        converted = self.convert_utf16_exe_text(ascii_str)
        clipboard = QApplication.clipboard()
        clipboard.setText(converted)
        self.update_status(f"已复制 {end - begin} 字节并转换为UTF16文本")

    def convert_selection_to_space(self):
        begin, end = self.hex_editor.getSelection()
        if begin is None or end is None:
            QMessageBox.warning(self, "提示", "请先选中要修改的字节范围")
            return
        
        count = 0
        for i in range(begin, end):
            if self.file_data[i] != 0x20:
                self.file_data[i] = 0x20
                count += 1
        
        if count > 0:
            self.save_history_state()
            self.hex_editor.setData(self.file_data)
            self.update_status(f"已将{count}个字节修改为空格(0x20)")
        else:
            self.update_status("选中的字节已经都是空格")

    def insert_bytes_at_cursor(self):
        begin, end = self.hex_editor.getSelection()
        if begin is None:
            QMessageBox.warning(self, "提示", "请先在十六进制视图中点击要插入的位置")
            return

        dialog = QInputDialog(self)
        dialog.setWindowTitle("插入字节")
        dialog.setLabelText("请输入要插入的字节数量:")
        dialog.setIntRange(1, 10000)
        dialog.setIntValue(1)
        if not dialog.exec():
            return
        count = dialog.intValue()

        byte_value_dialog = QInputDialog(self)
        byte_value_dialog.setWindowTitle("字节值")
        byte_value_dialog.setLabelText("请输入要插入的字节值(十六进制,默认20):")
        byte_value_dialog.setTextValue("20")
        if not byte_value_dialog.exec():
            return
        byte_value_str = byte_value_dialog.textValue().strip()
        if not byte_value_str:
            byte_value_str = "20"

        try:
            byte_value = int(byte_value_str, 16)
            if not (0 <= byte_value <= 255):
                raise ValueError
        except ValueError:
            QMessageBox.critical(self, "错误", "请输入有效的十六进制字节值(00-FF)")
            return

        self.save_history_state()
        for i in range(count):
            self.file_data.insert(begin + i, byte_value)

        self.hex_editor.setData(self.file_data)
        self.hex_editor.setSelection(begin, begin + count - 1)
        self.update_status(f"已在位置0x{begin:08X}插入{count}个字节(值:0x{byte_value:02X})")

    def delete_bytes_at_cursor(self):
        begin, end = self.hex_editor.getSelection()
        if begin is None:
            QMessageBox.warning(self, "提示", "请先在十六进制视图中点击要删除的起始位置")
            return

        max_count = len(self.file_data) - begin
        dialog = QInputDialog(self)
        dialog.setWindowTitle("删除字节")
        dialog.setLabelText(f"请输入要删除的字节数量(最大{max_count}):")
        dialog.setIntRange(1, max_count)
        dialog.setIntValue(1)
        if not dialog.exec():
            return
        count = dialog.intValue()

        reply = QMessageBox.question(
            self, "确认删除",
            f"确定要删除从位置0x{begin:08X}开始的{count}个字节吗?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        self.save_history_state()
        del self.file_data[begin:begin + count]
        self.hex_editor.setData(self.file_data)
        self.update_status(f"已从位置0x{begin:08X}删除{count}个字节")

    def copy_as_ascii(self):
        begin, end = self.hex_editor.getSelection()
        if begin is None or end is None:
            return
        selected_data = self.file_data[begin:end]
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in selected_data)
        clipboard = QApplication.clipboard()
        clipboard.setText(ascii_str)
        self.update_status(f"已复制{end - begin}字节为ASCII")

    def save_history_state(self):
        if self.history_index < len(self.history) - 1:
            self.history = self.history[:self.history_index + 1]

        self.history.append(copy.copy(self.file_data))
        self.history_index = len(self.history) - 1

        if self.max_history_items > 0 and len(self.history) > self.max_history_items:
            self.history.pop(0)
            self.history_index -= 1

    def _count_trailing_zero_bytes(self, start_pos):
        count = 0
        max_count = 100
        while start_pos + count < len(self.file_data) and count < max_count:
            if self.file_data[start_pos + count] == 0x00:
                count += 1
            else:
                break
        return count

    def get_padding_bytes(self, length):
        return b'\x20' * length

    def _replace_at_position(self, pos, find_bytes, replace_bytes, encoding):
        original_length = len(find_bytes)
        replace_length = len(replace_bytes)
        
        if encoding.lower() in ['utf-16le', 'utf-16be'] and (original_length - replace_length) % 2 != 0:
            padding_length = original_length - replace_length
            if padding_length % 2 != 0:
                padding_length += 1
        
        if replace_length > original_length:
            if encoding.lower() in ['utf-8', 'gbk', 'gb2312', 'big5']:
                excess_bytes = replace_length - original_length
                available_zero_bytes = self._count_trailing_zero_bytes(pos + original_length)
                if available_zero_bytes >= excess_bytes + 1:
                    self.save_history_state()
                    for i in range(replace_length):
                        self.file_data[pos + i] = replace_bytes[i]
                    return True, ""
                else:
                    return False, f"需要{excess_bytes}字节扩展,但后面只有{available_zero_bytes}个连续00字节"
            else:
                excess_bytes = replace_length - original_length
                return False, f"替换内容比查找内容多{excess_bytes}字节"
        
        if replace_length < original_length:
            padding = self.get_padding_bytes(original_length - replace_length)
            replace_bytes = replace_bytes + padding
        
        self.save_history_state()
        for i in range(len(replace_bytes)):
            self.file_data[pos + i] = replace_bytes[i]
        
        return True, ""

    def save_ui_state(self):
        self.settings.setValue("geometry", self.saveGeometry())

    def on_encoding_changed(self, index=None):
        self.config["encoding"] = self.encoding_combo.currentText()
        save_config(self.config)
        self.update_status(f"编码: {self.encoding_combo.currentText()}")

    def scan_strings(self):
        if not self.file_data:
            QMessageBox.warning(self, "警告", "请先打开文件")
            return

        mode = self.current_scan_mode or "ansi"
        encoding = self.encoding_combo.currentText()
        mapping_data = self.load_mapping_from_file(mode)
        if mapping_data and mapping_data.get('strings'):
            self.load_strings_from_mapping(mapping_data)
            self.update_status(f"已从本地映射加载{len(self.string_entries)}个字符串")
            return

        progress = QProgressDialog("正在扫描字符串...", "取消", 0, 100, self)
        progress.setWindowModality(Qt.WindowModal)
        progress.setValue(10)
        progress.show()
        QApplication.processEvents()

        if mode == "ansi":
            segments = self.find_ansi_strings()
        elif mode == "unicode_le":
            segments = self.find_unicode_strings("le")
        else:
            segments = self.find_unicode_strings("be")

        progress.setValue(80)
        QApplication.processEvents()

        self.load_strings_to_tree(segments)
        if segments:
            self.save_mapping_to_file(mode, segments)

        progress.setValue(100)
        progress.close()

        self.update_status(f"扫描完成,找到{len(segments)}个字符串")

    def find_ansi_strings(self, min_length=3):
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
                    if is_basic_english(text):
                        if len(text) > 200:
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

                        segments.append({
                            "start": segment_start,
                            "end": current_pos - 1,
                            "length": len(segment_bytes),
                            "text": text,
                            "bytes": segment_bytes,
                            "encoding": "ascii"
                        })
                except:
                    pass

        return segments

    def find_unicode_strings(self, encoding_type, min_length=3):
        segments = []
        data_length = len(self.file_data)
        encoding = "utf-16le" if encoding_type == "le" else "utf-16be"

        if encoding_type == "le":
            i = 0
            while i < data_length - 1:
                if self.file_data[i + 1] != 0x00 or not (32 <= self.file_data[i] <= 126):
                    i += 1
                    continue

                start = i
                bytes_collected = bytearray()
                unicode_count = 0

                while i < data_length - 1:
                    if self.file_data[i + 1] == 0x00 and (32 <= self.file_data[i] <= 126):
                        bytes_collected.extend([self.file_data[i], self.file_data[i + 1]])
                        unicode_count += 1
                        i += 2
                    else:
                        break

                if unicode_count >= min_length:
                    try:
                        text = bytes_collected.decode('utf-16le').rstrip('\x00')
                        if text and is_likely_valid_text(text):
                            segments.append({
                                "start": start,
                                "end": i - 1,
                                "length": len(bytes_collected),
                                "text": text,
                                "bytes": bytes_collected,
                                "encoding": encoding
                            })
                    except:
                        pass
                else:
                    i = start + 1
        else:
            i = 0
            while i < data_length - 1:
                if self.file_data[i] != 0x00 or not (32 <= self.file_data[i + 1] <= 126):
                    i += 1
                    continue

                start = i
                bytes_collected = bytearray()
                unicode_count = 0

                while i < data_length - 1:
                    if self.file_data[i] == 0x00 and (32 <= self.file_data[i + 1] <= 126):
                        bytes_collected.extend([self.file_data[i], self.file_data[i + 1]])
                        unicode_count += 1
                        i += 2
                    else:
                        break

                if unicode_count >= min_length:
                    try:
                        text = bytes_collected.decode('utf-16be').rstrip('\x00')
                        if text and is_likely_valid_text(text):
                            segments.append({
                                "start": start,
                                "end": i - 1,
                                "length": len(bytes_collected),
                                "text": text,
                                "bytes": bytes_collected,
                                "encoding": encoding
                            })
                    except:
                        pass
                else:
                    i = start + 1

        return segments

    def load_strings_to_tree(self, segments):
        self.string_entries = []
        self.all_string_entries = []
        self.string_tree.clear()

        segments.sort(key=lambda x: x["start"])

        for i, segment in enumerate(segments):
            entry = StringEntry(
                id=i + 1,
                address=segment["start"],
                length=segment["length"],
                text=segment["text"],
                original_text=segment["text"],
                translated_text="",
                bytes_data=segment.get("bytes", b""),
                encoding=segment.get("encoding", "ascii")
            )
            self.string_entries.append(entry)
            self.all_string_entries.append(entry)

            display_text = segment["text"]
            if len(display_text) > 30:
                display_text = display_text[:27] + "..."

            item = QTreeWidgetItem([
                str(i + 1),
                f"0x{segment['start']:08X}",
                str(segment['length']),
                display_text
            ])
            self.string_tree.addTopLevelItem(item)

        if self.string_entries:
            self.string_tree.setCurrentItem(self.string_tree.topLevelItem(0))
            self.current_string_index = 0

    def on_string_clicked(self, item, column):
        index = self.string_tree.indexOfTopLevelItem(item)
        if index >= 0 and index < len(self.string_entries):
            self.current_string_index = index
            self.display_string_entry(index)

    def on_string_double_clicked(self, item, column):
        index = self.string_tree.indexOfTopLevelItem(item)
        if index >= 0:
            self.translated_text_edit.setFocus()

    def display_string_entry(self, index):
        if index < 0 or index >= len(self.string_entries):
            return

        entry = self.string_entries[index]
        self.original_text_edit.setPlainText(entry.original_text)
        self.translated_text_edit.setPlainText(entry.translated_text)

        self.hex_editor.scrollToAddress(entry.address)
        self.hex_editor.setSelection(entry.address, entry.address + entry.length - 1)

    def on_filter_changed(self, text):
        case_sensitive = self.case_sensitive_checkbox.isChecked()
        filter_text = text if case_sensitive else text.lower()
        for i in range(self.string_tree.topLevelItemCount()):
            item = self.string_tree.topLevelItem(i)
            if not filter_text:
                item.setHidden(False)
                continue
            content = item.text(3) 
            if not content:
                item.setHidden(True)
                continue
            compare_content = content if case_sensitive else content.lower()
            item.setHidden(filter_text not in compare_content)

    def on_translation_changed(self):
        pass

    def apply_translation(self):
        if self.current_string_index < 0 or self.current_string_index >= len(self.string_entries):
            return

        entry = self.string_entries[self.current_string_index]
        new_text = self.translated_text_edit.toPlainText()

        if new_text == entry.original_text:
            entry.translated_text = ""
            new_text = ""
        else:
            entry.translated_text = new_text

        entry.text = new_text if new_text else entry.original_text

        item = self.string_tree.topLevelItem(self.current_string_index)
        if item:
            display_text = entry.text
            if len(display_text) > 30:
                display_text = display_text[:27] + "..."
            item.setText(3, display_text)

        if new_text:
            encoding = entry.encoding
            try:
                self.save_history_state()

                if encoding in ('utf-16le', 'utf-16be'):
                    new_bytes = new_text.encode(encoding)
                else:
                    new_bytes = new_text.encode(encoding, errors='replace')

                if len(new_bytes) <= entry.length:
                    self.file_data[entry.address:entry.address + len(new_bytes)] = new_bytes
                else:
                    self.file_data = bytearray(self.file_data[:entry.address]) + \
                                    bytearray(new_bytes) + \
                                    bytearray(self.file_data[entry.address + entry.length:])
                    entry.length = len(new_bytes)

                self.hex_editor.setData(self.file_data)
                self.pending_changes = True

            except Exception as e:
                QMessageBox.warning(self, "编码错误", f"无法编码翻译文本:\n{str(e)}")
                return

        self.save_current_mapping()
        self.update_status(f"已应用翻译(ID:{entry.id})")

    def prev_string(self):
        if self.string_entries:
            new_index = (self.current_string_index - 1) % len(self.string_entries)
            self.string_tree.setCurrentItem(self.string_tree.topLevelItem(new_index))

    def next_string(self):
        if self.string_entries:
            new_index = (self.current_string_index + 1) % len(self.string_entries)
            self.string_tree.setCurrentItem(self.string_tree.topLevelItem(new_index))

    def show_find_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("查找替换")
        dialog.setModal(False)  
        dialog.resize(600, 500)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        layout.addWidget(QLabel("查找内容:"))
        find_input = UTF16TextEdit(self.convert_utf16_exe_text)
        find_input.setMinimumHeight(100)
        layout.addWidget(find_input)

        layout.addWidget(QLabel("替换为:"))
        replace_input = UTF16TextEdit(self.convert_utf16_exe_text)
        replace_input.setMinimumHeight(100)
        layout.addWidget(replace_input)

        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("类型:"))
        type_combo = QComboBox()
        type_combo.addItems(["文本", "十六进制"])
        type_combo.setFixedWidth(100)
        type_layout.addWidget(type_combo)
        
        type_layout.addWidget(QLabel("编码:"))
        encoding_combo = QComboBox()
        encoding_combo.addItems(["utf-8", "gbk", "utf-16le", "utf-16be"])
        encoding_combo.setFixedWidth(120)
        encoding_combo.setCurrentText(self.config.get("find_encoding", "utf-8"))
        type_layout.addWidget(encoding_combo)
        
        def on_encoding_changed():
            self.config["find_encoding"] = encoding_combo.currentText()
            save_config(self.config)
        
        encoding_combo.currentTextChanged.connect(on_encoding_changed)
        
        type_layout.addStretch()
        layout.addLayout(type_layout)

        layout.addWidget(QLabel("搜索结果(点击跳转到对应地址):"))
        result_list = QTreeWidget()
        result_list.setColumnCount(3)
        result_list.setHeaderLabels(["序号", "十六进制地址", "预览"])
        result_list.setMinimumHeight(150)
        result_list.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(result_list)

        button_layout = QHBoxLayout()
        find_btn = QPushButton("查找")
        find_btn.setFixedWidth(100)
        replace_btn = QPushButton("替换当前")
        replace_btn.setFixedWidth(120)
        replace_all_btn = QPushButton("全部替换")
        replace_all_btn.setFixedWidth(120)
        cancel_btn = QPushButton("关闭")
        cancel_btn.setFixedWidth(100)
        
        button_layout.addWidget(find_btn)
        button_layout.addWidget(replace_btn)
        button_layout.addWidget(replace_all_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        search_results = []

        def jump_to_address(address, length=1):
            self.hex_editor.scrollToAddress(address)
            self.hex_editor.setSelection(address, address + length - 1)
            self.update_status(f"跳转到地址:0x{address:08X}")

        def on_result_clicked(item, column):
            idx = int(item.text(0)) - 1
            if 0 <= idx < len(search_results):
                pos = search_results[idx]
                search_text = find_input.toPlainText()
                search_text = re.sub(r'[\n\r\t]', '', search_text).strip()
                search_type = type_combo.currentText()
                encoding = encoding_combo.currentText()
                if search_type == "文本":
                    try:
                        match_len = len(search_text.encode(encoding))
                    except:
                        match_len = len(search_text)
                else:
                    try:
                        match_len = len(bytes.fromhex(search_text.replace(' ', '')))
                    except:
                        match_len = 1
                
                jump_to_address(pos, match_len)

        result_list.itemClicked.connect(on_result_clicked)
        result_list.itemDoubleClicked.connect(lambda item, col: on_result_clicked(item, col))

        def do_find():
            nonlocal search_results
            search_text = find_input.toPlainText()
            search_text = re.sub(r'[\n\r\t]', '', search_text).strip()
            search_type = type_combo.currentText()
            encoding = encoding_combo.currentText()
            
            if not search_text:
                QMessageBox.warning(dialog, "提示", "请输入查找内容")
                return

            search_results = []
            result_list.clear()

            if search_type == "文本":
                try:
                    search_bytes = search_text.encode(encoding)
                except:
                    QMessageBox.warning(dialog, "错误", "编码转换失败")
                    return
            else:
                try:
                    search_bytes = bytes.fromhex(search_text.replace(' ', ''))
                except:
                    QMessageBox.warning(dialog, "错误", "无效的十六进制格式")
                    return

            data = bytes(self.file_data)
            pos = 0
            count = 0

            while True:
                pos = data.find(search_bytes, pos)
                if pos == -1:
                    break
                
                match_length = len(search_bytes)
                preview = data[pos:pos+match_length].hex() if search_type == "十六进制" else \
                          data[pos:pos+match_length].decode(encoding, errors='replace')
                
                if len(preview) > 50:
                    preview = preview[:50] + "..."
                
                preview = f"{preview} ({match_length} 字节)"
                
                item = QTreeWidgetItem([str(count+1), f"0x{pos:08X}", preview])
                result_list.addTopLevelItem(item)
                search_results.append(pos)
                pos += len(search_bytes)
                count += 1

            if count == 0:
                QMessageBox.information(dialog, "结果", "未找到匹配项")
            elif count == 1:
                jump_to_address(search_results[0], len(search_bytes))
                self.update_status(f"找到1个匹配项,已自动跳转")
            else:
                result_list.setCurrentItem(result_list.topLevelItem(0))
                jump_to_address(search_results[0], len(search_bytes))
                self.update_status(f"找到{count}个匹配项,点击列表可跳转")

        def do_replace():
            nonlocal search_results
            search_text = re.sub(r'[\n\r\t]', '', find_input.toPlainText()).strip()
            replace_text = re.sub(r'[\n\r\t]', '', replace_input.toPlainText()).strip()
            search_type = type_combo.currentText()
            encoding = encoding_combo.currentText()

            if search_type == "文本":
                try:
                    search_bytes = search_text.encode(encoding)
                    replace_bytes = replace_text.encode(encoding)
                except:
                    QMessageBox.warning(dialog, "错误", "编码转换失败")
                    return
            else:
                try:
                    search_bytes = bytes.fromhex(search_text.replace(' ', ''))
                    replace_bytes = bytes.fromhex(replace_text.replace(' ', ''))
                except:
                    QMessageBox.warning(dialog, "错误", "无效的十六进制格式")
                    return

            if len(search_results) == 1:
                pos = search_results[0]
                success, msg = self._replace_at_position(pos, search_bytes, replace_bytes, encoding)
                if success:
                    self.hex_editor.setData(self.file_data)
                    search_results = []
                    result_list.clear()
                    self.update_status("已替换 1 项")
                else:
                    QMessageBox.warning(dialog, "替换失败", msg)
            else:
                selected_items = result_list.selectedItems()
                if selected_items:
                    item = selected_items[0]
                    idx = int(item.text(0)) - 1
                    pos = search_results[idx]
                    success, msg = self._replace_at_position(pos, search_bytes, replace_bytes, encoding)
                    if success:
                        self.hex_editor.setData(self.file_data)
                        search_results.pop(idx)
                        result_list.takeTopLevelItem(idx)
                        if search_results:
                            new_idx = min(idx, len(search_results)-1)
                            result_list.setCurrentItem(result_list.topLevelItem(new_idx))
                        self.update_status("已替换当前项")
                    else:
                        QMessageBox.warning(dialog, "替换失败", msg)
                else:
                    QMessageBox.warning(dialog, "提示", "请先选中要替换的结果")

        def do_replace_all():
            nonlocal search_results
            search_text = re.sub(r'[\n\r\t]', '', find_input.toPlainText()).strip()
            replace_text = re.sub(r'[\n\r\t]', '', replace_input.toPlainText()).strip()
            search_type = type_combo.currentText()
            encoding = encoding_combo.currentText()

            if search_type == "文本":
                try:
                    search_bytes = search_text.encode(encoding)
                    replace_bytes = replace_text.encode(encoding)
                except:
                    QMessageBox.warning(dialog, "错误", "编码转换失败")
                    return
            else:
                try:
                    search_bytes = bytes.fromhex(search_text.replace(' ', ''))
                    replace_bytes = bytes.fromhex(replace_text.replace(' ', ''))
                except:
                    QMessageBox.warning(dialog, "错误", "无效的十六进制格式")
                    return

            count = 0
            errors = []
            self.save_history_state()
            data = bytearray(self.file_data)
            pos = 0

            while True:
                pos = data.find(search_bytes, pos)
                if pos == -1:
                    break
                
                original_length = len(search_bytes)
                new_replace_length = len(replace_bytes)
                
                if new_replace_length > original_length:
                    if encoding.lower() in ['utf-8', 'gbk', 'gb2312', 'big5']:
                        excess_bytes = new_replace_length - original_length
                        available_zero_bytes = 0
                        temp_pos = pos + original_length
                        while temp_pos < len(data) and data[temp_pos] == 0x00:
                            available_zero_bytes += 1
                            temp_pos += 1
                        if available_zero_bytes >= excess_bytes + 1:
                            data[pos:pos+new_replace_length] = replace_bytes
                        else:
                            errors.append(f"位置0x{pos:08X}:需要{excess_bytes}字节扩展,但后面只有{available_zero_bytes}个连续00字节")
                            pos += original_length
                            continue
                    else:
                        errors.append(f"位置0x{pos:08X}:替换内容比查找内容多{new_replace_length - original_length}字节")
                        pos += original_length
                        continue
                elif new_replace_length < original_length:
                    padding = b'\x20' * (original_length - new_replace_length)
                    data[pos:pos+original_length] = replace_bytes + padding
                else:
                    data[pos:pos+original_length] = replace_bytes
                
                pos += len(search_bytes)
                count += 1

            if count > 0:
                self.file_data = data
                self.hex_editor.setData(self.file_data)
                search_results = []
                result_list.clear()
                self.update_status(f"已替换{count}项")
            else:
                QMessageBox.information(dialog, "结果", "未找到匹配项")

        find_btn.clicked.connect(do_find)
        replace_btn.clicked.connect(do_replace)
        replace_all_btn.clicked.connect(do_replace_all)
        cancel_btn.clicked.connect(dialog.close)

        dialog.show()  

    def show_export_dialog(self):
        if not self.file_data:
            QMessageBox.warning(self, "警告", "请先打开文件")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("导出字节范围")
        dialog.setModal(True)
        dialog.resize(500, 350)

        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(15, 15, 15, 15)

        input_frame = QGroupBox("地址范围")
        input_layout = QFormLayout()

        start_entry = QLineEdit()
        start_entry.setText("0x00000000")
        start_entry.setFixedWidth(180)
        input_layout.addRow("起始地址(16进制):", start_entry)

        end_entry = QLineEdit()
        end_entry.setText(f"0x{len(self.file_data)-1:08X}")
        end_entry.setFixedWidth(180)
        input_layout.addRow("结束地址(16进制):", end_entry)

        example_label = QLabel("示例:0x00000100到0x00000200")
        example_label.setStyleSheet("color: gray;")
        input_layout.addRow("", example_label)

        input_frame.setLayout(input_layout)
        layout.addWidget(input_frame)

        format_frame = QGroupBox("导出格式")
        format_layout = QVBoxLayout()

        format_combo = QComboBox()
        format_combo.addItems(["纯数字(52494646)", "1字节(0x52,0x49,0x46,0x46)", "4字节小端(0x52494646)"])
        format_combo.setFixedWidth(250)
        format_layout.addWidget(format_combo)

        format_frame.setLayout(format_layout)
        layout.addWidget(format_frame)

        button_layout = QHBoxLayout()
        export_btn = QPushButton("导出")
        export_btn.setFixedWidth(100)
        cancel_btn = QPushButton("取消")
        cancel_btn.setFixedWidth(100)
        button_layout.addWidget(export_btn)
        button_layout.addWidget(cancel_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        def validate_and_export():
            try:
                start_text = start_entry.text().strip()
                end_text = end_entry.text().strip()

                if start_text.lower().startswith("0x"):
                    start_text = start_text[2:]
                if end_text.lower().startswith("0x"):
                    end_text = end_text[2:]

                start_addr = int(start_text, 16)
                end_addr = int(end_text, 16)

                if start_addr < 0 or end_addr >= len(self.file_data):
                    QMessageBox.warning(self, "错误", f"地址范围无效!文件大小:0x{len(self.file_data):08X}")
                    return
                if start_addr > end_addr:
                    QMessageBox.warning(self, "错误", "起始地址不能大于结束地址!")
                    return

                byte_range = self.file_data[start_addr:end_addr+1]
                if not byte_range:
                    QMessageBox.warning(self, "警告", "选择的范围内没有字节数据")
                    return

                format_type = format_combo.currentText()

                if format_type == "纯数字(52494646)":
                    result = "".join([f"{b:02X}" for b in byte_range])
                elif format_type == "1字节(0x52,0x49,0x46,0x46)":
                    result = ", ".join([f"0x{b:02X}" for b in byte_range])
                elif format_type == "4字节小端(0x52494646)":
                    padded = bytearray(byte_range)
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

                result_dialog = QDialog(self)
                result_dialog.setWindowTitle("导出结果")
                result_dialog.resize(800, 550)
                result_dialog.setModal(True)

                result_layout = QVBoxLayout(result_dialog)

                info_text = f"地址范围: 0x{start_addr:08X} - 0x{end_addr:08X}\n"
                info_text += f"字节数量: {len(byte_range)} (0x{len(byte_range):X})\n"
                info_text += f"导出格式: {format_type}\n"
                info_text += f"输出字符数: {len(result)}\n"
                info_text += "-" * 60

                info_label = QLabel(info_text)
                info_label.setStyleSheet("font-family: Consolas;")
                result_layout.addWidget(info_label)

                result_text = QTextEdit()
                result_text.setPlainText(result)
                result_text.setReadOnly(True)
                result_text.setFont(QFont("Consolas", 10))
                result_layout.addWidget(result_text)

                copy_btn = QPushButton("复制到剪贴板")
                copy_btn.setFixedWidth(120)
                copy_btn.clicked.connect(lambda: (QApplication.clipboard().setText(result), copy_btn.setText("已复制!")))
                result_layout.addWidget(copy_btn)

                result_dialog.exec()

            except ValueError:
                QMessageBox.warning(self, "错误", "无效的地址格式,请输入16进制地址")

        export_btn.clicked.connect(validate_and_export)
        cancel_btn.clicked.connect(dialog.reject)

        dialog.exec()

    def show_cp932_converter(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("CP932乱码修复器")
        dialog.resize(500, 350)

        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("输入乱码的GBK字符串:"))
        input_text = QTextEdit()
        layout.addWidget(input_text)

        layout.addWidget(QLabel("转换后的CP932日语字符串:"))
        output_text = QTextEdit()
        output_text.setReadOnly(True)
        layout.addWidget(output_text)

        def convert():
            gbk_str = input_text.toPlainText()
            if not gbk_str:
                output_text.setPlainText("")
                return
            try:
                gbk_bytes = gbk_str.encode('gbk', errors='ignore')
                cp932_str = gbk_bytes.decode('cp932', errors='ignore')
                output_text.setPlainText(cp932_str)
            except Exception as e:
                output_text.setPlainText(f"错误: {str(e)}")

        def copy_result():
            result = output_text.toPlainText()
            if result:
                QApplication.clipboard().setText(result)
                self.update_status("已复制到剪贴板")

        def clear_all():
            input_text.clear()
            output_text.clear()

        button_layout = QHBoxLayout()
        convert_btn = QPushButton("转换")
        copy_btn = QPushButton("复制")
        clear_btn = QPushButton("清空")
        close_btn = QPushButton("关闭")

        convert_btn.clicked.connect(convert)
        copy_btn.clicked.connect(copy_result)
        clear_btn.clicked.connect(clear_all)
        close_btn.clicked.connect(dialog.accept)

        button_layout.addWidget(convert_btn)
        button_layout.addWidget(copy_btn)
        button_layout.addWidget(clear_btn)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)

        info_label = QLabel("此工具用于把日本软件在Windows系统上显示乱码的字符串还原成日语")
        layout.addWidget(info_label)

        dialog.exec()

    def show_utf16_converter(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("UTF-16字符串转换器")
        dialog.resize(500, 400)

        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("输入UTF16点分隔文本(自动转换为正常文本):"))
        input_text = QTextEdit()
        layout.addWidget(input_text)

        layout.addWidget(QLabel("转换结果:"))
        output_text = QTextEdit()
        output_text.setReadOnly(True)
        layout.addWidget(output_text)

        def convert():
            text = input_text.toPlainText()
            if not text:
                output_text.setPlainText("")
                return

            cleaned = re.sub(r'[\n\r\t]', '', text)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            cleaned = re.sub(r'\.\.', '\n', cleaned)
            cleaned = re.sub(r'\.', '', cleaned)
            cleaned = re.sub('\n', '.', cleaned)

            output_text.setPlainText(cleaned)

        def copy_result():
            result = output_text.toPlainText()
            if result:
                QApplication.clipboard().setText(result)
                self.update_status("已复制到剪贴板")

        def clear_all():
            input_text.clear()
            output_text.clear()

        button_layout = QHBoxLayout()
        clear_btn = QPushButton("清空")
        close_btn = QPushButton("关闭")

        clear_btn.clicked.connect(clear_all)
        close_btn.clicked.connect(dialog.accept)

        button_layout.addWidget(clear_btn)
        button_layout.addWidget(close_btn)
        layout.addLayout(button_layout)

        input_text.textChanged.connect(convert)

        dialog.exec()

    def show_about(self):
        QMessageBox.about(
            self,
            "关于",
            f"<h3>{APP_NAME}</h3>"
            f"<p>版本: {APP_VERSION}</p>"
            f"<p>基于 PySide6 和 pyhexedit 构建的十六进制编辑器</p>"
            f"<p>支持 ANSI、UTF-16LE、UTF-16BE 字符串扫描</p>"
            f"<p>专为软件汉化设计</p>"
        )

    def update_status(self, message):
        self.statusBar().showMessage(message)

    def closeEvent(self, event):
        if self.pending_changes:
            reply = QMessageBox.question(
                self, "保存更改",
                "文件有未保存的更改,是否保存?",
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel
            )
            if reply == QMessageBox.Save:
                self.save_file()
                event.accept()
            elif reply == QMessageBox.Discard:
                event.accept()
            else:
                event.ignore()
                return

        self.save_ui_state()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("BinaryEditorQt")

    window = BinaryEditorQt()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()