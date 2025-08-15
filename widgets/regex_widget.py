import sys
import re
import os
import time
from pathlib import Path

from PySide6.QtGui import QTextOption
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit,
    QPushButton, QLabel, QComboBox, QFileDialog, QMessageBox, QTabWidget, QScrollArea,
    QGroupBox, QProgressBar, QPlainTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal

class MatchWorker(QThread):
    progress_updated = Signal(int)
    result_ready = Signal(list, int)
    error_occurred = Signal(str)
    finished_signal = Signal()

    def __init__(self, text, pattern, flags, chunk_size=10000):
        super().__init__()
        self.text = text
        self.pattern = pattern
        self.flags = flags
        self.chunk_size = chunk_size
        self.is_cancelled = False

    def run(self):
        try:
            regex = re.compile(self.pattern, self.flags)
            matches = []
            total_chars = len(self.text)
            if total_chars > self.chunk_size:
                offset = 0
                for i in range(0, total_chars, self.chunk_size):
                    if self.is_cancelled:
                        break
                    chunk = self.text[i:i + self.chunk_size]
                    chunk_matches = list(regex.finditer(chunk))
                    for match in chunk_matches:
                        match_start = match.start() + offset
                        match_end = match.end() + offset
                        matches.append((match_start, match_end, match.group(), match.groups()))
                    offset += len(chunk)
                    progress = int((i + self.chunk_size) / total_chars * 100)
                    self.progress_updated.emit(min(progress, 100))
                    time.sleep(0.01)
            else:
                matches = [(m.start(), m.end(), m.group(), m.groups()) for m in regex.finditer(self.text)]
                self.progress_updated.emit(100)
            if not self.is_cancelled:
                self.result_ready.emit(matches, len(matches))
        except re.error as e:
            self.error_occurred.emit(f"正则表达式错误: {str(e)}")
        except Exception as e:
            self.error_occurred.emit(f"匹配过程中发生错误: {str(e)}")
        finally:
            self.finished_signal.emit()

    def cancel(self):
        self.is_cancelled = True

class RegexTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("正则表达式工具")
        self.setGeometry(100, 100, 1200, 800)
        self.common_patterns = {
            "手机号码": r"1[3-9]\d{9}",
            "邮箱地址": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "URL地址": r"https?://[^\s<>\"{}|\\^`\[\]]+",
            "IP地址": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "身份证号": r"\d{17}[\dXx]",
            "邮政编码": r"[1-9]\d{5}(?!\d)",
            "QQ号码": r"[1-9][0-9]{4,}",
            "微信号": r"[a-zA-Z][a-zA-Z\d_-]{5,19}",
            "银行卡号": r"\d{16,19}",
            "中文字符": r"[\u4e00-\u9fa5]+",
            "日期格式(YYYY-MM-DD)": r"\d{4}-\d{2}-\d{2}",
            "时间格式(HH:MM:SS)": r"\d{2}:\d{2}:\d{2}",
            "十六进制颜色": r"#[0-9a-fA-F]{6}",
            "正整数": r"^[1-9]\d*$",
            "小数": r"^\d+\.\d+$",
            "HTML标签": r"<[^>]+>",
            "XML标签": r"<[^>]+>",
            "JSON键值对": r"\"[^\"]+\"\s*:\s*[^,}\]]+"
        }
        self.match_worker = None
        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        match_tab = self.create_match_tab()
        tab_widget.addTab(match_tab, "正则匹配")
        help_tab = self.create_help_tab()
        tab_widget.addTab(help_tab, "帮助手册")

    def create_match_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        input_group = QGroupBox("输入文本")
        input_layout = QVBoxLayout(input_group)
        input_control_layout = QHBoxLayout()
        self.input_status_label = QLabel("状态: 直接输入模式")
        self.input_status_label.setStyleSheet("color: #666; font-size: 12px;")
        input_control_layout.addWidget(self.input_status_label)
        input_control_layout.addStretch()
        self.import_btn = QPushButton("📁 导入文件")
        self.import_btn.clicked.connect(self.import_file)
        input_control_layout.addWidget(self.import_btn)
        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self.clear_input)
        input_control_layout.addWidget(self.clear_btn)
        input_layout.addLayout(input_control_layout)
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("在此输入要匹配的文本，或点击上方'导入文件'按钮从文件加载...")
        # self.text_input.setMaximumHeight(200)
        self.text_input.textChanged.connect(self.on_text_changed)
        input_layout.addWidget(self.text_input)
        self.file_info_label = QLabel("")
        self.file_info_label.setStyleSheet("color: #666; font-size: 11px;")
        self.file_info_label.setVisible(False)
        input_layout.addWidget(self.file_info_label)
        layout.addWidget(input_group)
        regex_group = QGroupBox("正则表达式")
        regex_layout = QVBoxLayout(regex_group)
        pattern_layout = QHBoxLayout()
        pattern_layout.addWidget(QLabel("常用正则:"))
        self.pattern_combo = QComboBox()
        self.pattern_combo.addItem("自定义")
        self.pattern_combo.addItems(self.common_patterns.keys())
        self.pattern_combo.currentTextChanged.connect(self.on_pattern_changed)
        pattern_layout.addWidget(self.pattern_combo)
        pattern_layout.addStretch()
        regex_layout.addLayout(pattern_layout)
        self.regex_input = QLineEdit()
        self.regex_input.setPlaceholderText("输入正则表达式...")
        self.regex_input.textChanged.connect(self.on_regex_changed)
        regex_layout.addWidget(self.regex_input)
        options_layout = QHBoxLayout()
        self.ignore_case_cb = QComboBox()
        self.ignore_case_cb.addItems(["区分大小写", "忽略大小写"])
        self.multiline_cb = QComboBox()
        self.multiline_cb.addItems(["单行模式", "多行模式"])
        self.dotall_cb = QComboBox()
        self.dotall_cb.addItems(["点不匹配换行", "点匹配换行"])
        options_layout.addWidget(QLabel("选项:"))
        options_layout.addWidget(self.ignore_case_cb)
        options_layout.addWidget(self.multiline_cb)
        options_layout.addWidget(self.dotall_cb)
        # options_layout.addStretch()
        regex_layout.addLayout(options_layout)
        layout.addWidget(regex_group)
        match_control_layout = QHBoxLayout()
        self.match_btn = QPushButton("🔍 开始匹配")
        self.match_btn.clicked.connect(self.perform_match)
        # match_control_layout.addWidget(self.match_btn)
        options_layout.addWidget(self.match_btn)
        self.cancel_btn = QPushButton("❌ 取消")
        self.cancel_btn.clicked.connect(self.cancel_match)
        self.cancel_btn.setEnabled(False)
        options_layout.addWidget(self.cancel_btn)
        # match_control_layout.addWidget(self.cancel_btn)
        # match_control_layout.addStretch()
        self.export_btn = QPushButton("💾 导出结果")
        self.export_btn.clicked.connect(self.export_results)
        options_layout.addWidget(self.export_btn)
        options_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.export_btn.setEnabled(False)
        # match_control_layout.addWidget(self.export_btn)
        layout.addLayout(match_control_layout)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        result_group = QGroupBox("匹配结果")
        result_layout = QVBoxLayout(result_group)
        self.result_stats = QLabel("匹配结果: 0 个")
        self.result_stats.setStyleSheet("font-weight: bold; color: #333;")
        result_layout.addWidget(self.result_stats)
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(self.result_text)
        layout.addWidget(result_group)
        return widget

    def create_help_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 创建滚动区域
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)

        # 正则表达式基础语法
        basic_group = QGroupBox("正则表达式基础语法")
        basic_layout = QVBoxLayout(basic_group)

        basic_text = """
        <h3>字符类</h3>
        <ul>
        <li><code>.</code> - 匹配任意字符（除换行符外）</li>
        <li><code>\\w</code> - 匹配字母、数字、下划线</li>
        <li><code>\\W</code> - 匹配非字母、数字、下划线</li>
        <li><code>\\d</code> - 匹配数字</li>
        <li><code>\\D</code> - 匹配非数字</li>
        <li><code>\\s</code> - 匹配空白字符</li>
        <li><code>\\S</code> - 匹配非空白字符</li>
        <li><code>[abc]</code> - 匹配a、b、c中的任意一个</li>
        <li><code>[^abc]</code> - 匹配除a、b、c外的任意字符</li>
        <li><code>[a-z]</code> - 匹配a到z的任意字符</li>
        </ul>

        <h3>量词</h3>
        <ul>
        <li><code>*</code> - 匹配0次或多次</li>
        <li><code>+</code> - 匹配1次或多次</li>
        <li><code>?</code> - 匹配0次或1次</li>
        <li><code>{n}</code> - 匹配n次</li>
        <li><code>{n,}</code> - 匹配n次或更多</li>
        <li><code>{n,m}</code> - 匹配n到m次</li>
        </ul>

        <h3>锚点</h3>
        <ul>
        <li><code>^</code> - 匹配字符串开始</li>
        <li><code>$</code> - 匹配字符串结束</li>
        <li><code>\\b</code> - 匹配单词边界</li>
        <li><code>\\B</code> - 匹配非单词边界</li>
        </ul>

        <h3>分组和引用</h3>
        <ul>
        <li><code>(pattern)</code> - 捕获分组</li>
        <li><code>(?:pattern)</code> - 非捕获分组</li>
        <li><code>\\1, \\2, ...</code> - 引用分组</li>
        </ul>

        <h3>特殊字符转义</h3>
        <ul>
        <li><code>\\.</code> - 匹配点号</li>
        <li><code>\\*</code> - 匹配星号</li>
        <li><code>\\+</code> - 匹配加号</li>
        <li><code>\\?</code> - 匹配问号</li>
        <li><code>\\(</code> - 匹配左括号</li>
        <li><code>\\)</code> - 匹配右括号</li>
        <li><code>\\[</code> - 匹配左方括号</li>
        <li><code>\\]</code> - 匹配右方括号</li>
        <li><code>\\{</code> - 匹配左大括号</li>
        <li><code>\\}</code> - 匹配右大括号</li>
        </ul>
        """
        basic_label = QLabel(basic_text)
        basic_label.setWordWrap(True)
        basic_layout.addWidget(basic_label)
        scroll_layout.addWidget(basic_group)

        # 常用正则表达式示例
        examples_group = QGroupBox("常用正则表达式示例")
        examples_layout = QVBoxLayout(examples_group)

        examples_text = """
        <h3>内置常用正则表达式</h3>
        <table border="1" cellpadding="5" cellspacing="0">
        <tr><th>用途</th><th>正则表达式</th><th>说明</th></tr>
        <tr><td>手机号码</td><td><code>1[3-9]\\d{9}</code></td><td>匹配中国大陆手机号</td></tr>
        <tr><td>邮箱地址</td><td><code>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}</code></td><td>匹配邮箱格式</td></tr>
        <tr><td>URL地址</td><td><code>https?://[^\\s<>\"{}|\\\\^`\\[\\]]+</code></td><td>匹配HTTP/HTTPS链接</td></tr>
        <tr><td>IP地址</td><td><code>\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b</code></td><td>匹配IPv4地址</td></tr>
        <tr><td>身份证号</td><td><code>\\d{17}[\\dXx]</code></td><td>匹配18位身份证号</td></tr>
        <tr><td>邮政编码</td><td><code>[1-9]\\d{5}(?!\\d)</code></td><td>匹配6位邮政编码</td></tr>
        <tr><td>QQ号码</td><td><code>[1-9][0-9]{4,}</code></td><td>匹配QQ号</td></tr>
        <tr><td>微信号</td><td><code>[a-zA-Z][a-zA-Z\\d_-]{5,19}</code></td><td>匹配微信号</td></tr>
        <tr><td>银行卡号</td><td><code>\\d{16,19}</code></td><td>匹配银行卡号</td></tr>
        <tr><td>中文字符</td><td><code>[\\u4e00-\\u9fa5]+</code></td><td>匹配中文字符</td></tr>
        <tr><td>日期格式</td><td><code>\\d{4}-\\d{2}-\\d{2}</code></td><td>匹配YYYY-MM-DD格式</td></tr>
        <tr><td>时间格式</td><td><code>\\d{2}:\\d{2}:\\d{2}</code></td><td>匹配HH:MM:SS格式</td></tr>
        <tr><td>十六进制颜色</td><td><code>#[0-9a-fA-F]{6}</code></td><td>匹配CSS颜色值</td></tr>
        <tr><td>正整数</td><td><code>^[1-9]\\d*$</code></td><td>匹配正整数</td></tr>
        <tr><td>小数</td><td><code>^\\d+\\.\\d+$</code></td><td>匹配小数</td></tr>
        <tr><td>HTML标签</td><td><code>&lt;[^&gt;]+&gt;</code></td><td>匹配HTML标签</td></tr>
        <tr><td>JSON键值对</td><td><code>\"[^\"]+\"\\s*:\\s*[^,}\\]]+</code></td><td>匹配JSON格式</td></tr>
        </table>

        <h3>使用技巧</h3>
        <ul>
        <li>使用 <code>^</code> 和 <code>$</code> 确保完整匹配</li>
        <li>使用 <code>\\b</code> 确保单词边界匹配</li>
        <li>使用非贪婪匹配 <code>*?</code> 避免过度匹配</li>
        <li>使用分组 <code>()</code> 提取特定部分</li>
        <li>使用 <code>(?:)</code> 进行非捕获分组</li>
        </ul>
        """
        examples_label = QLabel(examples_text)
        examples_label.setWordWrap(True)
        examples_layout.addWidget(examples_label)
        scroll_layout.addWidget(examples_group)

        scroll.setWidget(scroll_widget)
        layout.addWidget(scroll)

        return widget

    def on_text_changed(self):
        text = self.text_input.toPlainText()
        if text:
            if len(text) < 200 and ('\\' in text or '/' in text) and Path(text).exists():
                self.input_status_label.setText("状态: 检测到文件路径")
            else:
                self.input_status_label.setText(f"状态: 直接输入模式 (字符数: {len(text)})")
        else:
            self.input_status_label.setText("状态: 直接输入模式")

    def import_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "",
            "文本文件 (*.txt *.log *.csv *.json *.xml *.html *.py *.js *.java *.cpp *.c *.h);;所有文件 (*)"
        )
        if file_path:
            try:
                encodings = ['utf-8', 'gbk', 'gb2312', 'latin-1']
                content = None
                for encoding in encodings:
                    try:
                        with open(file_path, 'r', encoding=encoding) as f:
                            content = f.read()
                        break
                    except UnicodeDecodeError:
                        continue
                if content is None:
                    QMessageBox.warning(self, "错误", "无法读取文件，编码格式不支持")
                    return
                self.text_input.setText(content)
                file_size = os.path.getsize(file_path)
                file_info = f"文件: {os.path.basename(file_path)} | 大小: {self.format_file_size(file_size)} | 字符数: {len(content)}"
                self.file_info_label.setText(file_info)
                self.file_info_label.setVisible(True)
                self.input_status_label.setText(f"状态: 文件导入模式 ({os.path.basename(file_path)})")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"无法读取文件: {str(e)}")

    def format_file_size(self, size_bytes):
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

    def clear_input(self):
        self.text_input.clear()
        self.file_info_label.setVisible(False)
        self.input_status_label.setText("状态: 直接输入模式")
        self.result_text.clear()
        self.result_stats.setText("匹配结果: 0 个")
        self.export_btn.setEnabled(False)

    def on_pattern_changed(self, pattern_name):
        if pattern_name in self.common_patterns:
            self.regex_input.setText(self.common_patterns[pattern_name])

    def on_regex_changed(self):
        if self.regex_input.text() != self.common_patterns.get(self.pattern_combo.currentText(), ""):
            self.pattern_combo.setCurrentText("自定义")

    def perform_match(self):
        text = self.text_input.toPlainText()
        pattern = self.regex_input.text()
        if not text:
            QMessageBox.warning(self, "警告", "请输入要匹配的文本")
            return
        if not pattern:
            QMessageBox.warning(self, "警告", "请输入正则表达式")
            return
        flags = 0
        if self.ignore_case_cb.currentText() == "忽略大小写":
            flags |= re.IGNORECASE
        if self.multiline_cb.currentText() == "多行模式":
            flags |= re.MULTILINE
        if self.dotall_cb.currentText() == "点匹配换行":
            flags |= re.DOTALL
        self.result_text.clear()
        self.result_stats.setText("正在匹配...")
        self.export_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.match_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.match_worker = MatchWorker(text, pattern, flags)
        self.match_worker.progress_updated.connect(self.update_progress)
        self.match_worker.result_ready.connect(self.show_results)
        self.match_worker.error_occurred.connect(self.show_error)
        self.match_worker.finished_signal.connect(self.on_match_finished)
        self.match_worker.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def show_results(self, matches, count):
        # if matches:
        #     result_text = f"找到 {count} 个匹配项:\n\n"
        #     for i, (start, end, group, groups) in enumerate(matches, 1):
        #         result_text += f"匹配项 {i}:\n  位置: {start}-{end}\n  内容: {group}\n"
        #         if groups:
        #             result_text += f"  分组: {groups}\n"
        #         result_text += "\n"
        # 修改输出仅匹配的内容！
        if matches:
            result_text = ''
            for i, (start, end, group, groups) in enumerate(matches, 1):
                result_text += f"{group}\n"
                if groups:
                    result_text += f"{groups}\n"
                result_text += ""
        else:
            result_text = "未找到匹配项"
        self.result_text.setText(result_text)
        self.result_stats.setText(f"匹配结果: {count} 个")
        self.export_btn.setEnabled(count > 0)

    def show_error(self, error_msg):
        QMessageBox.warning(self, "错误", error_msg)
        self.result_stats.setText("匹配失败")

    def on_match_finished(self):
        self.progress_bar.setVisible(False)
        self.match_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.match_worker = None

    def cancel_match(self):
        if self.match_worker and self.match_worker.isRunning():
            self.match_worker.cancel()
            self.match_worker.wait()
            self.result_stats.setText("匹配已取消")
            self.progress_bar.setVisible(False)
            self.match_btn.setEnabled(True)
            self.cancel_btn.setEnabled(False)

    def export_results(self):
        if not self.result_text.toPlainText():
            QMessageBox.warning(self, "警告", "没有可导出的结果")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存结果", "", "文本文件 (*.txt);;CSV文件 (*.csv);;所有文件 (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.result_text.toPlainText())
                QMessageBox.information(self, "成功", f"结果已导出到: {file_path}")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"导出失败: {str(e)}")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    app.setApplicationName("正则表达式匹配工具")
    window = RegexTool()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
