# codec_widget.py
import html
import urllib.parse

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                               QTextEdit, QComboBox, QPushButton,
                               QLabel, QMainWindow, QTabWidget,
                               QLineEdit, QCheckBox, QDialog, QPlainTextEdit, QGroupBox)
from PySide6.QtCore import Qt
import base64

from utils.BaseCodecUtils import BaseCodec
from utils.ToolsUtils import ToolUtils, UnicodeDecoder, NormalUtils

# ROT 编解码类
class ROTCodec:
    def __init__(self):
        self.rot_maps = {
            5: self.rot5,
            13: self.rot13,
            15: self.rot15,
            18: self.rot18,
            47: self.rot47
        }

    def rot5(self, text):
        result = ""
        for char in text:
            if char.isdigit():
                result += str((int(char) + 5) % 10)
            else:
                result += char
        return result

    def rot13(self, text):
        result = ""
        for char in text:
            if char.isalpha():
                if char.islower():
                    result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
                else:
                    result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result

    def rot15(self, text):
        result = ""
        for char in text:
            if char.isalpha():
                if char.islower():
                    result += chr((ord(char) - ord('a') + 15) % 26 + ord('a'))
                else:
                    result += chr((ord(char) - ord('A') + 15) % 26 + ord('A'))
            else:
                result += char
        return result

    def rot18(self, text):
        # 先应用 ROT13 处理字母，再应用 ROT5 处理数字
        result = ""
        for c in text:
            if c.isalpha():
                if c.isupper():
                    new_ascii = (ord(c) - 65 + 18) % 26 + 65
                else:
                    new_ascii = (ord(c) - 97 + 18) % 26 + 97
                result += chr(new_ascii)
            else:
                result += c
        return self.rot5(self.rot13(text))

    def rot47(self, text):
        result = ""
        for char in text:
            if 33 <= ord(char) <= 126:
                result += chr((ord(char) - 33 + 47) % 94 + 33)
            else:
                result += char
        return result

    def encode(self, text, rot):
        return self.rot_maps[rot](text)

    def decode(self, text, rot):
        return self.rot_maps[rot](text)

    def brute_force(self, text):
        results = {}
        for rot in self.rot_maps.keys():
            results[rot] = self.decode(text, rot)
        return results

class ReplaceChrDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("自定义字符替换")
        self.setFixedSize(320,240)
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        input_label = QLabel("请输入需要被替换的字符")
        self.replace_input_text = QPlainTextEdit()
        output_label = QLabel("请输入替换成的字符")
        self.replace_output_text = QPlainTextEdit()
        btn_layout = QHBoxLayout()
        confirm_btn = QPushButton("确定")
        cancel_btn = QPushButton("取消")
        btn_layout.addWidget(confirm_btn)
        btn_layout.addWidget(cancel_btn)
        btn_layout.setAlignment(Qt.AlignCenter)

        confirm_btn.clicked.connect(self.accept)
        cancel_btn.clicked.connect(self.reject_text)


        layout.addWidget(input_label)
        layout.addWidget(self.replace_input_text)
        layout.addWidget(output_label)
        layout.addWidget(self.replace_output_text)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def get_current_chr(self):
        return self.replace_input_text.toPlainText()

    def get_replace_chr(self):
        return self.replace_output_text.toPlainText()

    def reject_text(self):
        self.replace_input_text.clear()
        self.replace_output_text.clear()
        self.close()

class CodecWidget(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        # 创建主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # tab框架
        self.tab_widget = QTabWidget()
        # 添加内部tab布局
        self.inner_tab_widget = QTabWidget()

        self.codec_tab = QWidget()  # 第一个 tab 标签按钮
        self.codec_tab.setObjectName("codec_tab")
        self.codec_tab.setWindowTitle("常用编解码")

        self.base_tab = QWidget()  # 第二个 tab 标签按钮
        self.base_tab.setObjectName("base_tab")

        self.other_codec_tab = QWidget()  # 第二个 tab 标签按钮
        self.other_codec_tab.setObjectName("other_codec_tab")

        self.rot_codec_tab = QWidget()  # 第二个 tab 标签按钮
        self.rot_codec_tab.setObjectName("rot_codec_tab")

        self.inner_tab_widget.addTab(self.codec_tab, "常用编解码")
        self.inner_tab_widget.addTab(self.base_tab, "Base系列编解码")
        self.inner_tab_widget.addTab(self.other_codec_tab,"其他编解码")
        self.inner_tab_widget.addTab(self.rot_codec_tab, "ROT编解码")

        # 输入区域
        self.input_label = QLabel("输入:")
        self.codec_input_text = QTextEdit()

        self.codec_input_text.setPlaceholderText("请输入...")
        self.codec_input_text.setMinimumHeight(100)

        self.base_input_text = QTextEdit()
        self.base_input_text.setPlaceholderText("请输入...")
        self.base_input_text.setMinimumHeight(100)

        self.other_codec_input_text = QTextEdit()
        self.other_codec_input_text.setPlaceholderText("请输入...")
        self.other_codec_input_text.setMinimumHeight(100)

        # 输出区域
        self.output_label = QLabel("输出:")
        self.codec_output_text = QTextEdit()
        self.codec_output_text.setMinimumHeight(100)

        self.base_output_text = QTextEdit()
        self.base_output_text.setMinimumHeight(100)

        self.other_codec_output_text = QTextEdit()
        self.other_codec_output_text.setMinimumHeight(100)

        # 初始化
        self.init_codec_tab()
        self.init_base_tab()
        self.init_other_codec_tab()
        self.init_rot_codec_tab()
        # 添加一个状态栏(用QLbel，statusBar无法右侧显示Message)
        self.status_bar = QLabel()
        # self.setStatusBar(self.status_bar)
        # self.status_bar.setStyleSheet("QStatusBar::item { alignment: AlignRight; }")
        # self.status_bar.setStyleSheet('QStatusBar {text-align: center;}')
        #
        # self.update_status_bar1()
        # self.update_status_bar2()
        # self.update_status_bar3()


        # 输入字符数添加监听器
        self.codec_input_text.textChanged.connect(self.update_status_bar1)
        self.codec_output_text.textChanged.connect(self.update_status_bar1)

        self.base_input_text.textChanged.connect(self.update_status_bar2)
        self.base_output_text.textChanged.connect(self.update_status_bar2)

        self.other_codec_input_text.textChanged.connect(self.update_status_bar3)
        self.other_codec_output_text.textChanged.connect(self.update_status_bar3)


        # 添加到内主tab
        main_layout.addWidget(self.inner_tab_widget)
        # 添加状态栏
        statusbar_layout = QHBoxLayout()
        statusbar_layout.setAlignment(Qt.AlignRight)
        statusbar_layout.addWidget(self.status_bar)
        main_layout.addLayout(statusbar_layout)


    def update_status_bar1(self):
        """更新状态栏显示输入框的字符长度"""
        ToolUtils.update_textChanged_statusbar(self.codec_input_text,self.codec_output_text,self.status_bar)

    def update_status_bar2(self):
        ToolUtils.update_textChanged_statusbar(self.base_input_text, self.base_output_text, self.status_bar)

    def update_status_bar3(self):
        ToolUtils.update_textChanged_statusbar(self.other_codec_input_text,self.other_codec_output_text,self.status_bar)

    def init_codec_tab(self):
        # 设置布局
        layout = QVBoxLayout(self.codec_tab)


        # 第一排操作按钮
        button_layout = QHBoxLayout()
        button_layout.setSpacing(5)
        button_layout.setAlignment(Qt.AlignCenter)
        base64_encode_btn = QPushButton("Base64编码")
        base64_decode_btn = QPushButton("Base64解码")
        base64_tohex_btn = QPushButton("Base64>>Hex")
        hex_tobase64_btn = QPushButton("Hex>>Base64")
        asc_tostr_btn = QPushButton("ASCII>>Str")
        str_toasc_btn = QPushButton("Str>>ASCII")
        escape_btn = QPushButton("Escape")
        unescape_btn = QPushButton("UnEscape")

        # 第二排操作按钮
        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(5)
        button_layout2.setAlignment(Qt.AlignCenter)
        urlencode_btn = QPushButton("URLEncode")
        urldecode_btn = QPushButton("URLDecode")
        unicode_tostr_btn = QPushButton("Unicode>>Str")
        str_tounicode_btn = QPushButton("Str>>Unicode")
        str_tohex_btn = QPushButton("Str>>Hex")
        hex_tostr_btn = QPushButton("Hex>>Str")
        jsonparam_to_urlparam_btn = QPushButton("Json转URLParam")
        urlparam_to_jsonparam_btn = QPushButton("URL提取JsonParam")

        #第三排操作按钮
        button_layout3 = QHBoxLayout()
        button_layout3.setSpacing(5)
        str_lower_btn = QPushButton("全部小写")
        str_upper_btn = QPushButton("全部大写")
        str_swapcase_btn = QPushButton("大小写互换")
        str_reverse_btn= QPushButton("字符反转")
        remove_blank_btn = QPushButton("去除空格")
        remove_blankline_btn = QPushButton("去除空行")
        remove_line_btn = QPushButton("去除换行")
        remove_tab_btn = QPushButton("去除Tab")
        self.remove_chr_btn = QCheckBox("去除字符")
        self.remove_chr_btn.setMinimumWidth(45)
        self.remove_chr_line = QLineEdit()
        self.remove_chr_line.setAlignment(Qt.AlignCenter)
        self.remove_chr_line.setMinimumWidth(50)
        self.remove_chr_line.setMaximumWidth(50)


        #第四排按钮
        button_layout4 = QHBoxLayout()
        button_layout4.setSpacing(5)
        button_layout4.setAlignment(Qt.AlignCenter)

        replace_chr_btn = QPushButton("字符替换")
        codec_swap_btn = QPushButton("互换内容")
        codec_clear_btn = QPushButton("清空内容")


        #添加按钮到布局
        button_layout.addWidget(base64_encode_btn)
        button_layout.addWidget(base64_decode_btn)
        button_layout.addWidget(base64_tohex_btn)
        button_layout.addWidget(hex_tobase64_btn)
        button_layout.addWidget(str_toasc_btn)
        button_layout.addWidget(asc_tostr_btn)
        button_layout.addWidget(escape_btn)
        button_layout.addWidget(unescape_btn)

        button_layout2.addWidget(unicode_tostr_btn)
        button_layout2.addWidget(str_tounicode_btn)
        button_layout2.addWidget(urlencode_btn)
        button_layout2.addWidget(urldecode_btn)
        button_layout2.addWidget(str_tohex_btn)
        button_layout2.addWidget(hex_tostr_btn)
        button_layout2.addWidget(jsonparam_to_urlparam_btn)
        button_layout2.addWidget(urlparam_to_jsonparam_btn)

        # 设置居中
        button_layout3.setAlignment(Qt.AlignCenter)
        button_layout3.insertStretch(0, 1)

        button_layout3.addWidget(str_lower_btn)
        button_layout3.addWidget(str_upper_btn)
        button_layout3.addWidget(str_swapcase_btn)
        button_layout3.addWidget(str_reverse_btn)
        button_layout3.addWidget(remove_blank_btn)
        button_layout3.addWidget(remove_blankline_btn)
        button_layout3.addWidget(remove_line_btn)
        button_layout3.addWidget(remove_tab_btn)
        button_layout3.addWidget(self.remove_chr_btn)
        button_layout3.addWidget(self.remove_chr_line)
        # 添加右侧的扩展空间
        button_layout3.insertStretch(button_layout3.count(), 1)

        button_layout4.addWidget(replace_chr_btn)
        button_layout4.addWidget(codec_swap_btn)
        button_layout4.addWidget(codec_clear_btn)

        # 添加所有组件到主布局
        # layout.addWidget(QLabel("输入:"))
        codec_group_layout = QGroupBox("输入区域")
        input_layout = QVBoxLayout()
        input_layout.addWidget(self.codec_input_text)
        codec_group_layout.setLayout(input_layout)
        layout.addWidget(codec_group_layout)

        layout.addLayout(button_layout)
        layout.addLayout(button_layout2)
        layout.addLayout(button_layout3)
        layout.addLayout(button_layout4)

        codec_group_layout2 = QGroupBox("输出区域")
        output_layout = QVBoxLayout()
        output_layout.addWidget(self.codec_output_text)
        codec_group_layout2.setLayout(output_layout)
        layout.addWidget(codec_group_layout2)

        # 添加按钮功能绑定
        base64_encode_btn.clicked.connect(self.base64_encode_text)
        base64_decode_btn.clicked.connect(self.base64_decode_text)
        base64_tohex_btn.clicked.connect(self.base64_to_hex_text)
        hex_tobase64_btn.clicked.connect(self.hex_to_base64_text)
        str_toasc_btn.clicked.connect(self.str_to_asc_text)
        asc_tostr_btn.clicked.connect(self.asc_to_str_text)
        escape_btn.clicked.connect(self.escape_text)
        unescape_btn.clicked.connect(self.unescape_text)
        unicode_tostr_btn.clicked.connect(self.unicode_to_str_text)
        str_tounicode_btn.clicked.connect(self.str_to_unicode_text)
        urlencode_btn.clicked.connect(self.urlencode_text)
        urldecode_btn.clicked.connect(self.urldecode_text)

        str_tohex_btn.clicked.connect(self.str_to_hex_text)
        hex_tostr_btn.clicked.connect(self.hex_to_str_text)

        str_lower_btn.clicked.connect(self.str_lower_text)
        str_upper_btn.clicked.connect(self.str_upper_text)
        str_swapcase_btn.clicked.connect(self.str_swapcase_text)
        str_reverse_btn.clicked.connect(self.str_reverse_text)
        remove_tab_btn.clicked.connect(self.remove_tab_text)
        remove_blank_btn.clicked.connect(self.remove_empty_chr)
        remove_blankline_btn.clicked.connect(self.remove_empty_lines)
        remove_line_btn.clicked.connect(self.remove_line_breaks)

        urlparam_to_jsonparam_btn.clicked.connect(self.urlparam_to_jsonparam_text)
        jsonparam_to_urlparam_btn.clicked.connect(self.jsonparam_to_urlparam_text)
        self.remove_chr_btn.stateChanged.connect(self.remove_chr_text)

        replace_chr_btn.clicked.connect(self.replace_chr_text)
        codec_swap_btn.clicked.connect(self.codec_swap_content)
        codec_clear_btn.clicked.connect(self.codec_clear_content)

    def init_base_tab(self):
        # 设置布局
        layout = QVBoxLayout(self.base_tab)

        # 第一排操作选项
        button_layout = QHBoxLayout()
        button_layout.setSpacing(5)
        button_layout.setAlignment(Qt.AlignCenter)
        self.base_type_combo = QComboBox()
        self.base_type_combo.addItems([
            "Base16", "Base32","Base36","Base45","Base58","Base62", "Base64","Base85",
            "Base91", "Base92","Base100","Base122"
        ])
        self.base_type_combo.setCurrentText("Base64")

        # 字符编码选择
        self.encoding_combo = QComboBox()
        self.encoding_combo.addItems([
            "UTF-8", "GBK", "GB2312", "ISO-8859-1", "GB18030","UTF-16","BIG5"
        ])
        self.encoding_combo.setCurrentText("UTF-8")
        type_label = QLabel("编码类型")
        encoding_label = QLabel("字符编码")

        # 添加到HBox容器
        button_layout.addWidget(type_label)
        button_layout.addWidget(self.base_type_combo)
        button_layout.addWidget(encoding_label)
        button_layout.addWidget(self.encoding_combo)

        # 第二排操作按钮
        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(5)
        button_layout2.setAlignment(Qt.AlignCenter)

        base_encode_btn = QPushButton("编码")
        base_decode_btn = QPushButton("解码")
        base_brute_btn = QPushButton("爆破")
        swap_btn = QPushButton("互换内容")
        clear_btn = QPushButton("清空内容")
        button_layout2.addWidget(base_encode_btn)
        button_layout2.addWidget(base_decode_btn)
        button_layout2.addWidget(base_brute_btn)
        button_layout2.addWidget(swap_btn)
        button_layout2.addWidget(clear_btn)

        base_group_layout = QGroupBox("输入区域")
        input_layout = QVBoxLayout()
        input_layout.addWidget(self.base_input_text)
        base_group_layout.setLayout(input_layout)
        layout.addWidget(base_group_layout)


        layout.addLayout(button_layout)
        layout.addLayout(button_layout2)

        base_group_layout2 = QGroupBox("输出区域")
        output_layout = QVBoxLayout()
        output_layout.addWidget(self.base_output_text)
        base_group_layout2.setLayout(output_layout)
        layout.addWidget(base_group_layout2)

        # 绑定按钮功能
        base_encode_btn.clicked.connect(self.base_encode_text)
        base_decode_btn.clicked.connect(self.base_decode_text)
        base_brute_btn.clicked.connect(self.brute_base_text)


        swap_btn.clicked.connect(self.base_swap_content)
        clear_btn.clicked.connect(self.base_clear_content)


    def init_other_codec_tab(self):
        layout = QVBoxLayout(self.other_codec_tab)

        # 第一排功能按钮
        button_layout = QHBoxLayout()
        # button_layout.setSpacing(5)
        button_layout.setAlignment(Qt.AlignCenter)


        self.other_encoding_type_combo = QComboBox()
        self.other_encoding_type_combo.addItems([
            "ASCII", "HEX", "HTML"
        ])
        # self.other_encoding_type_combo.addItems([
        #     "ASCII", "HEX", "HTML", "Brainfuck", "Ook", "shortOok", "Trollscript"
        # ])
        self.other_encoding_type_combo.setCurrentText("ASCII")
        self.other_encoding_type_combo.currentIndexChanged.connect(self.on_other_encoding_combo_changed)
        self.other_encoding_type_combo.setMaximumWidth(120)

        self.spilt_chr_combo = QComboBox()
        self.spilt_chr_combo.addItems(["space", "newline", "自定义"])
        self.spilt_chr_combo.setCurrentText("space")
        self.spilt_chr_combo.setMaximumWidth(120)
        self.spilt_chr_combo.currentIndexChanged.connect(self.on_spilt_chr_combo_changed)

        # 输入框（默认隐藏）
        self.chr_line_edit = QLineEdit()
        self.chr_line_edit.setFixedWidth(120)
        self.chr_line_edit.setAlignment(Qt.AlignCenter)
        # self.chr_line_edit.setPlaceholderText("请输入内容")
        self.chr_line_edit.hide()

        button_layout.addWidget(self.other_encoding_type_combo)
        button_layout.addWidget(self.spilt_chr_combo)
        button_layout.addWidget(self.chr_line_edit)

        # 第二排按钮
        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(5)
        button_layout2.setAlignment(Qt.AlignCenter)
        other_encode_btn = QPushButton("编码")
        other_decode_btn = QPushButton("解码")
        other_swap_btn = QPushButton("互换内容")
        other_clear_btn = QPushButton("清空内容")

        button_layout2.addWidget(other_encode_btn)
        button_layout2.addWidget(other_decode_btn)
        button_layout2.addWidget(other_swap_btn)
        button_layout2.addWidget(other_clear_btn)

        other_encode_btn.clicked.connect(self.other_encode_text)
        other_decode_btn.clicked.connect(self.other_decode_text)
        other_swap_btn.clicked.connect(self.other_swap_text)
        other_clear_btn.clicked.connect(self.other_clear_text)

        other_group_layout = QGroupBox("输入区域")
        input_layout = QVBoxLayout()
        input_layout.addWidget(self.other_codec_input_text)
        other_group_layout.setLayout(input_layout)
        layout.addWidget(other_group_layout)

        layout.addLayout(button_layout)
        layout.addLayout(button_layout2)

        other_group_layout2 = QGroupBox("输出区域")
        output_layout = QVBoxLayout()
        output_layout.addWidget(self.other_codec_output_text)
        other_group_layout2.setLayout(output_layout)
        layout.addWidget(other_group_layout2)

    def init_rot_codec_tab(self):
        # 主布局
        main_layout = QVBoxLayout(self.rot_codec_tab)
        # main_layout.setContentsMargins(15, 15, 15, 15)
        # main_layout.setSpacing(15)

        # 输入区域
        input_group = QGroupBox("输入区域")
        input_group.setFont(self.font())
        input_layout = QVBoxLayout()
        self.rot_input_text = QTextEdit()
        self.rot_input_text.setPlaceholderText("请输入需要编码/解码的内容...")
        # self.rot_input_text.setMinimumHeight(120)
        input_layout.addWidget(self.rot_input_text)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # 算法选择和按钮区域
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)

        # ROT算法选择
        rot_label = QLabel("ROT算法:")
        self.rot_combo = QComboBox()
        self.rot_combo.addItems(["5", "13", "15", "18", "47"])
        self.rot_combo.setCurrentText("47")
        self.rot_combo.setMinimumWidth(80)

        control_layout.addWidget(rot_label)
        control_layout.addWidget(self.rot_combo)
        control_layout.addStretch()

        # 功能按钮
        self.rot_encode_btn = QPushButton("🔒 加密")
        self.rot_decode_btn = QPushButton("🔓 解密")
        self.rot_brute_btn = QPushButton("🔍 爆破")
        self.rot_swap_btn = QPushButton("↔️ 互换")
        self.rot_clear_btn = QPushButton("🗑️ 清空")

        # 设置按钮样式
        buttons = [self.rot_encode_btn, self.rot_decode_btn, self.rot_brute_btn,
                   self.rot_swap_btn, self.rot_clear_btn]

        for btn in buttons:
            btn.setMinimumHeight(30)
            btn.setStyleSheet("""
                        QPushButton {
                            background-color: #f0f0f0;
                            border: 1px solid #d0d0d0;
                            border-radius: 4px;
                            padding: 5px 10px;
                        }
                        QPushButton:hover {
                            background-color: #e0e0e0;
                        }
                        QPushButton:pressed {
                            background-color: #d0d0d0;
                        }
                    """)
            control_layout.addWidget(btn)

        main_layout.addLayout(control_layout)

        # 输出区域
        output_group = QGroupBox("输出结果")
        output_group.setFont(self.font())
        output_layout = QVBoxLayout()
        self.rot_output_text = QTextEdit()
        self.rot_output_text.setReadOnly(True)
        self.rot_output_text.setMinimumHeight(120)
        # 设置等宽字体，使爆破结果对齐更美观

        output_layout.addWidget(self.rot_output_text)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)

        # 状态栏信息
        self.status_label = QLabel("就绪")
        self.status_label.setAlignment(Qt.AlignRight)
        main_layout.addWidget(self.status_label)

        # 设置主布局
        self.setLayout(main_layout)

        # 连接信号与槽
        self.rot_encode_btn.clicked.connect(self.rot_encode)
        self.rot_decode_btn.clicked.connect(self.rot_decode)
        self.rot_brute_btn.clicked.connect(self.rot_brute_force)
        self.rot_swap_btn.clicked.connect(self.rot_swap_content)
        self.rot_clear_btn.clicked.connect(self.rot_clear_content)

    def rot_encode(self):
        input_content = self.rot_input_text.toPlainText()
        if not input_content:
            self.status_label.setText("错误: 请输入内容")
            return

        try:
            rot = int(self.rot_combo.currentText())
            result = ROTCodec().encode(input_content, rot)
            self.rot_output_text.setPlainText(result)
            self.status_label.setText(f"已完成 ROT{rot} 加密")
        except Exception as e:
            self.status_label.setText(f"错误: {str(e)}")

    def rot_decode(self):
        input_content = self.rot_input_text.toPlainText()
        if not input_content:
            self.status_label.setText("错误: 请输入内容")
            return

        try:
            rot = int(self.rot_combo.currentText())
            result = ROTCodec().decode(input_content, rot)
            self.rot_output_text.setPlainText(result)
            self.status_label.setText(f"已完成 ROT{rot} 解密")
        except Exception as e:
            self.status_label.setText(f"错误: {str(e)}")

    def rot_brute_force(self):
        input_content = self.rot_input_text.toPlainText()
        if not input_content:
            self.status_label.setText("错误: 请输入内容")
            return

        try:
            results = ROTCodec().brute_force(input_content)
            result_text = "=== 爆破结果 ===\n"  # 标题

            # 为每个ROT算法结果添加分隔线和格式化输出
            for i, (rot, res) in enumerate(results.items()):
                # 添加分隔线（除了第一个结果）
                if i > 0:
                    result_text += "-" * 60 + "\n"

                # 添加算法名称，加粗显示
                result_text += f"【ROT{rot}】:"
                # 添加结果，缩进显示
                result_text += f"{res}\n"

            self.rot_output_text.setPlainText(result_text.strip())
            self.status_label.setText("已完成所有算法爆破")
        except Exception as e:
            self.status_label.setText(f"错误: {str(e)}")

    def rot_swap_content(self):
        input_content = self.rot_input_text.toPlainText()
        output_content = self.rot_output_text.toPlainText()
        self.rot_input_text.setPlainText(output_content)
        self.rot_output_text.setPlainText(input_content)
        self.status_label.setText("已交换输入输出内容")

    def rot_clear_content(self):
        self.rot_input_text.clear()
        self.rot_output_text.clear()
        self.status_label.setText("已清空所有内容")


    def other_encode_text(self):
        input = self.other_codec_input_text.toPlainText()
        other_encode_type = self.other_encoding_type_combo.currentText()
        other_chr_combo = self.spilt_chr_combo.currentText()
        other_customize_chr = self.chr_line_edit.text().strip()
        try:
            if(other_encode_type=="ASCII"):
                result = []
                for char in input:
                    result.append(str(ord(char)))
                if(other_chr_combo=="space"):
                    self.other_codec_output_text.setPlainText(' '.join(result))
                elif(other_chr_combo=="newline"):
                    self.other_codec_output_text.setPlainText('\n'.join(result))
                else:
                    self.other_codec_output_text.setPlainText(f'{other_customize_chr}'.join(result))
            elif(other_encode_type=="HEX"):
                result = []
                for char in input:
                    result.append(char.encode("utf-8").hex())
                if (other_chr_combo == "space"):
                    self.other_codec_output_text.setPlainText(' '.join(result))
                elif (other_chr_combo == "newline"):
                    self.other_codec_output_text.setPlainText('\n'.join(result))
                elif (other_chr_combo == "0x"):
                    self.other_codec_output_text.setPlainText('0x'.join(result))
                elif (other_chr_combo == "\\x"):
                    self.other_codec_output_text.setPlainText(''.join(f"\\x{byte:02X}" for byte in input.encode('utf-8')))
                else:
                    self.other_codec_output_text.setPlainText(f'{other_customize_chr}'.join(result))
            elif (other_encode_type == "HTML"):
                encoded = html.escape(input)
                if(other_chr_combo == "&#[dec]"):
                    result = ''.join(f'&#{ord(char)};' for char in input)
                    self.other_codec_output_text.setPlainText(result)
                elif(other_chr_combo == "&#x[hex]"):
                    result = ''.join(f'&#x{ord(char):x};' for char in input)
                    self.other_codec_output_text.setPlainText(result)
                else:
                    self.other_codec_output_text.setPlainText(encoded)


        except Exception as e:
            self.other_codec_output_text.setPlainText(f'出错了：{e}')

    def other_decode_text(self):
        input = self.other_codec_input_text.toPlainText()
        other_encode_type = self.other_encoding_type_combo.currentText()
        other_chr_combo = self.spilt_chr_combo.currentText()
        other_customize_chr = self.chr_line_edit.text().strip()
        try:
            if (other_encode_type == "ASCII"):
                if (other_chr_combo == "space"):
                    ascii_list = list(map(int, input.split(' ')))
                    self.other_codec_output_text.setPlainText(''.join(chr(i) for i in ascii_list))
                elif (other_chr_combo == "newline"):
                    ascii_list = list(map(int, input.split('\n')))
                    self.other_codec_output_text.setPlainText(''.join(chr(i) for i in ascii_list))
                else:
                    ascii_list = list(map(int, input.split(f'{other_customize_chr}')))
                    self.other_codec_output_text.setPlainText(''.join(chr(i) for i in ascii_list))
            elif (other_encode_type == "HEX"):
                if (other_chr_combo == "space"):
                    result = bytes.fromhex(input).decode('utf-8')
                    self.other_codec_output_text.setPlainText(result)
                elif (other_chr_combo == "newline"):
                    result = bytes.fromhex(input).decode('utf-8')
                    self.other_codec_output_text.setPlainText(result)
                elif (other_chr_combo == "0x"):
                    data = input.replace("0x","")
                    result = bytes.fromhex(data).decode('utf-8')
                    self.other_codec_output_text.setPlainText(result)
                elif (other_chr_combo == "\\x"):
                    data = input.replace("\\x","")
                    result = bytes.fromhex(data).decode('utf-8')
                    self.other_codec_output_text.setPlainText(result)
                else:
                    input_data = input.replace(other_customize_chr,"")
                    result = bytes.fromhex(input_data).decode('utf-8')
                    self.other_codec_output_text.setPlainText(result)
            elif (other_encode_type == "HTML"):
                if(other_chr_combo == "&#[dec]"):
                    result = NormalUtils.decode_decimal_entities(input)
                    self.other_codec_output_text.setPlainText(result)
                elif(other_chr_combo == "&#x[hex]"):
                    result = NormalUtils.decode_hexadecimal_entities(input)
                    self.other_codec_output_text.setPlainText(result)
                else:
                    result = html.unescape(input)
                    self.other_codec_output_text.setPlainText(result)


        except Exception as e:
            self.other_codec_output_text.setPlainText(f'出错了：{e}')

    def other_swap_text(self):
        ToolUtils.swap_content(self.other_codec_input_text,self.other_codec_output_text)

    def other_clear_text(self):
        self.other_codec_output_text.clear()
        self.other_codec_input_text.clear()

    def replace_chr_text(self):
        input = self.codec_input_text.toPlainText()
        dialog = ReplaceChrDialog(self)
        dialog.exec_()
        current_chr = dialog.get_current_chr()
        # print(current_chr)
        replace_chr = dialog.get_replace_chr()
        # print(replace_chr)
        result = input.replace(current_chr, replace_chr)
        self.codec_output_text.setPlainText(result)

    def on_other_encoding_combo_changed(self,index):
        self.spilt_chr_combo.clear()
        self.chr_line_edit.clear()
            # 根据第一个 combo 设置 combo2 的内容
        if (self.other_encoding_type_combo.currentText() == "ASCII"):
            self.spilt_chr_combo.addItems(["space", "newline", "自定义"])
            self.spilt_chr_combo.setCurrentText("space")
        elif (self.other_encoding_type_combo.currentText() == "HEX"):
            self.spilt_chr_combo.addItems(["space", "newline", "0x", "\\x","自定义"])
            self.spilt_chr_combo.setCurrentText("space")
        elif self.other_encoding_type_combo.currentText() == "HTML":
            self.spilt_chr_combo.addItems(["&#[dec]", "&#x[hex]", "&[char]"])
            self.spilt_chr_combo.setCurrentText("&#[dec]")
        else:
            self.spilt_chr_combo.addItems(["UTF-8", "GBK", "GB2312", "ISO-8859-1", "GB18030","UTF-16","BIG5"])
            self.spilt_chr_combo.setCurrentText("UTF-8")





    def on_spilt_chr_combo_changed(self):
        selected = self.spilt_chr_combo.currentText()
        if selected == "自定义":
            self.chr_line_edit.show()
        else:
            self.chr_line_edit.hide()

    def base_swap_content(self):
        """互换输入输出内容"""
        ToolUtils.swap_content(self.base_input_text,self.base_output_text)

    def base_clear_content(self):
        """清空输入输出内容"""
        ToolUtils.clear_content(self.base_input_text,self.base_output_text)

    def codec_swap_content(self):
        """互换输入输出内容"""
        ToolUtils.swap_content(self.codec_input_text,self.codec_output_text)

    def codec_clear_content(self):
        """清空输入输出内容"""
        ToolUtils.clear_content(self.codec_input_text,self.codec_output_text)

    def base64_decode_text(self):
        input = self.codec_input_text.toPlainText().strip()
        input = urllib.parse.unquote(input)
        try:
            result = base64.b64decode(input.encode("UTF-8")).decode("UTF-8",errors='ignore')
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def base64_encode_text(self):
        input = self.codec_input_text.toPlainText().strip()

        try:
            result = base64.b64encode(input.encode("UTF-8")).decode("UTF-8",errors='ignore')
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def base64_to_hex_text(self):
        input = self.codec_input_text.toPlainText().strip()
        try:
            # 尝试解码，无效的Base64会引发异常
            byte_data = base64.b64decode(input)

            # 转换为Hex
            hex_data = byte_data.hex()
            self.codec_output_text.setPlainText(hex_data)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")


    def hex_to_base64_text(self):
        input = self.codec_input_text.toPlainText().strip()
        hex_data = input.replace(" ", "")
        try:
            # 转换为字节
            byte_data = bytes.fromhex(hex_data)
            # 编码为Base64
            base64_data = base64.b64encode(byte_data)
            result = base64_data.decode('ascii')
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def str_to_asc_text(self):
        input = self.codec_input_text.toPlainText().strip()
        try:
            result = []
            for char in input:
                result.append(str(ord(char)))
                result.append('')  # 添加一个空行
            self.codec_output_text.setPlainText(' '.join(result))
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def asc_to_str_text(self):
        input = self.codec_input_text.toPlainText().strip()
        try:
            if(input.endswith("\n")):
                ascii_list = list(map(int, input.split("\n")))
                self.codec_output_text.setPlainText(''.join(chr(i) for i in ascii_list))
            else:
                ascii_list = list(map(int, input.split()))
                self.codec_output_text.setPlainText(''.join(chr(i) for i in ascii_list))
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def escape_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            # result = urllib.parse.quote(input)
            result = NormalUtils.escape_text(input)
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def unescape_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            # result = urllib.parse.quote(input)
            result = NormalUtils.unescape_text(input)
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def unicode_to_str_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = UnicodeDecoder.decode_mixed(input)
            # decoded_str = input.encode('utf-8').decode('unicode_escape')
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def str_to_unicode_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = ''.join(f'\\u{ord(c):04x}' for c in input)
            # unicode_str = ''.join([f"\\u{ord(char):04x}" for char in input])
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def urlencode_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = urllib.parse.quote(input,encoding="utf-8")
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def urldecode_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = urllib.parse.unquote(input)
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def str_to_hex_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = input.encode("utf-8").hex()
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def hex_to_str_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = bytes.fromhex(input).decode('utf-8')
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def str_lower_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = input.lower()
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def str_upper_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = input.upper()
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def str_swapcase_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = input.swapcase()
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def remove_empty_chr(self):
        input = self.codec_input_text.toPlainText()
        # 过滤掉空格
        result = input.strip().replace(" ","")
        self.codec_input_text.setPlainText(result)

    def remove_empty_lines(self):
        input = self.codec_input_text.toPlainText()
        # result = re.sub(r'^\s*$', '', input, flags=re.M)
        result = [line for line in input.splitlines() if line.strip()]
        result ="\n".join(result)
        self.codec_input_text.setPlainText(result)

    def remove_line_breaks(self):
        text = self.codec_input_text.toPlainText()
        # 将所有换行替换为空格
        result = text.replace('\n', ' ')
        self.codec_input_text.setPlainText(result)

    def remove_tab_text(self):
        text = self.codec_input_text.toPlainText()
        # 将所有换行替换为空格
        result = text.replace('\t', ' ')
        self.codec_input_text.setPlainText(result)

    def str_reverse_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = input[::-1]
            self.codec_input_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def urlparam_to_jsonparam_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = NormalUtils.url_params_to_dict(input)
            self.codec_output_text.setPlainText(str(result))
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def jsonparam_to_urlparam_text(self):
        input = self.codec_input_text.toPlainText()
        try:
            result = NormalUtils.jsonparam_to_url_params(input)
            self.codec_output_text.setPlainText(result)
        except Exception as e:
            self.codec_output_text.setPlainText(f"出错了：{e}")

    def remove_chr_text(self):
        input = self.codec_input_text.toPlainText()
        replace_chr = self.remove_chr_line.text().strip()
        if(self.remove_chr_btn.isChecked()):
            if(replace_chr!=''):
                result = input.replace(replace_chr,'')
                self.codec_output_text.setPlainText(result)

    def base_encode_text(self):
        base_type = self.base_type_combo.currentText()
        # print(base_type)
        base_encoding = self.encoding_combo.currentText()
        # print(base_encoding)
        input = self.base_input_text.toPlainText().strip()
        # print(input)
        try:
            if(base_type=='Base16'):
                result = BaseCodec.base16_encode(input,base_encoding)
                self.base_output_text.setPlainText(result)
            if (base_type == 'Base32'):
                result = BaseCodec.base32_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base36'):
                result = BaseCodec.base36_encode(input, base_encoding)
                self.base_output_text.setPlainText(str(result))
            elif (base_type == 'Base45'):
                result = BaseCodec.base45_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base58'):
                result = BaseCodec.base58_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base62'):
                result = BaseCodec.base62_encode(input, base_encoding)
                self.base_output_text.setPlainText(str(result))
            elif (base_type == 'Base64'):
                result = BaseCodec.base64_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base85'):
                result = BaseCodec.base85_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base91'):
                result = BaseCodec.base91_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base92'):
                result = BaseCodec.base92_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base122'):
                result = BaseCodec.base122_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base100'):
                result = BaseCodec.base100_encode(input, base_encoding)
                self.base_output_text.setPlainText(result)

        except Exception as e:
            self.base_output_text.setPlainText(f"出错了：{e}")

    def base_decode_text(self):
        base_type = self.base_type_combo.currentText()
        base_encoding = self.encoding_combo.currentText()
        input = self.base_input_text.toPlainText().strip()
        try:
            if(base_type=='Base16'):
                result = BaseCodec.base16_decode(input,base_encoding)
                self.base_output_text.setPlainText(result)
            if (base_type == 'Base32'):
                result = BaseCodec.base32_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            if (base_type == 'Base36'):
                result = BaseCodec.base36_decode(input, base_encoding)
                self.base_output_text.setPlainText(str(result))
            elif (base_type == 'Base45'):
                result = BaseCodec.base45_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base58'):
                result = BaseCodec.base58_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base62'):
                result = BaseCodec.base62_decode(input, base_encoding)
                self.base_output_text.setPlainText(str(result))
            elif (base_type == 'Base64'):
                result = BaseCodec.base64_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base85'):
                result = BaseCodec.base85_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base91'):
                result = BaseCodec.base91_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base92'):
                result = BaseCodec.base92_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base122'):
                result = BaseCodec.base122_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)
            elif (base_type == 'Base100'):
                result = BaseCodec.base100_decode(input, base_encoding)
                self.base_output_text.setPlainText(result)

        except Exception as e:
            self.base_output_text.setPlainText(f"出错了：{e}")


    def brute_base_text(self):
        base_type = self.base_type_combo.currentText()
        base_encoding = self.encoding_combo.currentText()
        input = self.base_input_text.toPlainText().strip()
        self.base_output_text.clear()
        try:
            result = BaseCodec.auto_decode(input,base_encoding)
            data = ''
            for item in result:
                data += f'<p><span style="color:green;">[+]{item["base"]} : {item["result"]}</span></p>'
                # print(data)
            self.base_output_text.setPlainText("爆破结果如下：\n")
            self.base_output_text.append(data)
        except Exception as e:
            self.base_output_text.setPlainText(f"出错了：{e}")