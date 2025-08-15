
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QTextEdit, QPushButton, QApplication, QLabel
)
from PySide6.QtCore import Qt, QMimeData
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
import json

try:
    import yaml
except ImportError:
    yaml = None
try:
    import toml
except ImportError:
    toml = None
import xml.etree.ElementTree as ET
import sys
import csv
import io
import configparser
import os
import re

# --- Syntax Highlighters ---

class JsonHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        # Key
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#007acc"))
        key_format.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(r'"(.*?)"\s*:'), key_format))

        # String value
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.rules.append((re.compile(r':\s*"(.*?)"'), string_format))

        # Number
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#b5cea8"))
        self.rules.append((re.compile(r':\s*([0-9\.\-eE]+)'), number_format))

        # Boolean/null
        bool_format = QTextCharFormat()
        bool_format.setForeground(QColor("#569cd6"))
        self.rules.append((re.compile(r':\s*(true|false|null)'), bool_format))

        # Braces/brackets
        brace_format = QTextCharFormat()
        brace_format.setForeground(QColor("#d4d4d4"))
        self.rules.append((re.compile(r'[\{\}\[\]]'), brace_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                start, end = match.span(1) if pattern.groups else match.span()
                self.setFormat(start, end - start, fmt)

class XmlHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        # Tag
        tag_format = QTextCharFormat()
        tag_format.setForeground(QColor("#569cd6"))
        tag_format.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(r'</?[\w:.-]+'), tag_format))

        # Attribute
        attr_format = QTextCharFormat()
        attr_format.setForeground(QColor("#9cdcfe"))
        self.rules.append((re.compile(r'(\w+)=(".*?")'), attr_format))

        # String
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.rules.append((re.compile(r'"[^"]*"'), string_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                if pattern.groups:
                    for i in range(1, pattern.groups + 1):
                        if match.start(i) != -1:
                            self.setFormat(match.start(i), match.end(i) - match.start(i), fmt)
                else:
                    self.setFormat(match.start(), match.end() - match.start(), fmt)

class YamlHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        # Key
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#dcdcaa"))
        key_format.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(r'^(\s*[\w\-]+):'), key_format))

        # String
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.rules.append((re.compile(r':\s*"(.*?)"'), string_format))

        # Number
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#b5cea8"))
        self.rules.append((re.compile(r':\s*([0-9\.\-eE]+)'), number_format))

        # Boolean/null
        bool_format = QTextCharFormat()
        bool_format.setForeground(QColor("#569cd6"))
        self.rules.append((re.compile(r':\s*(true|false|null)'), bool_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                if pattern.groups:
                    for i in range(1, pattern.groups + 1):
                        if match.start(i) != -1:
                            self.setFormat(match.start(i), match.end(i) - match.start(i), fmt)
                else:
                    self.setFormat(match.start(), match.end() - match.start(), fmt)

class TomlHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        # Section
        section_format = QTextCharFormat()
        section_format.setForeground(QColor("#569cd6"))
        section_format.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(r'^\s*\[.*\]'), section_format))

        # Key
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#dcdcaa"))
        self.rules.append((re.compile(r'^(\s*[\w\-]+)\s*='), key_format))

        # String
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.rules.append((re.compile(r'=\s*"(.*?)"'), string_format))

        # Number
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#b5cea8"))
        self.rules.append((re.compile(r'=\s*([0-9\.\-eE]+)'), number_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                if pattern.groups:
                    for i in range(1, pattern.groups + 1):
                        if match.start(i) != -1:
                            self.setFormat(match.start(i), match.end(i) - match.start(i), fmt)
                else:
                    self.setFormat(match.start(), match.end() - match.start(), fmt)

class IniHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules = []

        # Section
        section_format = QTextCharFormat()
        section_format.setForeground(QColor("#569cd6"))
        section_format.setFontWeight(QFont.Bold)
        self.rules.append((re.compile(r'^\s*\[.*\]'), section_format))

        # Key
        key_format = QTextCharFormat()
        key_format.setForeground(QColor("#dcdcaa"))
        self.rules.append((re.compile(r'^(\s*[\w\-]+)\s*='), key_format))

        # String
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#ce9178"))
        self.rules.append((re.compile(r'=\s*"(.*?)"'), string_format))

        # Number
        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#b5cea8"))
        self.rules.append((re.compile(r'=\s*([0-9\.\-eE]+)'), number_format))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                if pattern.groups:
                    for i in range(1, pattern.groups + 1):
                        if match.start(i) != -1:
                            self.setFormat(match.start(i), match.end(i) - match.start(i), fmt)
                else:
                    self.setFormat(match.start(), match.end() - match.start(), fmt)

# --- End Syntax Highlighters ---

class DraggableTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                file_path = urls[0].toLocalFile()
                if os.path.isfile(file_path):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()
                        self.setPlainText(content)
                    except Exception as e:
                        self.setPlainText(f"文件读取失败: {e}")
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

class JsonConverter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("JsonConverter工具")
        self.resize(1000, 700)
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)

        # 输入区域
        input_group = QGroupBox("输入")
        input_layout = QVBoxLayout()
        self.input_text = DraggableTextEdit()
        input_layout.addWidget(self.input_text)
        # 输入格式化和高亮按钮
        input_btn_layout = QHBoxLayout()
        input_btn_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.btn_format_input = QPushButton("🧹 格式化/高亮")
        input_btn_layout.addWidget(self.btn_format_input)
        input_layout.addLayout(input_btn_layout)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # 功能按钮区（三排，最后一排为互换和清空），使用三个QHBoxLayout并居中
        # 第一排按钮
        self.btn_json2xml = QPushButton("🗂️ JSON → XML")
        self.btn_xml2json = QPushButton("📄 XML → JSON")
        self.btn_json2yaml = QPushButton("📝 JSON → YAML")
        self.btn_yaml2json = QPushButton("📄 YAML → JSON")
        self.btn_json2toml = QPushButton("📑 JSON → TOML")
        self.btn_toml2json = QPushButton("📄 TOML → JSON")
        # 第二排按钮
        self.btn_yaml2toml = QPushButton("📑 YAML → TOML")
        self.btn_toml2yaml = QPushButton("📝 TOML → YAML")
        self.btn_json2csv = QPushButton("📊 JSON → CSV")
        self.btn_csv2json = QPushButton("📄 CSV → JSON")
        self.btn_json2ini = QPushButton("🏷️ JSON → INI")
        self.btn_ini2json = QPushButton("📄 INI → JSON")
        # 第三排按钮
        self.btn_json2pb = QPushButton("🧬 JSON → ProtoBuf")
        self.btn_pb2json = QPushButton("📄 ProtoBuf → JSON")
        self.btn_json2gql = QPushButton("🕸️ JSON → GraphQL")
        self.btn_gql2json = QPushButton("📄 GraphQL → JSON")
        self.btn_json2html = QPushButton("🌐 JSON → HTML")
        self.btn_html2json = QPushButton("📄 HTML → JSON")
        # 互换和清空
        self.btn_swap = QPushButton("🔄 互换内容")
        self.btn_clear = QPushButton("🗑️ 清空内容")

        # 第一排布局
        hbox1 = QHBoxLayout()
        hbox1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hbox1.addWidget(self.btn_json2xml)
        hbox1.addWidget(self.btn_xml2json)
        hbox1.addWidget(self.btn_json2yaml)
        hbox1.addWidget(self.btn_yaml2json)
        hbox1.addWidget(self.btn_json2toml)
        hbox1.addWidget(self.btn_toml2json)

        # 第二排布局
        hbox2 = QHBoxLayout()
        hbox2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hbox2.addWidget(self.btn_yaml2toml)
        hbox2.addWidget(self.btn_toml2yaml)
        hbox2.addWidget(self.btn_json2csv)
        hbox2.addWidget(self.btn_csv2json)
        hbox2.addWidget(self.btn_json2ini)
        hbox2.addWidget(self.btn_ini2json)

        # 第三排布局
        hbox3 = QHBoxLayout()
        hbox3.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hbox3.addWidget(self.btn_json2pb)
        hbox3.addWidget(self.btn_pb2json)
        hbox3.addWidget(self.btn_json2gql)
        hbox3.addWidget(self.btn_gql2json)
        hbox3.addWidget(self.btn_json2html)
        hbox3.addWidget(self.btn_html2json)

        # 互换和清空按钮单独一排，居中
        hbox4 = QHBoxLayout()
        hbox4.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hbox4.addWidget(self.btn_swap)
        hbox4.addWidget(self.btn_clear)

        # 添加到主布局
        main_layout.addLayout(hbox1)
        main_layout.addLayout(hbox2)
        main_layout.addLayout(hbox3)
        main_layout.addLayout(hbox4)

        # 输出区域
        output_group = QGroupBox("输出")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        output_layout.addWidget(self.output_text)
        # 输出格式化和高亮按钮
        output_btn_layout = QHBoxLayout()
        output_btn_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.btn_format_output = QPushButton("🧹 格式化/高亮")
        output_btn_layout.addWidget(self.btn_format_output)
        output_layout.addLayout(output_btn_layout)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)

        # 连接信号
        self.btn_json2xml.clicked.connect(lambda: self.convert("JSON", "XML"))
        self.btn_xml2json.clicked.connect(lambda: self.convert("XML", "JSON"))
        self.btn_json2yaml.clicked.connect(lambda: self.convert("JSON", "YAML"))
        self.btn_yaml2json.clicked.connect(lambda: self.convert("YAML", "JSON"))
        self.btn_json2toml.clicked.connect(lambda: self.convert("JSON", "TOML"))
        self.btn_toml2json.clicked.connect(lambda: self.convert("TOML", "JSON"))
        self.btn_yaml2toml.clicked.connect(lambda: self.convert("YAML", "TOML"))
        self.btn_toml2yaml.clicked.connect(lambda: self.convert("TOML", "YAML"))
        self.btn_json2csv.clicked.connect(lambda: self.convert("JSON", "CSV"))
        self.btn_csv2json.clicked.connect(lambda: self.convert("CSV", "JSON"))
        self.btn_json2ini.clicked.connect(lambda: self.convert("JSON", "INI"))
        self.btn_ini2json.clicked.connect(lambda: self.convert("INI", "JSON"))
        self.btn_json2pb.clicked.connect(lambda: self.convert("JSON", "PROTOBUF"))
        self.btn_pb2json.clicked.connect(lambda: self.convert("PROTOBUF", "JSON"))
        self.btn_json2gql.clicked.connect(lambda: self.convert("JSON", "GRAPHQL"))
        self.btn_gql2json.clicked.connect(lambda: self.convert("GRAPHQL", "JSON"))
        self.btn_json2html.clicked.connect(lambda: self.convert("JSON", "HTML"))
        self.btn_html2json.clicked.connect(lambda: self.convert("HTML", "JSON"))
        self.btn_swap.clicked.connect(self.swap_content)
        self.btn_clear.clicked.connect(self.clear_content)
        self.btn_format_input.clicked.connect(self.format_and_highlight_input)
        self.btn_format_output.clicked.connect(self.format_and_highlight_output)

        # 记录当前输入/输出格式
        self.input_format = None
        self.output_format = None

        # 高亮器
        self.input_highlighter = None
        self.output_highlighter = None

    def set_highlighter(self, textedit, fmt):
        # Remove previous highlighter
        if hasattr(textedit, "_highlighter") and textedit._highlighter:
            textedit._highlighter.setDocument(None)
            textedit._highlighter = None
        if fmt == "JSON":
            textedit._highlighter = JsonHighlighter(textedit.document())
        elif fmt == "XML":
            textedit._highlighter = XmlHighlighter(textedit.document())
        elif fmt == "YAML":
            textedit._highlighter = YamlHighlighter(textedit.document())
        elif fmt == "TOML":
            textedit._highlighter = TomlHighlighter(textedit.document())
        elif fmt == "INI":
            textedit._highlighter = IniHighlighter(textedit.document())
        else:
            textedit._highlighter = None

    def detect_format(self, text):
        # Try to detect format by content
        t = text.strip()
        if not t:
            return None
        if t.startswith("{") or t.startswith("["):
            try:
                json.loads(t)
                return "JSON"
            except Exception:
                pass
        if t.startswith("<"):
            if t.startswith("<?xml") or re.match(r"<[a-zA-Z]", t):
                return "XML"
        if t.startswith("---") or ":" in t:
            if yaml is not None:
                try:
                    yaml.safe_load(t)
                    return "YAML"
                except Exception:
                    pass
        if t.startswith("[") and "]" in t:
            if toml is not None:
                try:
                    toml.loads(t)
                    return "TOML"
                except Exception:
                    pass
        if "[" in t and "]" in t and "=" in t:
            return "INI"
        return None

    def format_and_highlight_input(self):
        text = self.input_text.toPlainText()
        fmt = self.detect_format(text)
        if fmt == "JSON":
            try:
                obj = json.loads(text)
                pretty = json.dumps(obj, ensure_ascii=False, indent=2)
                self.input_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "YAML" and yaml is not None:
            try:
                obj = yaml.safe_load(text)
                pretty = yaml.safe_dump(obj, allow_unicode=True, sort_keys=False)
                self.input_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "TOML" and toml is not None:
            try:
                obj = toml.loads(text)
                pretty = toml.dumps(obj)
                self.input_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "XML":
            try:
                elem = ET.fromstring(text)
                pretty = ET.tostring(elem, encoding="unicode")
                self.input_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "INI":
            try:
                config = configparser.ConfigParser()
                config.read_string(text)
                output = io.StringIO()
                config.write(output)
                self.input_text.setPlainText(output.getvalue())
            except Exception:
                pass
        self.set_highlighter(self.input_text, fmt)

    def format_and_highlight_output(self):
        text = self.output_text.toPlainText()
        fmt = self.detect_format(text)
        if fmt == "JSON":
            try:
                obj = json.loads(text)
                pretty = json.dumps(obj, ensure_ascii=False, indent=2)
                self.output_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "YAML" and yaml is not None:
            try:
                obj = yaml.safe_load(text)
                pretty = yaml.safe_dump(obj, allow_unicode=True, sort_keys=False)
                self.output_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "TOML" and toml is not None:
            try:
                obj = toml.loads(text)
                pretty = toml.dumps(obj)
                self.output_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "XML":
            try:
                elem = ET.fromstring(text)
                pretty = ET.tostring(elem, encoding="unicode")
                self.output_text.setPlainText(pretty)
            except Exception:
                pass
        elif fmt == "INI":
            try:
                config = configparser.ConfigParser()
                config.read_string(text)
                output = io.StringIO()
                config.write(output)
                self.output_text.setPlainText(output.getvalue())
            except Exception:
                pass
        self.set_highlighter(self.output_text, fmt)

    def convert(self, from_fmt, to_fmt):
        input_data = self.input_text.toPlainText()
        try:
            # Step 1: Parse input to Python object
            if from_fmt == "JSON":
                obj = json.loads(input_data)
            elif from_fmt == "XML":
                obj = self.xml_to_obj(input_data)
            elif from_fmt == "YAML":
                if yaml is None:
                    self.output_text.setPlainText("未安装PyYAML库")
                    return
                obj = yaml.safe_load(input_data)
            elif from_fmt == "TOML":
                if toml is None:
                    self.output_text.setPlainText("未安装toml库")
                    return
                obj = toml.loads(input_data)
            elif from_fmt == "CSV":
                obj = self.csv_to_obj(input_data)
            elif from_fmt == "INI":
                obj = self.ini_to_obj(input_data)
            elif from_fmt == "PROTOBUF":
                obj = self.protobuf_to_obj(input_data)
            elif from_fmt == "GRAPHQL":
                obj = self.graphql_to_obj(input_data)
            elif from_fmt == "HTML":
                obj = self.html_to_obj(input_data)
            else:
                self.output_text.setPlainText("不支持的输入格式")
                return

            # Step 2: Dump Python object to target format
            if to_fmt == "JSON":
                out = json.dumps(obj, ensure_ascii=False, indent=2)
            elif to_fmt == "XML":
                out = self.obj_to_xml(obj)
            elif to_fmt == "YAML":
                if yaml is None:
                    self.output_text.setPlainText("未安装PyYAML库")
                    return
                out = yaml.safe_dump(obj, allow_unicode=True, sort_keys=False)
            elif to_fmt == "TOML":
                if toml is None:
                    self.output_text.setPlainText("未安装toml库")
                    return
                out = toml.dumps(obj)
            elif to_fmt == "CSV":
                out = self.obj_to_csv(obj)
            elif to_fmt == "INI":
                out = self.obj_to_ini(obj)
            elif to_fmt == "PROTOBUF":
                out = self.obj_to_protobuf(obj)
            elif to_fmt == "GRAPHQL":
                out = self.obj_to_graphql(obj)
            elif to_fmt == "HTML":
                out = self.obj_to_html(obj)
            else:
                out = "不支持的输出格式"
            self.output_text.setPlainText(out)
            # 自动高亮输出
            self.set_highlighter(self.output_text, to_fmt)
        except Exception as e:
            self.output_text.setPlainText(f"转换失败: {e}")

    def swap_content(self):
        input_text = self.input_text.toPlainText()
        output_text = self.output_text.toPlainText()
        self.input_text.setPlainText(output_text)
        self.output_text.setPlainText(input_text)
        # 自动高亮
        self.format_and_highlight_input()
        self.format_and_highlight_output()

    def clear_content(self):
        self.input_text.clear()
        self.output_text.clear()
        self.set_highlighter(self.input_text, None)
        self.set_highlighter(self.output_text, None)

    def xml_to_obj(self, xml_str):
        def elem_to_internal(elem):
            d = {}
            # 处理属性
            if elem.attrib:
                d.update(('@' + k, v) for k, v in elem.attrib.items())
            # 处理子元素
            children = list(elem)
            if children:
                dd = {}
                for child in children:
                    child_obj = elem_to_internal(child)
                    tag = child.tag
                    if tag in dd:
                        if not isinstance(dd[tag], list):
                            dd[tag] = [dd[tag]]
                        dd[tag].append(child_obj[tag])
                    else:
                        dd.update(child_obj)
                d[elem.tag] = dd
            else:
                d[elem.tag] = elem.text if elem.text is not None else ""
            return d
        root = ET.fromstring(xml_str)
        return elem_to_internal(root)

    def obj_to_xml(self, obj):
        def build_elem(key, value):
            elem = ET.Element(str(key))
            if isinstance(value, dict):
                for k, v in value.items():
                    child = build_elem(k, v)
                    elem.append(child)
            elif isinstance(value, list):
                for item in value:
                    child = build_elem("item", item)
                    elem.append(child)
            else:
                elem.text = str(value)
            return elem
        # 只取第一个key为根
        if isinstance(obj, dict) and len(obj) == 1:
            root_key = next(iter(obj))
            root_elem = build_elem(root_key, obj[root_key])
        else:
            root_elem = build_elem("root", obj)
        return ET.tostring(root_elem, encoding="unicode")

    def csv_to_obj(self, csv_str):
        f = io.StringIO(csv_str)
        reader = csv.DictReader(f)
        return [row for row in reader]

    def obj_to_csv(self, obj):
        if not isinstance(obj, list):
            raise ValueError("CSV输出仅支持对象数组")
        if not obj:
            return ""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=obj[0].keys())
        writer.writeheader()
        for row in obj:
            writer.writerow(row)
        return output.getvalue()

    def ini_to_obj(self, ini_str):
        config = configparser.ConfigParser()
        config.read_string(ini_str)
        result = {}
        for section in config.sections():
            result[section] = dict(config.items(section))
        return result

    def obj_to_ini(self, obj):
        config = configparser.ConfigParser()
        for section, values in obj.items():
            config[section] = {}
            for k, v in values.items():
                config[section][k] = str(v)
        output = io.StringIO()
        config.write(output)
        return output.getvalue()

    def obj_to_protobuf(self, obj):
        # 简单实现：将json转为伪proto文本
        def to_proto(obj, indent=0, name="Message"):
            lines = []
            ind = "  " * indent
            if isinstance(obj, dict):
                lines.append(f"{ind}message {name} {{")
                idx = 1
                for k, v in obj.items():
                    field_type = "string"
                    if isinstance(v, int):
                        field_type = "int32"
                    elif isinstance(v, float):
                        field_type = "float"
                    elif isinstance(v, list):
                        field_type = "repeated string"
                    elif isinstance(v, dict):
                        field_type = k.capitalize()
                    if isinstance(v, dict):
                        lines.append(to_proto(v, indent+1, k.capitalize()))
                        lines.append(f"{ind}  {k.capitalize()} {k} = {idx};")
                    else:
                        lines.append(f"{ind}  {field_type} {k} = {idx};")
                    idx += 1
                lines.append(f"{ind}}}")
            elif isinstance(obj, list):
                # 只取第一个元素推断类型
                if obj:
                    lines.append(to_proto(obj[0], indent, name))
            return "\n".join(lines)
        return to_proto(obj)

    def protobuf_to_obj(self, pb_str):
        # 仅支持简单的message结构的反序列化
        # 这里只能做极简的解析，实际应使用protobuf库
        import re
        result = {}
        stack = []
        current = result
        section = None
        for line in pb_str.splitlines():
            line = line.strip()
            if line.startswith("message "):
                section = re.findall(r"message (\w+)", line)
                if section:
                    stack.append((current, section[0]))
                    current = {}
            elif line == "}":
                if stack:
                    parent, name = stack.pop()
                    parent[name] = current
                    current = parent
            elif "=" in line:
                parts = line.split()
                if len(parts) >= 3:
                    key = parts[1]
                    value = ""
                    current[key] = value
        return result

    def obj_to_graphql(self, obj):
        # 简单实现：将json对象转为GraphQL查询
        def to_gql(obj, indent=0):
            ind = "  " * indent
            if isinstance(obj, dict):
                fields = []
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        fields.append(f"{ind}{k} {{\n{to_gql(v, indent+1)}\n{ind}}}")
                    else:
                        fields.append(f"{ind}{k}")
                return "\n".join(fields)
            elif isinstance(obj, list):
                if obj:
                    return to_gql(obj[0], indent)
                else:
                    return ""
            else:
                return ""
        return f"{{\n{to_gql(obj, 1)}\n}}"

    def graphql_to_obj(self, gql_str):
        # 仅支持简单的GraphQL查询结构转为dict
        # 这里只能做极简的解析
        import re
        stack = []
        result = {}
        current = result
        key = None
        for line in gql_str.splitlines():
            line = line.strip()
            if line.endswith("{"):
                key = line[:-1].strip()
                if key:
                    new_dict = {}
                    current[key] = new_dict
                    stack.append(current)
                    current = new_dict
            elif line == "}":
                if stack:
                    current = stack.pop()
            elif line:
                current[line] = ""
        return result

    def obj_to_html(self, obj):
        # 简单实现：将json对象转为html表格
        def dict_to_table(d):
            html = "<table border='1'>"
            for k, v in d.items():
                html += "<tr><th>{}</th><td>{}</td></tr>".format(k, dict_to_table(v) if isinstance(v, dict) else v)
            html += "</table>"
            return html
        def list_to_table(lst):
            html = "<table border='1'><tr>"
            if lst and isinstance(lst[0], dict):
                for k in lst[0].keys():
                    html += f"<th>{k}</th>"
                html += "</tr>"
                for row in lst:
                    html += "<tr>"
                    for v in row.values():
                        html += f"<td>{v}</td>"
                    html += "</tr>"
            else:
                for v in lst:
                    html += f"<tr><td>{v}</td></tr>"
            html += "</table>"
            return html
        if isinstance(obj, dict):
            return dict_to_table(obj)
        elif isinstance(obj, list):
            return list_to_table(obj)
        else:
            return f"<pre>{obj}</pre>"

    def html_to_obj(self, html_str):
        # 仅支持简单的table转为list[dict]
        from html.parser import HTMLParser

        class TableParser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.in_td = False
                self.in_th = False
                self.headers = []
                self.row = []
                self.rows = []
                self.current_data = ""
            def handle_starttag(self, tag, attrs):
                if tag == "td":
                    self.in_td = True
                    self.current_data = ""
                elif tag == "th":
                    self.in_th = True
                    self.current_data = ""
            def handle_endtag(self, tag):
                if tag == "td":
                    self.in_td = False
                    self.row.append(self.current_data.strip())
                elif tag == "th":
                    self.in_th = False
                    self.headers.append(self.current_data.strip())
                elif tag == "tr":
                    if self.row:
                        self.rows.append(self.row)
                        self.row = []
            def handle_data(self, data):
                if self.in_td or self.in_th:
                    self.current_data += data
        parser = TableParser()
        parser.feed(html_str)
        if parser.headers and parser.rows:
            return [dict(zip(parser.headers, row)) for row in parser.rows]
        elif parser.rows:
            return parser.rows
        else:
            return {}

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = JsonConverter()
    win.show()
    sys.exit(app.exec())


