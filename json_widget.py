import sys
import json
import os
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QTextEdit, QPushButton, QFileDialog,
                               QScrollArea, QLabel, QSplitter, QFrame, QPlainTextEdit,
                               QSpinBox, QTabWidget, QTreeWidget, QTreeWidgetItem,
                               QMenu, QHeaderView, QMessageBox)
from PySide6.QtCore import Qt, QThread, QTimer, Signal, QRegularExpression
from PySide6.QtGui import QFont, QColor, QTextCharFormat, QSyntaxHighlighter, QBrush, QAction

class JsonHighlighterCode(QSyntaxHighlighter):
    """JSON语法高亮器"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.json_format()

    def json_format(self):
        # 定义不同JSON元素的格式
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor(163, 21, 21))

        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor(28, 0, 207))

        self.boolean_format = QTextCharFormat()
        self.boolean_format.setForeground(QColor(128, 0, 128))

        self.null_format = QTextCharFormat()
        self.null_format.setForeground(QColor(0, 128, 0))

        self.key_format = QTextCharFormat()
        self.key_format.setForeground(QColor(160, 32, 240))

        self.operator_format = QTextCharFormat()
        self.operator_format.setForeground(QColor(0, 0, 0))
        self.operator_format.setFontWeight(QFont.Bold)

    def highlightBlock(self, text):
        # 正则表达式模式
        string_pattern = r'"(?:[^"\\]|\\.)*"'
        number_pattern = r'\b\d+(?:\.\d+)?\b'
        boolean_pattern = r'\b(true|false)\b'
        null_pattern = r'\bnull\b'
        key_pattern = r'"([^"\\]|\\.)*":'
        operator_pattern = r'[:,\[\]{}]'

        # 应用格式
        import re
        for pattern, format in [(string_pattern, self.string_format),
                                (number_pattern, self.number_format),
                                (boolean_pattern, self.boolean_format),
                                (null_pattern, self.null_format),
                                (key_pattern, self.key_format),
                                (operator_pattern, self.operator_format)]:
            for match in re.finditer(pattern, text):
                start, end = match.span()
                self.setFormat(start, end - start, format)


class JsonLoaderThread(QThread):
    """加载JSON文件的工作线程，防止UI卡顿"""
    finished = Signal(str)
    error = Signal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.finished.emit(content)
        except Exception as e:
            self.error.emit(str(e))

class JsonTreeWidget(QTreeWidget):
    """自定义树状控件，用于显示JSON数据"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(["Key", "Value"])
        self.setColumnWidth(0, 250)
        self.setAlternatingRowColors(True)
        self.setFont(QFont("Consolas", 10))
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def fill_tree(self, data):
        """填充树状结构"""
        self.clear()
        if isinstance(data, list):
            if len(data) > 0:
                # 处理JSON数组
                root = QTreeWidgetItem(self, ["Array", f"[{len(data)} items]"])
                root.setForeground(0, QColor(0, 0, 255))
                for i, item in enumerate(data):
                    self._add_item(root, f"[{i}]", item)
                self.expandItem(root)
        elif isinstance(data, dict):
            # 处理JSON对象
            root = QTreeWidgetItem(self, ["Root", "object"])
            root.setForeground(0, QColor(0, 0, 255))
            for key, value in data.items():
                self._add_item(root, key, value)
            self.expandItem(root)
        else:
            # 处理单个值
            root = QTreeWidgetItem(self, ["Value", str(data)])
            self.expandItem(root)

    def _add_item(self, parent, key, value):
        """递归添加JSON项到树状结构"""
        if isinstance(value, dict):
            item = QTreeWidgetItem(parent, [key, "object"])
            item.setForeground(0, QColor(0, 0, 255))
            for k, v in value.items():
                self._add_item(item, k, v)
        elif isinstance(value, list):
            item = QTreeWidgetItem(parent, [key, f"[{len(value)} items]"])
            item.setForeground(0, QColor(0, 0, 255))
            for i, v in enumerate(value):
                self._add_item(item, f"[{i}]", v)
        else:
            # 基本类型值
            item = QTreeWidgetItem(parent, [key, str(value)])
            # 根据值类型设置不同颜色
            if isinstance(value, bool):
                item.setForeground(1, QColor(128, 0, 128))
            elif isinstance(value, (int, float)):
                item.setForeground(1, QColor(128, 0, 0))
            elif value is None:
                item.setForeground(1, QColor(0, 128, 0))

    def show_context_menu(self, position):
        """显示右键菜单"""
        item = self.itemAt(position)
        if item:
            menu = QMenu()
            copy_key_action = menu.addAction("复制键")
            copy_value_action = menu.addAction("复制值")
            copy_both_action = menu.addAction("复制键值")

            action = menu.exec_(self.viewport().mapToGlobal(position))

            if action == copy_key_action:
                clipboard = QApplication.clipboard()
                clipboard.setText(item.text(0))
            elif action == copy_value_action:
                clipboard = QApplication.clipboard()
                clipboard.setText(item.text(1))
            elif action == copy_both_action:
                clipboard = QApplication.clipboard()
                clipboard.setText(f"{item.text(0)}: {item.text(1)}")

class JsonParserThread(QThread):
    """解析JSON的工作线程，防止UI卡顿"""
    finished = Signal(object, bool)
    error = Signal(str)

    def __init__(self, json_text):
        super().__init__()
        self.json_text = json_text

    def run(self):
        try:
            # 调用与主类相同的解析方法
            parser = JsonProcessor()  # 创建临时实例仅用于调用解析方法
            data, is_multiple = parser._parse_json_content(self.json_text)
            self.finished.emit(data, is_multiple)
        except Exception as e:
            self.error.emit(str(e))


class JsonProcessor(QMainWindow):
    """JSON处理工具主窗口"""

    def __init__(self):
        super().__init__()
        self.initUI()
        self.json_data = None
        self.is_multiple_json = False
        self.parser_thread = None
        self.selected_paths = set()  # 存储选中的字段路径

    def initUI(self):
        # 设置窗口基本属性
        self.setWindowTitle('JSON处理工具')
        self.setGeometry(100, 100, 800, 600)

        # 创建主布局
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)

        # 顶部按钮布局
        top_layout = QHBoxLayout()
        top_layout.setAlignment(Qt.AlignCenter)

        # 使用QPlainTextEdit替代QTextEdit，处理大量文本更高效
        self.input_text = QPlainTextEdit()
        self.input_text.setPlaceholderText('请输入JSON数据或从文件加载...')
        self.input_text.setMinimumHeight(200)

        # 按钮
        self.open_file_btn = QPushButton('打开文件')
        self.open_file_btn.clicked.connect(self.open_file)

        self.format_btn = QPushButton('格式化JSON')
        self.format_btn.clicked.connect(self.format_json)

        self.parse_btn = QPushButton('解析JSON')
        self.parse_btn.clicked.connect(self.parse_json)

        self.minify_btn = QPushButton("压缩JSON")
        self.minify_btn.clicked.connect(self.minify_json)

        self.export_btn = QPushButton('导出JSON')
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_json)

        self.clear_btn = QPushButton('清空JSON')
        self.clear_btn.clicked.connect(self.clear_json)

        # 添加JSON个数显示
        self.json_count_label = QLabel("JSON个数: 0")
        top_layout.addWidget(self.json_count_label)

        # 添加按钮到顶部布局
        top_layout.addWidget(self.open_file_btn)
        top_layout.addWidget(self.parse_btn)
        top_layout.addWidget(self.format_btn)
        top_layout.addWidget(self.minify_btn)
        top_layout.addWidget(self.export_btn)
        top_layout.addWidget(self.clear_btn)

        # 添加JSON选择器
        json_selector_layout = QHBoxLayout()
        json_selector_layout.addWidget(QLabel("选择JSON对象:"))
        json_selector_layout.setAlignment(Qt.AlignCenter)

        self.json_index_spinbox = QSpinBox()
        self.json_index_spinbox.setRange(1, 1)
        self.json_index_spinbox.setValue(1)
        self.json_index_spinbox.setEnabled(False)
        self.json_index_spinbox.valueChanged.connect(self.on_json_index_changed)
        json_selector_layout.addWidget(self.json_index_spinbox)

        self.total_json_label = QLabel("共 0 个")
        json_selector_layout.addWidget(self.total_json_label)

        # 输入区域
        input_frame = QFrame()
        input_frame.setFrameShape(QFrame.StyledPanel)
        input_layout = QVBoxLayout(input_frame)
        input_layout.addLayout(top_layout)
        input_layout.addLayout(json_selector_layout)
        input_layout.addWidget(self.input_text)

        # 创建标签页控件
        self.tab_widget = QTabWidget()

        # 字段选择区域 - 第一个标签页
        fields_widget = QWidget()
        fields_layout = QVBoxLayout(fields_widget)

        # 使用QSplitter分隔字段选择区域和输出区域
        fields_splitter = QSplitter(Qt.Vertical)

        # 使用QTreeWidget替代QScrollArea和QCheckBox，支持多层级字段选择
        self.fields_tree = QTreeWidget()
        self.fields_tree.setHeaderLabel("JSON字段结构")
        self.fields_tree.setSelectionMode(QTreeWidget.SingleSelection)
        self.fields_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.fields_tree.customContextMenuRequested.connect(self.show_context_menu)
        self.fields_tree.itemChanged.connect(self.on_tree_item_changed)

        # 设置列宽适应内容
        self.fields_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents)

        # 使用QPlainTextEdit替代QTextEdit，处理大量文本更高效
        self.output_text = QPlainTextEdit()
        # self.output_text.setReadOnly(True)
        # self.output_text.setMinimumHeight(200)

        # 将字段选择区域和输出区域添加到分隔器
        fields_splitter.addWidget(self.fields_tree)
        fields_splitter.addWidget(self.output_text)

        # 设置初始大小比例 (2:3)
        fields_splitter.setSizes([200, 300])

        fields_layout.addWidget(fields_splitter)

        # 格式化输出区域 - 第二个标签页
        format_widget = QWidget()
        format_layout = QVBoxLayout(format_widget)

        # 使用QPlainTextEdit替代QTextBrowser
        self.formatted_text = QPlainTextEdit()
        self.formatted_text.setReadOnly(True)
        # self.formatted_text.setMinimumHeight(500)
        self.formatted_text.setPlaceholderText('格式化后的JSON将显示在这里...')

        # 添加按钮
        result_button_layout = QHBoxLayout()
        self.copy_button = QPushButton("复制结果")
        self.copy_button.clicked.connect(self.copy_result)
        self.save_button = QPushButton("保存结果")
        self.save_button.clicked.connect(self.save_result)

        result_button_layout.addWidget(self.copy_button)
        result_button_layout.addWidget(self.save_button)

        # 创建JSON语法高亮器
        self.json_highlighter = JsonHighlighterCode(self.formatted_text.document())
        self.json_highlighter2 = JsonHighlighterCode(self.output_text.document())

        format_layout.addWidget(self.formatted_text)
        format_layout.addLayout(result_button_layout)

        # 树状显示区域 第三个区域
        self.tree_tab = QWidget()
        tree_layout = QVBoxLayout(self.tree_tab)
        self.json_tree = JsonTreeWidget()
        tree_layout.addWidget(self.json_tree)

        # 将两个标签页添加到标签页控件
        self.tab_widget.addTab(fields_widget, "字段选择")
        self.tab_widget.addTab(self.tree_tab,"树状输出")
        self.tab_widget.addTab(format_widget, "格式化输出")

        # 分隔器
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(input_frame)
        splitter.addWidget(self.tab_widget)

        # 设置分隔器初始大小
        splitter.setSizes([300, 500])

        # 添加到主布局
        main_layout.addWidget(splitter)

        # 设置中心部件
        self.setCentralWidget(main_widget)

        # 状态栏
        self.statusBar().showMessage('就绪')

        # 字体设置
        font = QFont()
        font.setFamily('Consolas')
        font.setFixedPitch(True)
        font.setPointSize(10)
        self.input_text.setFont(font)
        self.output_text.setFont(font)
        self.formatted_text.setFont(font)

        # 设置格式化输出的背景色和样式
        # self.formatted_text.setStyleSheet("""
        #     QPlainTextEdit {
        #         background-color: #282c34;
        #         color: #abb2bf;
        #         border: 1px solid #444;
        #         border-radius: 4px;
        #         padding: 5px;
        #     }
        # """)

        # 创建右键菜单
        self.create_context_menu()

    def create_context_menu(self):
        """创建右键菜单"""
        self.context_menu = QMenu(self)

        self.select_all_action = QAction("全选", self)
        self.select_all_action.triggered.connect(self.select_all_fields)

        self.deselect_all_action = QAction("取消全选", self)
        self.deselect_all_action.triggered.connect(self.deselect_all_fields)

        self.expand_all_action = QAction("展开所有", self)
        self.expand_all_action.triggered.connect(self.expand_all_fields)

        self.collapse_all_action = QAction("折叠所有", self)
        self.collapse_all_action.triggered.connect(self.collapse_all_fields)

        self.context_menu.addAction(self.select_all_action)
        self.context_menu.addAction(self.deselect_all_action)
        self.context_menu.addSeparator()
        self.context_menu.addAction(self.expand_all_action)
        self.context_menu.addAction(self.collapse_all_action)

    def show_context_menu(self, position):
        """显示右键菜单"""
        self.context_menu.exec_(self.fields_tree.viewport().mapToGlobal(position))

    def minify_json(self):
        """压缩JSON数据"""
        current_json_data = self.formatted_text.toPlainText()
        print(current_json_data)
        if not current_json_data:
            self.parse_json()
            return

        try:
            # 压缩JSON
            json_data = json.loads(current_json_data)
            minified_json = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
                        # print(data)
            # self.json_input.setText(minified_json)
            print(minified_json)
            self.formatted_text.setPlainText(f'{minified_json}')


            # 切换到格式化文本标签页
            self.tab_widget.setCurrentIndex(2)

            self.statusBar().showMessage("JSON压缩成功")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"压缩失败: {str(e)}")
            self.statusBar().showMessage("JSON压缩失败")

    def open_file(self):
        """打开JSON文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, '打开JSON文件', '', 'JSON Files (*.json);;All Files (*)'
        )

        if file_path:
            self.statusBar().showMessage(f'正在加载文件: {os.path.basename(file_path)}')
            self.json_data = None
            self.clear_fields()
            self.output_text.clear()
            self.formatted_text.clear()
            self.json_count_label.setText("JSON个数: 0")
            self.json_index_spinbox.setRange(1, 1)
            self.json_index_spinbox.setValue(1)
            self.json_index_spinbox.setEnabled(False)
            self.total_json_label.setText("共 0 个")
            self.selected_paths = set()

            # 使用线程加载大文件
            self.loader_thread = JsonLoaderThread(file_path)
            self.loader_thread.finished.connect(self.on_file_loaded)
            self.loader_thread.error.connect(self.on_file_error)
            self.loader_thread.start()

    def on_file_loaded(self, content):
        """文件加载完成回调"""
        self.input_text.setPlainText(content)
        self.statusBar().showMessage(f'文件加载完成')
        self.parse_btn.setEnabled(True)

    def on_file_error(self, error_msg):
        """文件加载错误回调"""
        self.statusBar().showMessage(f'文件加载错误: {error_msg}')

    def format_json(self):
        """格式化JSON数据并在格式化标签页显示"""
        json_text = self.input_text.toPlainText().strip()
        if not json_text:
            self.statusBar().showMessage('请输入JSON数据')
            return

        try:
            # 尝试解析为单个JSON对象
            parsed_data = json.loads(json_text)
            formatted_json = json.dumps(parsed_data, indent=2, ensure_ascii=False)
            self.formatted_text.setPlainText(formatted_json)
            self.statusBar().showMessage('JSON已格式化')

            # 处理树状输出
            # 在树状视图中显示
            self.json_tree.fill_tree(parsed_data)

            # 切换到格式化标签页
            self.tab_widget.setCurrentIndex(2)
            return
        except json.JSONDecodeError:
            QMessageBox.warning(self,"提示",f"格式化失败!")
            pass  # 继续尝试其他格式

        try:
            # 尝试解析为JSON数组
            parsed_data = json.loads(f"[{json_text}]")
            formatted_json = json.dumps(parsed_data, indent=2, ensure_ascii=False)
            # 移除最外层的括号，保持原始格式
            formatted_json = formatted_json[1:-1].strip()
            self.formatted_text.setPlainText(formatted_json)
            self.statusBar().showMessage('JSON数组已格式化')
            # 切换到格式化标签页
            self.tab_widget.setCurrentIndex(1)
            return
        except json.JSONDecodeError:
            QMessageBox.warning(self, "提示", f"格式化失败!")
            pass  # 继续尝试其他格式

        try:
            # 尝试解析为每行一个JSON对象
            lines = json_text.strip().split('\n')
            formatted_lines = []
            for line in lines:
                if line.strip():
                    obj = json.loads(line)
                    formatted_lines.append(json.dumps(obj, indent=2, ensure_ascii=False))

            if formatted_lines:
                formatted_json = '\n'.join(formatted_lines)
                self.formatted_text.setPlainText(formatted_json)
                self.statusBar().showMessage('多行JSON已格式化')
                # 切换到格式化标签页
                self.tab_widget.setCurrentIndex(2)
                return
        except json.JSONDecodeError:
            QMessageBox.warning(self, "提示", f"格式化失败!")
            pass  # 继续尝试其他格式

        try:
            # 尝试解析为用逗号分隔的多个JSON对象
            cleaned_content = json_text.strip()
            if cleaned_content.startswith('{') and cleaned_content.endswith('}'):
                # 可能是多个对象用逗号分隔
                potential_objects = cleaned_content.split('}{')
                if len(potential_objects) > 1:
                    # 重建对象列表
                    reconstructed = '[' + '},{'.join(potential_objects) + ']'
                    parsed_data = json.loads(reconstructed)
                    formatted_json = json.dumps(parsed_data, indent=2, ensure_ascii=False)
                    # 移除最外层的括号，保持原始格式
                    formatted_json = formatted_json[1:-1].strip()
                    self.formatted_text.setPlainText(formatted_json)
                    self.statusBar().showMessage('多个JSON对象已格式化')
                    # 切换到格式化标签页
                    self.tab_widget.setCurrentIndex(1)
                    return
        except json.JSONDecodeError:
            QMessageBox.warning(self, "提示", f"格式化失败!")
            pass  # 所有尝试都失败

        self.statusBar().showMessage('无法解析JSON格式')

    def parse_json(self):
        """解析JSON数据"""
        json_text = self.input_text.toPlainText().strip()
        if not json_text:
            self.statusBar().showMessage('请输入JSON数据')
            return

        # 禁用解析按钮防止重复点击
        self.parse_btn.setEnabled(False)
        self.statusBar().showMessage('正在解析JSON数据...')

        # 使用线程解析JSON
        self.parser_thread = JsonParserThread(json_text)
        self.parser_thread.finished.connect(self.on_json_parsed)
        self.parser_thread.error.connect(self.on_json_parse_error)
        self.parser_thread.start()

    def on_json_parsed(self, data, is_multiple):
        """JSON解析完成回调"""
        self.json_data = data
        self.is_multiple_json = is_multiple

        # 重新启用解析按钮
        self.parse_btn.setEnabled(True)

        try:
            # 清除现有字段选择
            self.clear_fields()

            # 获取样本数据（只使用第一个JSON对象）
            sample_data = self._get_sample_data()

            if sample_data is None:
                self.statusBar().showMessage('JSON格式不支持字段选择')
                self.output_text.setPlainText(json.dumps(self.json_data, indent=2, ensure_ascii=False))
                return

            # 生成字段树
            if isinstance(sample_data, dict):
                self.generate_field_tree(sample_data)
            else:
                self.statusBar().showMessage('JSON格式不支持字段选择')
                self.output_text.setPlainText(json.dumps(self.json_data, indent=2, ensure_ascii=False))
                return

            # 初始全选
            self.select_all_fields()

            # 更新输出
            self.update_output()

            # 启用导出按钮
            self.export_btn.setEnabled(True)

            # 更新JSON个数显示
            if self.is_multiple_json:
                count = len(self.json_data)
                self.json_count_label.setText(f"JSON个数: {count}")
                self.statusBar().showMessage(f'已解析 {count} 个JSON对象，使用第一个对象的字段')

                # 更新JSON选择器
                self.json_index_spinbox.setRange(1, count)
                self.json_index_spinbox.setValue(1)
                self.json_index_spinbox.setEnabled(True)
                self.total_json_label.setText(f"共 {count} 个")
            else:
                self.json_count_label.setText("JSON个数: 1")
                self.statusBar().showMessage('已解析单个JSON对象')

                # 更新JSON选择器
                self.json_index_spinbox.setRange(1, 1)
                self.json_index_spinbox.setValue(1)
                self.json_index_spinbox.setEnabled(False)
                self.total_json_label.setText("共 1 个")

            # 切换到字段选择标签页
            self.tab_widget.setCurrentIndex(0)

        except Exception as e:
            self.statusBar().showMessage(f'处理错误: {str(e)}')

    def on_json_parse_error(self, error_msg):
        """JSON解析错误回调"""
        self.parse_btn.setEnabled(True)
        self.statusBar().showMessage(f'解析错误: {error_msg}')

    def _parse_json_content(self, content):
        """解析JSON内容，支持多种格式"""
        try:
            # 尝试解析为单个JSON对象
            data = json.loads(content)
            return data, False
        except json.JSONDecodeError:
            try:
                # 尝试解析为JSON数组
                data = json.loads(f"[{content}]")
                return data, len(data) > 1
            except json.JSONDecodeError:
                try:
                    # 尝试解析为每行一个JSON对象
                    lines = content.strip().split('\n')
                    data = []
                    for line in lines:
                        if line.strip():
                            obj = json.loads(line)
                            data.append(obj)
                    return data, len(data) > 1
                except json.JSONDecodeError:
                    # 尝试解析为用逗号分隔的多个JSON对象
                    try:
                        # 尝试在每个对象周围添加方括号
                        cleaned_content = content.strip()
                        if cleaned_content.startswith('{') and cleaned_content.endswith('}'):
                            # 可能是多个对象用逗号分隔
                            potential_objects = cleaned_content.split('}{')
                            if len(potential_objects) > 1:
                                # 重建对象列表
                                reconstructed = '[' + '},{'.join(potential_objects) + ']'
                                data = json.loads(reconstructed)
                                return data, len(data) > 1
                    except json.JSONDecodeError:
                        # 如果所有解析方法都失败，抛出异常而不是返回None
                        raise json.JSONDecodeError("无法解析JSON格式", content, 0)

    def _get_sample_data(self):
        """获取用于生成字段选择器的样本数据（始终返回第一个JSON对象）"""
        if self.is_multiple_json:
            if isinstance(self.json_data, list) and len(self.json_data) > 0:
                # 处理多个JSON对象的情况，只返回第一个
                first_item = self.json_data[0]
                if isinstance(first_item, dict):
                    return first_item
                elif isinstance(first_item, list) and len(first_item) > 0 and isinstance(first_item[0], dict):
                    # 如果第一个项目是列表，使用列表的第一个元素
                    return first_item[0]
        else:
            # 处理单个JSON对象的情况
            if isinstance(self.json_data, dict):
                return self.json_data
            elif isinstance(self.json_data, list) and len(self.json_data) > 0 and isinstance(self.json_data[0], dict):
                # 如果是对象列表，使用第一个元素
                return self.json_data[0]
        return None

    def clear_fields(self):
        """清除字段选择区域"""
        self.fields_tree.clear()

    def clear_json(self):
        self.input_text.clear()
        self.formatted_text.clear()
        self.output_text.clear()
        self.fields_tree.clear()
        self.json_tree.clear()

    def copy_result(self):
        """复制结果到剪贴板"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.formatted_text.toPlainText())
        self.statusBar().showMessage("结果已复制到剪贴板")

    def save_result(self):
        """保存结果到文件"""
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "保存JSON文件", "", "JSON Files (*.json);;All Files (*)"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.formatted_text.toPlainText())
                self.statusBar().showMessage(f"文件已保存至: {file_path}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存文件失败: {str(e)}")

    def generate_field_tree(self, data, parent=None, path=""):
        """生成字段树，支持多层级"""
        if parent is None:
            # 根节点
            self.fields_tree.clear()
            for key, value in data.items():
                current_path = key if not path else f"{path}.{key}"
                item = QTreeWidgetItem([key])
                item.setCheckState(0, Qt.Checked)
                item.setData(0, Qt.UserRole, current_path)
                self.fields_tree.addTopLevelItem(item)

                # 递归添加子节点
                self._add_child_nodes(item, value, current_path)
        else:
            # 子节点
            for key, value in data.items():
                current_path = key if not path else f"{path}.{key}"
                item = QTreeWidgetItem([key])
                item.setCheckState(0, Qt.Checked)
                item.setData(0, Qt.UserRole, current_path)
                parent.addChild(item)

                # 递归添加子节点
                self._add_child_nodes(item, value, current_path)

    def _add_child_nodes(self, parent_item, value, path):
        """递归添加子节点"""
        if isinstance(value, dict):
            # 对象类型，继续展开
            for key, val in value.items():
                current_path = f"{path}.{key}"
                child_item = QTreeWidgetItem([key])
                child_item.setCheckState(0, Qt.Checked)
                child_item.setData(0, Qt.UserRole, current_path)
                parent_item.addChild(child_item)

                # 递归处理子节点
                self._add_child_nodes(child_item, val, current_path)
        elif isinstance(value, list):
            # 数组类型，检查第一个元素
            if len(value) > 0:
                first_item = value[0]
                if isinstance(first_item, dict):
                    # 如果数组包含对象，使用第一个对象的结构
                    for key, val in first_item.items():
                        current_path = f"{path}.[].{key}"
                        child_item = QTreeWidgetItem([f"{key} (数组元素)"])
                        child_item.setCheckState(0, Qt.Checked)
                        child_item.setData(0, Qt.UserRole, current_path)
                        parent_item.addChild(child_item)

                        # 递归处理子节点
                        self._add_child_nodes(child_item, val, current_path)
                else:
                    # 简单数组类型，添加一个通用节点
                    child_item = QTreeWidgetItem([f"[] (数组，元素类型: {type(first_item).__name__})"])
                    child_item.setCheckState(0, Qt.Checked)
                    child_item.setData(0, Qt.UserRole, f"{path}.[]")
                    parent_item.addChild(child_item)

    def on_tree_item_changed(self, item, column):
        """树节点状态变更回调"""
        path = item.data(0, Qt.UserRole)
        state = item.checkState(0)

        if state == Qt.Checked:
            self.selected_paths.add(path)
            # 选中父节点时，自动选中所有子节点
            self._set_children_state(item, Qt.Checked)
            # 确保所有父节点也被选中
            self._ensure_parent_selected(item)
        else:
            self.selected_paths.discard(path)
            # 取消选中父节点时，自动取消选中所有子节点
            self._set_children_state(item, Qt.Unchecked)

        # 更新输出
        self.update_output()

    def _set_children_state(self, item, state):
        """设置所有子节点的状态"""
        for i in range(item.childCount()):
            child = item.child(i)
            child.setCheckState(0, state)

            path = child.data(0, Qt.UserRole)
            if state == Qt.Checked:
                self.selected_paths.add(path)
            else:
                self.selected_paths.discard(path)

            # 递归处理子节点
            self._set_children_state(child, state)

    def _ensure_parent_selected(self, item):
        """确保所有父节点都被选中"""
        parent = item.parent()
        if parent:
            parent.setCheckState(0, Qt.Checked)
            path = parent.data(0, Qt.UserRole)
            self.selected_paths.add(path)
            # 递归处理父节点的父节点
            self._ensure_parent_selected(parent)

    def select_all_fields(self):
        """全选所有字段"""
        self._recursive_set_check_state(self.fields_tree.invisibleRootItem(), Qt.Checked)
        self.update_output()

    def deselect_all_fields(self):
        """取消全选所有字段"""
        self._recursive_set_check_state(self.fields_tree.invisibleRootItem(), Qt.Unchecked)
        self.update_output()

    def _recursive_set_check_state(self, item, state):
        """递归设置节点状态"""
        for i in range(item.childCount()):
            child = item.child(i)
            child.setCheckState(0, state)

            path = child.data(0, Qt.UserRole)
            if state == Qt.Checked:
                self.selected_paths.add(path)
            else:
                self.selected_paths.discard(path)

            # 递归处理子节点
            self._recursive_set_check_state(child, state)

    def expand_all_fields(self):
        """展开所有字段"""
        self.fields_tree.expandAll()

    def collapse_all_fields(self):
        """折叠所有字段"""
        self.fields_tree.collapseAll()

    def on_json_index_changed(self):
        """JSON选择变更回调"""
        self.update_output()

    def update_output(self):
        """更新输出文本"""
        if not self.selected_paths:
            self.output_text.setPlainText('请选择要显示的字段')
            return

        # 获取当前选择的JSON索引（从1开始）
        if self.is_multiple_json:
            index = self.json_index_spinbox.value() - 1  # 转换为0-based索引
            current_item = self.json_data[index]
        else:
            current_item = self.json_data

        # 过滤字段
        filtered_data = self._filter_data_by_paths(current_item, self.selected_paths)
        output_json = json.dumps(filtered_data, indent=2, ensure_ascii=False)

        self.output_text.setPlainText(output_json)

    def _filter_data_by_paths(self, data, paths):
        """根据选择的路径过滤数据"""
        if not isinstance(data, (dict, list)):
            return data

        result = {} if isinstance(data, dict) else []

        if isinstance(data, dict):
            for path in paths:
                # 分割路径
                parts = path.split('.')
                if not parts:
                    continue

                # 检查路径是否匹配当前层级
                if parts[0] not in data:
                    continue

                # 获取当前键的值
                value = data[parts[0]]

                if len(parts) == 1:
                    # 路径只有一级，直接添加
                    result[parts[0]] = value
                else:
                    # 路径有多级，递归处理
                    sub_path = '.'.join(parts[1:])

                    if sub_path.startswith('[]'):
                        # 处理数组
                        if isinstance(value, list) and len(value) > 0:
                            if isinstance(value[0], dict):
                                # 数组元素是对象
                                sub_result = []
                                for item in value:
                                    sub_item = self._filter_data_by_paths(item, {sub_path[2:]})
                                    if sub_item:
                                        sub_result.append(sub_item)
                                if sub_result:
                                    result[parts[0]] = sub_result
                            else:
                                # 简单数组，直接添加
                                result[parts[0]] = value
                    else:
                        # 处理嵌套对象
                        if isinstance(value, dict):
                            sub_result = self._filter_data_by_paths(value, {sub_path})
                            if sub_result:
                                result[parts[0]] = sub_result
        else:
            # 处理数组
            for item in data:
                if isinstance(item, dict):
                    # 过滤数组中的每个对象
                    filtered_item = self._filter_data_by_paths(item, paths)
                    if filtered_item:
                        result.append(filtered_item)
                else:
                    # 简单数组，直接添加
                    result.append(item)

        return result

    def export_json(self):
        """导出JSON数据"""
        if not self.json_data:
            self.statusBar().showMessage('没有可导出的JSON数据')
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, '保存JSON文件', '', 'JSON Files (*.json);;All Files (*)'
        )

        if file_path:
            try:
                # 导出所有JSON对象，使用选中的字段
                output_data = []

                if self.is_multiple_json:
                    for item in self.json_data:
                        filtered_item = self._filter_data_by_paths(item, self.selected_paths)
                        output_data.append(filtered_item)
                else:
                    if isinstance(self.json_data, dict):
                        filtered_data = self._filter_data_by_paths(self.json_data, self.selected_paths)
                        output_data.append(filtered_data)
                    elif isinstance(self.json_data, list):
                        for item in self.json_data:
                            filtered_item = self._filter_data_by_paths(item, self.selected_paths)
                            output_data.append(filtered_item)
                    else:
                        output_data.append({'value': self.json_data})

                output_json = json.dumps(output_data, indent=2, ensure_ascii=False)

                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(output_json)

                self.statusBar().showMessage(f'JSON已导出到: {os.path.basename(file_path)}')
            except Exception as e:
                self.statusBar().showMessage(f'导出错误: {str(e)}')


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = JsonProcessor()
    window.show()
    sys.exit(app.exec())