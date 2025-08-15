import sys
import base64
import re
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                             QHBoxLayout, QTextEdit, QPushButton, QLabel, QFileDialog,
                             QComboBox, QMessageBox, QGroupBox, QSplitter, QTableWidget,
                             QTableWidgetItem, QCheckBox, QMenu)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QAction, QIcon
from PySide6.QtWidgets import QLineEdit

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidKey, InvalidSignature


class RSAtool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

        # 存储密钥
        self.private_key = None
        self.public_key = None

    def init_ui(self):
        # 设置窗口基本属性
        self.setWindowTitle("RSA加解密工具")
        self.setGeometry(100, 100, 1200, 700)

        # 创建中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页
        self.tabs = QTabWidget()
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()
        self.key_tab = QWidget()
        self.parse_tab = QWidget()

        self.tabs.addTab(self.encrypt_tab, "RSA加密")
        self.tabs.addTab(self.decrypt_tab, "RSA解密")
        self.tabs.addTab(self.key_tab, "密钥管理")
        self.tabs.addTab(self.parse_tab, "密钥解析")

        # 初始化各个标签页
        self.init_encrypt_tab()
        self.init_decrypt_tab()
        self.init_key_tab()
        self.init_parse_tab()

        # 添加标签页到主布局
        main_layout.addWidget(self.tabs)

        # 设置字体
        # font = QFont("YaHei", 10)
        # self.setFont(font)

    def init_encrypt_tab(self):
        main_layout = QVBoxLayout(self.encrypt_tab)

        input_group = QGroupBox("明文")
        input_layout = QVBoxLayout(input_group)
        self.plaintext_edit = QTextEdit()
        self.plaintext_edit.setPlaceholderText("请输入要加密的文本...")
        input_layout.addWidget(self.plaintext_edit)

        pubkey_group = QGroupBox("公钥")
        pubkey_layout = QVBoxLayout(pubkey_group)
        self.pubkey_edit = QTextEdit()
        self.pubkey_edit.setPlaceholderText("请输入RSA公钥（支持PEM格式或纯Base64格式）...")
        pubkey_layout.addWidget(self.pubkey_edit)

        # 公钥格式提示
        # format_hint = QLabel('<font size="2" color="gray">支持格式：带-----BEGIN/END标记的PEM格式或纯Base64编码</font>')
        # pubkey_layout.addWidget(format_hint)

        btn_layout = QHBoxLayout()
        self.load_pubkey_btn = QPushButton("📁 加载公钥")
        self.load_pubkey_btn.clicked.connect(self.load_public_key)

        self.format_combo_encrypt = QComboBox()
        self.format_combo_encrypt.addItems(["Base64", "Hex"])
        self.format_combo_encrypt.setCurrentIndex(0)

        self.encrypt_btn = QPushButton("🔒 加密")
        self.encrypt_btn.clicked.connect(self.encrypt_text)

        btn_layout.addWidget(self.load_pubkey_btn)
        btn_layout.addWidget(QLabel("输出格式:"))
        btn_layout.addWidget(self.format_combo_encrypt)
        btn_layout.addWidget(self.encrypt_btn)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        output_group = QGroupBox("加密结果")
        output_layout = QVBoxLayout(output_group)
        self.ciphertext_edit = QTextEdit()
        # self.ciphertext_edit.setReadOnly(True)
        output_layout.addWidget(self.ciphertext_edit)

        bottom_btn_layout = QHBoxLayout()
        self.copy_encrypt_btn = QPushButton("📋 复制结果")
        self.copy_encrypt_btn.clicked.connect(lambda: self.copy_to_clipboard(self.ciphertext_edit))

        self.clear_encrypt_btn = QPushButton("🗑️ 清空")
        self.clear_encrypt_btn.clicked.connect(self.clear_encrypt_fields)

        bottom_btn_layout.addWidget(self.copy_encrypt_btn)
        bottom_btn_layout.addWidget(self.clear_encrypt_btn)
        bottom_btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(input_group)
        splitter.addWidget(pubkey_group)
        splitter.addWidget(output_group)
        splitter.setSizes([200, 200, 200])

        main_layout.addWidget(splitter)
        main_layout.addLayout(btn_layout)
        main_layout.addLayout(bottom_btn_layout)

    def init_decrypt_tab(self):
        main_layout = QVBoxLayout(self.decrypt_tab)

        input_group = QGroupBox("密文")
        input_layout = QVBoxLayout(input_group)
        self.ciphertext_decrypt_edit = QTextEdit()
        self.ciphertext_decrypt_edit.setPlaceholderText("请输入要解密的文本...")
        input_layout.addWidget(self.ciphertext_decrypt_edit)

        privkey_group = QGroupBox("私钥")
        privkey_layout = QVBoxLayout(privkey_group)
        self.privkey_edit = QTextEdit()
        self.privkey_edit.setPlaceholderText("请输入RSA私钥（支持PEM格式或纯Base64格式）...")
        privkey_layout.addWidget(self.privkey_edit)

        # 私钥格式提示
        # format_hint = QLabel('<font size="2" color="gray">支持格式：带-----BEGIN/END标记的PEM格式或纯Base64编码</font>')
        # privkey_layout.addWidget(format_hint)

        # 私钥密码输入框
        self.privkey_password_label = QLabel("私钥密码 (如加密):")
        self.privkey_password_edit = QTextEdit()
        self.privkey_password_edit.setPlaceholderText("如果私钥被加密，请输入密码")
        # self.privkey_password_edit.setMaximumHeight(60)
        privkey_layout.addWidget(self.privkey_password_label)
        privkey_layout.addWidget(self.privkey_password_edit)

        btn_layout = QHBoxLayout()
        self.load_privkey_btn = QPushButton("📁 加载私钥")
        self.load_privkey_btn.clicked.connect(self.load_private_key)

        self.format_combo_decrypt = QComboBox()
        self.format_combo_decrypt.addItems(["Base64", "Hex"])
        self.format_combo_decrypt.setCurrentIndex(0)

        self.decrypt_btn = QPushButton("🔓 解密")
        self.decrypt_btn.clicked.connect(self.decrypt_text)

        btn_layout.addWidget(self.load_privkey_btn)
        btn_layout.addWidget(QLabel("输入格式:"))
        btn_layout.addWidget(self.format_combo_decrypt)
        btn_layout.addWidget(self.decrypt_btn)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        output_group = QGroupBox("解密结果")
        output_layout = QVBoxLayout(output_group)
        self.plaintext_decrypt_edit = QTextEdit()
        # self.plaintext_decrypt_edit.setReadOnly(True)
        output_layout.addWidget(self.plaintext_decrypt_edit)

        bottom_btn_layout = QHBoxLayout()
        self.copy_decrypt_btn = QPushButton("📋 复制结果")
        self.copy_decrypt_btn.clicked.connect(lambda: self.copy_to_clipboard(self.plaintext_decrypt_edit))

        self.clear_decrypt_btn = QPushButton("🗑️ 清空")
        self.clear_decrypt_btn.clicked.connect(self.clear_decrypt_fields)

        bottom_btn_layout.addWidget(self.copy_decrypt_btn)
        bottom_btn_layout.addWidget(self.clear_decrypt_btn)
        bottom_btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(input_group)
        splitter.addWidget(privkey_group)
        splitter.addWidget(output_group)
        splitter.setSizes([200, 250, 200])

        main_layout.addWidget(splitter)
        main_layout.addLayout(btn_layout)
        main_layout.addLayout(bottom_btn_layout)

    def init_key_tab(self):
        main_layout = QVBoxLayout(self.key_tab)

        key_size_layout = QHBoxLayout()
        key_size_layout.addWidget(QLabel("密钥长度:"))

        self.key_size_combo = QComboBox()
        self.key_size_combo.addItems(["1024", "2048", "4096"])
        self.key_size_combo.setCurrentIndex(1)

        # 加密私钥选项
        self.encrypt_key_checkbox = QCheckBox("加密私钥")
        self.encrypt_key_checkbox.stateChanged.connect(self.toggle_key_password)

        self.key_password_label = QLabel("私钥密码:")
        self.key_password_edit = QLineEdit()
        self.key_password_edit.setPlaceholderText("设置私钥密码")
        # self.key_password_edit.setMaximumHeight(60)
        self.key_password_edit.setEnabled(False)

        key_size_layout.addWidget(self.key_size_combo)
        key_size_layout.addWidget(self.encrypt_key_checkbox)
        key_size_layout.addWidget(self.key_password_label)
        key_size_layout.addWidget(self.key_password_edit)
        key_size_layout.addStretch()

        self.generate_btn = QPushButton("生成RSA密钥对")
        self.generate_btn.clicked.connect(self.generate_key_pair)

        privkey_group = QGroupBox("私钥 (PEM格式)")
        privkey_layout = QVBoxLayout(privkey_group)
        self.gen_privkey_edit = QTextEdit()
        # self.gen_privkey_edit.setReadOnly(True)
        privkey_layout.addWidget(self.gen_privkey_edit)

        pubkey_group = QGroupBox("公钥 (PEM格式)")
        pubkey_layout = QVBoxLayout(pubkey_group)
        self.gen_pubkey_edit = QTextEdit()
        # self.gen_pubkey_edit.setReadOnly(True)
        pubkey_layout.addWidget(self.gen_pubkey_edit)

        btn_layout = QHBoxLayout()
        self.save_privkey_btn = QPushButton("💾 保存私钥")
        self.save_privkey_btn.clicked.connect(lambda: self.save_key(self.gen_privkey_edit, "私钥", "*.pem"))

        self.save_pubkey_btn = QPushButton("💾 保存公钥")
        self.save_pubkey_btn.clicked.connect(lambda: self.save_key(self.gen_pubkey_edit, "公钥", "*.pem"))

        self.copy_privkey_btn = QPushButton("📋 复制私钥")
        self.copy_privkey_btn.clicked.connect(lambda: self.copy_to_clipboard(self.gen_privkey_edit))

        self.copy_pubkey_btn = QPushButton("📋 复制公钥")
        self.copy_pubkey_btn.clicked.connect(lambda: self.copy_to_clipboard(self.gen_pubkey_edit))

        # 新增纯Base64格式复制按钮
        self.copy_privkey_b64_btn = QPushButton("📋 复制私钥(Base64)")
        self.copy_privkey_b64_btn.clicked.connect(self.copy_private_key_b64)

        self.copy_pubkey_b64_btn = QPushButton("📋 复制公钥(Base64)")
        self.copy_pubkey_b64_btn.clicked.connect(self.copy_public_key_b64)

        btn_layout.addWidget(self.save_privkey_btn)
        btn_layout.addWidget(self.save_pubkey_btn)
        btn_layout.addWidget(self.copy_privkey_btn)
        btn_layout.addWidget(self.copy_pubkey_btn)
        btn_layout.addWidget(self.copy_privkey_b64_btn)
        btn_layout.addWidget(self.copy_pubkey_b64_btn)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(privkey_group)
        splitter.addWidget(pubkey_group)
        splitter.setSizes([300, 300])

        main_layout.addLayout(key_size_layout)
        main_layout.addWidget(self.generate_btn)
        main_layout.addWidget(splitter)
        main_layout.addLayout(btn_layout)

    def init_parse_tab(self):
        main_layout = QVBoxLayout(self.parse_tab)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)

        key_type_layout = QHBoxLayout()
        key_type_layout.addWidget(QLabel("密钥类型:"))

        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["自动识别", "公钥", "私钥"])
        self.key_type_combo.setCurrentIndex(0)

        key_type_layout.addWidget(self.key_type_combo)
        key_type_layout.addStretch()

        key_input_group = QGroupBox("密钥内容")
        key_input_layout = QVBoxLayout(key_input_group)
        self.key_to_parse_edit = QTextEdit()
        self.key_to_parse_edit.setPlaceholderText("请输入RSA密钥（支持PEM格式或纯Base64格式）...")
        key_input_layout.addWidget(self.key_to_parse_edit)

        # 密钥格式提示
        # format_hint = QLabel('<font size="2" color="gray">支持格式：带-----BEGIN/END标记的PEM格式或纯Base64编码</font>')
        # key_input_layout.addWidget(format_hint)

        # 密钥密码输入框
        self.parse_password_label = QLabel("密钥密码 (如加密):")
        self.parse_password_edit = QLineEdit()
        self.parse_password_edit.setPlaceholderText("如果密钥被加密，请输入密码")
        self.parse_password_edit.setMaximumHeight(60)
        key_input_layout.addWidget(self.parse_password_label)
        key_input_layout.addWidget(self.parse_password_edit)

        btn_layout = QHBoxLayout()
        self.load_key_to_parse_btn = QPushButton("📁 加载密钥文件")
        self.load_key_to_parse_btn.clicked.connect(self.load_key_to_parse)

        self.parse_key_btn = QPushButton("🔍 解析密钥")
        self.parse_key_btn.clicked.connect(self.parse_key)

        self.clear_parse_btn = QPushButton("🗑️ 清空")
        self.clear_parse_btn.clicked.connect(self.clear_parse_fields)

        btn_layout.addWidget(self.load_key_to_parse_btn)
        btn_layout.addWidget(self.parse_key_btn)
        btn_layout.addWidget(self.clear_parse_btn)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        left_layout.addLayout(key_type_layout)
        left_layout.addWidget(key_input_group)
        left_layout.addLayout(btn_layout)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        result_group = QGroupBox("解析结果")
        result_layout = QVBoxLayout(result_group)

        # 表格操作按钮
        table_btn_layout = QHBoxLayout()
        self.select_all_table_btn = QPushButton("全选")
        self.select_all_table_btn.clicked.connect(self.select_all_table_items)

        self.copy_selected_btn = QPushButton("复制选中")
        self.copy_selected_btn.clicked.connect(self.copy_selected_table_items)

        self.copy_all_btn = QPushButton("复制全部")
        self.copy_all_btn.clicked.connect(self.copy_all_table_items)

        table_btn_layout.addWidget(self.select_all_table_btn)
        table_btn_layout.addWidget(self.copy_selected_btn)
        table_btn_layout.addWidget(self.copy_all_btn)
        table_btn_layout.addStretch()

        # 创建表格并设置右键菜单
        self.parse_result_table = QTableWidget()
        self.parse_result_table.setColumnCount(2)
        self.parse_result_table.setHorizontalHeaderLabels(["参数", "值"])
        self.parse_result_table.horizontalHeader().setStretchLastSection(True)
        self.parse_result_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.parse_result_table.customContextMenuRequested.connect(self.show_table_context_menu)

        # old code
        # self.parse_result_table = QTableWidget()
        # self.parse_result_table.setColumnCount(2)
        # self.parse_result_table.setHorizontalHeaderLabels(["参数", "值"])
        # self.parse_result_table.horizontalHeader().setStretchLastSection(True)

        result_layout.addLayout(table_btn_layout)

        result_layout.addWidget(self.parse_result_table)
        right_layout.addWidget(result_group)

        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([500, 700])

        main_layout.addWidget(splitter)

    def toggle_key_password(self, state):
        """切换私钥密码输入框的启用状态"""
        # print(f"state: {state}")
        # print(Qt.CheckState.Checked.value)
        self.key_password_edit.setEnabled(state == Qt.CheckState.Checked.value)

    def generate_key_pair(self):
        """生成RSA密钥对，支持加密私钥"""
        try:
            key_size = int(self.key_size_combo.currentText())

            # 生成私钥
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size
            )

            # 处理加密选项
            encryption_algorithm = serialization.NoEncryption()
            if self.encrypt_key_checkbox.isChecked():
                password = self.key_password_edit.text().strip()
                if not password:
                    QMessageBox.warning(self, "警告", "请输入私钥密码")
                    return
                encryption_algorithm = serialization.BestAvailableEncryption(password.encode())

            # 序列化私钥 (PEM格式)
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )

            # 生成公钥
            public_key = private_key.public_key()

            # 序列化公钥 (PEM格式)
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # 显示密钥
            self.gen_privkey_edit.setText(private_pem.decode())
            self.gen_pubkey_edit.setText(public_pem.decode())

            # 保存密钥供其他标签页使用
            self.private_key = private_key
            self.public_key = public_key

            msg = f"已生成{key_size}位RSA密钥对"
            if self.encrypt_key_checkbox.isChecked():
                msg += "（私钥已加密）"
            # QMessageBox.information(self, "成功", msg)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成密钥对失败: {str(e)}")

    def extract_key_data(self, key_text):
        """从输入文本中提取密钥数据，支持PEM格式和纯Base64格式"""
        # 去除所有空白字符
        key_text = re.sub(r'\s+', '', key_text)

        # 检查是否是PEM格式（包含BEGIN/END标记）
        pem_pattern = re.compile(r'-----BEGIN(.*?)-----([A-Za-z0-9+/=]+)-----END(.*?)-----')
        match = pem_pattern.search(key_text)

        if match:
            # 提取PEM中的Base64数据
            return match.group(2).encode()
        else:
            # 假设是纯Base64格式
            return key_text.encode()

    def load_public_key(self):
        """加载公钥文件，支持多种格式"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择公钥文件", "", "PEM文件 (*.pem *.pub);;所有文件 (*)")

        if file_path:
            try:
                with open(file_path, "rb") as f:
                    key_data = f.read()

                self._load_public_key_from_data(key_data)

            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载公钥失败: {str(e)}")

    def _load_public_key_from_data(self, key_data):
        """从密钥数据加载公钥，支持多种格式"""
        try:
            # 尝试PEM格式
            public_key = serialization.load_pem_public_key(key_data)
            format_type = "PEM"
        except:
            try:
                # 尝试DER格式
                public_key = serialization.load_der_public_key(key_data)
                format_type = "DER"
            except:
                try:
                    # 尝试Base64解码后再解析
                    decoded_data = base64.b64decode(key_data)
                    public_key = serialization.load_der_public_key(decoded_data)
                    format_type = "Base64 (DER编码)"
                except Exception as e:
                    raise Exception(f"解析公钥失败: {str(e)}")

        # 显示公钥（PEM格式）
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.pubkey_edit.setText(public_pem.decode())
        self.public_key = public_key

        QMessageBox.information(self, "成功", f"公钥加载成功（{format_type}格式）")

    def load_private_key(self):
        """加载私钥文件，支持多种格式"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择私钥文件", "", "PEM文件 (*.pem);;所有文件 (*)")

        if file_path:
            try:
                with open(file_path, "rb") as f:
                    key_data = f.read()

                # 获取密码（如果有）
                password = self.privkey_password_edit.toPlainText().strip()
                password_bytes = password.encode() if password else None

                self._load_private_key_from_data(key_data, password_bytes)

            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载私钥失败: {str(e)}")

    def _load_private_key_from_data(self, key_data, password=None):
        """从密钥数据加载私钥，支持多种格式"""
        try:
            # 尝试PEM格式
            private_key = serialization.load_pem_private_key(
                key_data,
                password=password
            )
            format_type = "PEM"
        except:
            try:
                # 尝试DER格式
                private_key = serialization.load_der_private_key(
                    key_data,
                    password=password
                )
                format_type = "DER"
            except:
                try:
                    # 尝试Base64解码后再解析
                    decoded_data = base64.b64decode(key_data)
                    private_key = serialization.load_der_private_key(
                        decoded_data,
                        password=password
                    )
                    format_type = "Base64 (DER编码)"
                except Exception as e:
                    raise Exception(f"解析私钥失败: {str(e)}")

        # 显示私钥（PEM格式）
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.privkey_edit.setText(private_pem.decode())
        self.private_key = private_key

        QMessageBox.information(self, "成功", f"私钥加载成功（{format_type}格式）")

    def load_key_to_parse(self):
        """加载要解析的密钥文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", "", "PEM文件 (*.pem *.pub);;所有文件 (*)")

        if file_path:
            try:
                with open(file_path, "r") as f:
                    key_data = f.read()

                self.key_to_parse_edit.setText(key_data)

            except Exception as e:
                QMessageBox.critical(self, "错误", f"加载密钥失败: {str(e)}")

    def show_table_context_menu(self, position):
        """显示表格右键菜单"""
        menu = QMenu()

        # 复制当前单元格动作
        copy_cell_action = QAction("复制单元格内容", self)
        copy_cell_action.triggered.connect(self.copy_current_cell)

        # 复制选中内容动作
        copy_selected_action = QAction("复制选中内容", self)
        copy_selected_action.triggered.connect(self.copy_selected_table_items)

        # 全选动作
        select_all_action = QAction("全选", self)
        select_all_action.triggered.connect(self.select_all_table_items)

        menu.addAction(copy_cell_action)
        menu.addAction(copy_selected_action)
        menu.addAction(select_all_action)

        # 在鼠标位置显示菜单
        menu.exec_(self.parse_result_table.mapToGlobal(position))

    def copy_current_cell(self):
        """复制当前选中的单元格内容"""
        current_item = self.parse_result_table.currentItem()
        if current_item:
            text = current_item.text()
            clipboard = QApplication.clipboard()
            clipboard.setText(text)

    def select_all_table_items(self):
        """全选表格内容"""
        self.parse_result_table.selectAll()

    def copy_selected_table_items(self):
        """复制选中的表格内容"""
        selected_items = self.parse_result_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "提示", "请先选择要复制的内容")
            return

        # 按行组织选中的内容
        row_data = {}
        for item in selected_items:
            row = item.row()
            col = item.column()
            if row not in row_data:
                row_data[row] = ["", ""]
            row_data[row][col] = item.text()

        # 构建复制文本
        copy_text = ""
        for row in sorted(row_data.keys()):
            params = row_data[row]
            # 只添加有值的单元格
            if params[0] and params[1]:
                copy_text += f"{params[0]}: {params[1]}\n"
            elif params[0]:
                copy_text += f"{params[0]}\n"
            elif params[1]:
                copy_text += f"{params[1]}\n"

        if copy_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(copy_text)
            QMessageBox.information(self, "成功", "选中内容已复制到剪贴板")

    def copy_all_table_items(self):
        """复制表格所有内容"""
        row_count = self.parse_result_table.rowCount()
        if row_count == 0:
            QMessageBox.warning(self, "提示", "表格中没有内容可复制")
            return

        copy_text = ""
        for row in range(row_count):
            name_item = self.parse_result_table.item(row, 0)
            value_item = self.parse_result_table.item(row, 1)

            if name_item and value_item:
                copy_text += f"{name_item.text()}: {value_item.text()}\n"

        if copy_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(copy_text)
            QMessageBox.information(self, "成功", "表格所有内容已复制到剪贴板")

    def parse_key(self):
        """解析RSA密钥，支持多种格式"""
        key_text = self.key_to_parse_edit.toPlainText()
        if not key_text:
            QMessageBox.warning(self, "警告", "请输入要解析的密钥")
            return

        try:
            self.parse_result_table.setRowCount(0)

            key_type = self.key_type_combo.currentText()
            password = self.parse_password_edit.text().strip()
            password_bytes = password.encode() if password else None

            # 提取密钥数据（处理PEM和纯Base64格式）
            key_data = self.extract_key_data(key_text)
            parsed_key = None

            # 尝试解析密钥
            if key_type == "公钥" or key_type == "自动识别":
                try:
                    parsed_key = serialization.load_der_public_key(base64.b64decode(key_data))
                    self.add_parse_result("密钥类型", "公钥 (Base64编码)")
                except:
                    try:
                        parsed_key = serialization.load_pem_public_key(key_text.encode())
                        self.add_parse_result("密钥类型", "公钥 (PEM格式)")
                    except:
                        if key_type == "公钥":
                            raise Exception("无法解析为公钥，请检查密钥格式")

            if parsed_key is None and (key_type == "私钥" or key_type == "自动识别"):
                try:
                    parsed_key = serialization.load_der_private_key(
                        base64.b64decode(key_data),
                        password=password_bytes
                    )
                    self.add_parse_result("密钥类型", "私钥 (Base64编码)")
                except:
                    try:
                        parsed_key = serialization.load_pem_private_key(
                            key_text.encode(),
                            password=password_bytes
                        )
                        self.add_parse_result("密钥类型", "私钥 (PEM格式)")
                    except:
                        if key_type == "私钥":
                            raise Exception("无法解析为私钥，请检查密钥格式和密码")

            if parsed_key is None:
                raise Exception("无法识别的密钥格式，请确认是RSA密钥")

            # 提取公钥信息
            if hasattr(parsed_key, 'public_key'):
                public_key = parsed_key.public_key()
            else:
                public_key = parsed_key

            public_numbers = public_key.public_numbers()

            # 公钥参数
            self.add_parse_result("密钥长度 (bits)", public_numbers.n.bit_length())
            self.add_parse_result("公钥指数 (e)", public_numbers.e)
            self.add_parse_result("模数 (n)", f"{public_numbers.n}\n(十六进制: 0x{public_numbers.n:x})")

            # 如果是私钥，提取更多信息
            if hasattr(parsed_key, 'private_numbers'):
                private_numbers = parsed_key.private_numbers()

                # 私钥参数
                self.add_parse_result("私钥指数 (d)", private_numbers.d)
                self.add_parse_result("素数 p", private_numbers.p)
                self.add_parse_result("素数 q", private_numbers.q)
                self.add_parse_result("p的指数 (dmp1)", private_numbers.dmp1)
                self.add_parse_result("q的指数 (dmq1)", private_numbers.dmq1)
                self.add_parse_result("CRT系数 (iqmp)", private_numbers.iqmp)

                # 验证p和q的乘积是否等于n
                pq_product = private_numbers.p * private_numbers.q
                self.add_parse_result("p*q 验证", "成功" if pq_product == public_numbers.n else "失败")

            self.parse_result_table.resizeColumnsToContents()
            self.parse_result_table.horizontalHeader().setStretchLastSection(True)

        except Exception as e:
            QMessageBox.critical(self, "解析失败", f"解析密钥时出错: {str(e)}")

    def add_parse_result(self, name, value):
        """向解析结果表格添加一行数据"""
        row = self.parse_result_table.rowCount()
        self.parse_result_table.insertRow(row)

        name_item = QTableWidgetItem(str(name))
        name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        name_item.setBackground(Qt.lightGray)
        # name_item.setBackground(lightGray)
        self.parse_result_table.setItem(row, 0, name_item)

        value_item = QTableWidgetItem(str(value))
        value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        self.parse_result_table.setItem(row, 1, value_item)

    def save_key(self, text_edit, key_type, filter):
        """保存密钥到文件"""
        key_data = text_edit.toPlainText()
        if not key_data:
            QMessageBox.warning(self, "警告", f"没有可保存的{key_type}")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, f"保存{key_type}", "", filter)

        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(key_data)

                QMessageBox.information(self, "成功", f"{key_type}已保存到: {file_path}")

            except Exception as e:
                QMessageBox.critical(self, "错误", f"保存{key_type}失败: {str(e)}")

    def copy_to_clipboard(self, text_edit):
        """复制文本到剪贴板"""
        text = text_edit.toPlainText()
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            QMessageBox.information(self, "成功", "内容已复制到剪贴板")
        else:
            QMessageBox.warning(self, "警告", "没有可复制的内容")

    def copy_private_key_b64(self):
        """复制纯Base64格式的私钥"""
        privkey_pem = self.gen_privkey_edit.toPlainText()
        if not privkey_pem:
            QMessageBox.warning(self, "警告", "没有可复制的私钥")
            return

        # 提取Base64部分
        key_data = self.extract_key_data(privkey_pem)
        if key_data:
            clipboard = QApplication.clipboard()
            clipboard.setText(key_data.decode())
            QMessageBox.information(self, "成功", "纯Base64格式私钥已复制到剪贴板")

    def copy_public_key_b64(self):
        """复制纯Base64格式的公钥"""
        pubkey_pem = self.gen_pubkey_edit.toPlainText()
        if not pubkey_pem:
            QMessageBox.warning(self, "警告", "没有可复制的公钥")
            return

        # 提取Base64部分
        key_data = self.extract_key_data(pubkey_pem)
        if key_data:
            clipboard = QApplication.clipboard()
            clipboard.setText(key_data.decode())
            QMessageBox.information(self, "成功", "纯Base64格式公钥已复制到剪贴板")

    def clear_encrypt_fields(self):
        """清空加密标签页的字段"""
        self.plaintext_edit.clear()
        self.pubkey_edit.clear()
        self.ciphertext_edit.clear()

    def clear_decrypt_fields(self):
        """清空解密标签页的字段"""
        self.ciphertext_decrypt_edit.clear()
        self.privkey_edit.clear()
        self.privkey_password_edit.clear()
        self.plaintext_decrypt_edit.clear()

    def clear_parse_fields(self):
        """清空解析标签页的字段"""
        self.key_to_parse_edit.clear()
        self.parse_password_edit.clear()
        self.parse_result_table.setRowCount(0)

    def encrypt_text(self):
        """加密文本"""
        plaintext = self.plaintext_edit.toPlainText()
        pubkey_text = self.pubkey_edit.toPlainText()

        if not plaintext:
            QMessageBox.warning(self, "警告", "请输入要加密的文本")
            return

        if not pubkey_text:
            QMessageBox.warning(self, "警告", "请输入或加载公钥")
            return

        try:
            # 提取公钥数据（支持PEM和纯Base64格式）
            key_data = self.extract_key_data(pubkey_text)

            # 解析公钥
            if not self.public_key:
                try:
                    self.public_key = serialization.load_der_public_key(base64.b64decode(key_data))
                except:
                    self.public_key = serialization.load_pem_public_key(pubkey_text.encode())

            # 检查明文长度是否适合密钥大小
            max_length = (self.public_key.key_size // 8) - 42  # OAEP填充需要的空间
            if len(plaintext.encode('utf-8')) > max_length:
                raise Exception(f"明文过长，最大支持{max_length}字节（约{max_length // 3}个中文字符）")

            # 加密
            encrypted = self.public_key.encrypt(
                plaintext.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 根据选择的格式编码
            format_type = self.format_combo_encrypt.currentText()
            if format_type == "Base64":
                result = base64.b64encode(encrypted).decode('utf-8')
            else:  # Hex
                result = encrypted.hex()

            self.ciphertext_edit.setText(result)

        except Exception as e:
            QMessageBox.critical(self, "错误", f"加密失败: {str(e)}")
            self.public_key = None  # 重置公钥，下次尝试重新解析

    def decrypt_text(self):
        """解密文本"""
        ciphertext = self.ciphertext_decrypt_edit.toPlainText()
        privkey_text = self.privkey_edit.toPlainText()

        if not ciphertext:
            QMessageBox.warning(self, "警告", "请输入要解密的文本")
            return

        if not privkey_text:
            QMessageBox.warning(self, "警告", "请输入或加载私钥")
            return

        try:
            # 获取密码（如果有）
            password = self.privkey_password_edit.toPlainText().strip()
            password_bytes = password.encode() if password else None

            # 提取私钥数据（支持PEM和纯Base64格式）
            key_data = self.extract_key_data(privkey_text)

            # 解析私钥
            if not self.private_key:
                try:
                    self.private_key = serialization.load_der_private_key(
                        base64.b64decode(key_data),
                        password=password_bytes
                    )
                except:
                    self.private_key = serialization.load_pem_private_key(
                        privkey_text.encode(),
                        password=password_bytes
                    )

            # 根据选择的格式解码
            format_type = self.format_combo_decrypt.currentText()
            try:
                if format_type == "Base64":
                    encrypted = base64.b64decode(ciphertext)
                else:  # Hex
                    encrypted = bytes.fromhex(ciphertext)
            except Exception as e:
                raise Exception(f"解码失败，请检查输入格式: {str(e)}")

            # 解密 - 尝试多种填充方式
            try:
                decrypted = self.private_key.decrypt(
                    encrypted,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            except:
                decrypted = self.private_key.decrypt(
                    encrypted,
                    padding.PKCS1v15()
                )

            self.plaintext_decrypt_edit.setText(decrypted.decode('utf-8', errors='replace'))

        except Exception as e:
            QMessageBox.critical(self, "错误", f"解密失败: {str(e)}")
            self.private_key = None  # 重置私钥，下次尝试重新解析


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # font = QFont("SimHei")
    # app.setFont(font)

    window = RSAtool()
    window.show()
    sys.exit(app.exec_())
