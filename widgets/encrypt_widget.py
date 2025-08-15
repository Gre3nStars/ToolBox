
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QTextEdit, QPushButton, QLabel, QComboBox, QLineEdit, QMessageBox, QGroupBox
)

from utils.AES_utils import AESCipher
from utils.DES_utils import DESCipher
from utils.DES3_utils import TripleDESCipher
from utils.ToolsUtils import ToolUtils


class EncryptToolWindow(QMainWindow):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        # 窗口基础设置
        self.setWindowTitle("加密解密工具")
        self.resize(1000, 600)

        # 中心部件与主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. 顶部标签栏（编码分类）
        self.tab_widget = QTabWidget()
        # self.tab_widget.setStyleSheet("QTabBar::tab { padding: 5px 10px; }")
        # self.init_tabs()  # 初始化分类标签

        # 添加内部tab布局
        self.inner_tab_widget = QTabWidget()

        self.aes_tab = QWidget()  # 第一个 tab 标签按钮
        self.aes_tab.setObjectName("aes_tab")
        self.aes_tab.setWindowTitle("AES加解密")

        self.des_tab = QWidget()  # 第二个 tab 标签按钮
        self.des_tab = QWidget()

        self.des3_tab = QWidget()  # 第三个 tab 标签按钮
        self.des3_tab = QWidget()

        self.inner_tab_widget.addTab(self.aes_tab, "AES加解密")
        self.inner_tab_widget.addTab(self.des_tab, "DES加解密")
        self.inner_tab_widget.addTab(self.des3_tab, "3DES加解密")

        # 统一放置输入输出区域，防止报错。。


        # 设置status_bar
        # 添加一个状态栏(用QLbel，statusBar无法右侧显示Message)
        self.status_bar = QLabel()
        self.status_bar.setText("就绪。。")



        # 先布局？再加载？
        self.init_aes_encrypt_tab()
        self.init_des_encrypt_tab()
        self.init_des3_encrypt_tab()
        main_layout.addWidget(self.inner_tab_widget)
        # 添加状态栏
        statusbar_layout = QHBoxLayout()
        statusbar_layout.setAlignment(Qt.AlignRight)
        statusbar_layout.addWidget(self.status_bar)
        main_layout.addLayout(statusbar_layout)

    def init_aes_encrypt_tab(self):
        """初始化aes加解密"""
        layout = QVBoxLayout(self.aes_tab)
        # 输入区域

        aes_input_group =QGroupBox("输入区域")
        aes_input_layout = QVBoxLayout()
        self.aes_input_text = QTextEdit()
        self.aes_input_text.setPlaceholderText("请输入...")
        self.aes_input_text.setMinimumHeight(100)
        aes_input_layout.addWidget(self.aes_input_text)
        aes_input_group.setLayout(aes_input_layout)


        # 第一排操作选项
        button_layout = QHBoxLayout()
        button_layout.setSpacing(5)
        # button_layout.setAlignment(Qt.AlignCenter)
        self.aes_mode_combo = QComboBox()
        self.aes_mode_combo.addItems(["ECB","CBC", "CTR","CFB","OFB","GCM"])
        self.aes_mode_combo.setCurrentText("ECB")

        # 字符编码选择
        self.aes_padding_combo = QComboBox()
        self.aes_padding_combo.addItems([
            "PKCS7", "PKCS5", "NONE", "ZERO", "ISO10126"
        ])
        self.aes_padding_combo.setCurrentText("PKCS7")

        # 密码编码选择
        self.aes_pass_combo = QComboBox()
        self.aes_pass_combo.addItems([
            "UTF-8", "Base64", "Hex"
        ])
        self.aes_pass_combo.setCurrentText("UTF-8")

        aes_mode_label = QLabel("模式")
        aes_padding_label = QLabel("填充")
        aes_pass_label = QLabel("密钥key")
        self.aes_passwd_inputline = QLineEdit()
        self.aes_passwd_inputline.setFont(QFont('Arial', 10))

        # 第二排
        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(5)
        # button_layout2.setAlignment(Qt.AlignCenter)
        # 数据块大小
        self.aes_block_combo = QComboBox()
        self.aes_block_combo.addItems([
            "128", "192", "256"
        ])
        self.aes_block_combo.setCurrentText("128")

        # 输出字符编码选择
        self.aes_output_combo = QComboBox()
        self.aes_output_combo.addItems([
            "Base64", "Hex"
        ])
        self.aes_output_combo.setCurrentText("Base64")

        # 偏移量编码选择
        self.aes_iv_combo = QComboBox()
        self.aes_iv_combo.addItems([
            "UTF-8", "Base64", "Hex"
        ])
        self.aes_iv_combo.setCurrentText("UTF-8")

        aes_block_label = QLabel("数据块")
        aes_output_label = QLabel("输出")
        aes_iv_label = QLabel("偏移量iv")
        self.aes_iv_inputline = QLineEdit()
        # aes_iv_inputline.setStyleSheet("QLineEdit { padding: 5px; width: 120px;}")
        self.aes_iv_inputline.setFont(QFont('Arial', 10))


        # 添加到HBox容器
        button_layout.addWidget(aes_mode_label)
        button_layout.addWidget(self.aes_mode_combo)
        button_layout.addWidget(aes_padding_label)
        button_layout.addWidget(self.aes_padding_combo)
        button_layout.addWidget(aes_pass_label)
        button_layout.addWidget(self.aes_pass_combo)
        button_layout.addWidget(self.aes_passwd_inputline)


        button_layout2.addWidget(aes_block_label)
        button_layout2.addWidget(self.aes_block_combo)
        button_layout2.addWidget(aes_output_label)
        button_layout2.addWidget(self.aes_output_combo)
        button_layout2.addWidget(aes_iv_label)
        button_layout2.addWidget(self.aes_iv_combo)
        button_layout2.addWidget(self.aes_iv_inputline)


        # 第三排操作按钮
        button_layout3 = QHBoxLayout()
        button_layout3.setSpacing(5)
        button_layout3.setAlignment(Qt.AlignCenter)

        encrypt_btn = QPushButton("🔒 加密")
        decrypt_btn = QPushButton("🔓 解密")
        # brute_btn = QPushButton("爆破")
        swap_btn = QPushButton("🔄 互换内容")

        clear_btn = QPushButton("🗑️ 清空内容")
        button_layout3.addWidget(encrypt_btn)
        button_layout3.addWidget(decrypt_btn)
        # button_layout3.addWidget(brute_btn)
        button_layout3.addWidget(swap_btn)
        button_layout3.addWidget(clear_btn)

        # 输出区域
        # output_label = QLabel("输出:")
        aes_output_group = QGroupBox("输出区域")
        aes_output_layout = QVBoxLayout()
        self.aes_output_text = QTextEdit()
        self.aes_output_text.setMinimumHeight(100)
        aes_output_layout.addWidget(self.aes_output_text)
        aes_output_group.setLayout(aes_output_layout)

        # 按钮绑定功能
        # 添加事件绑定
        self.aes_input_text.textChanged.connect(self.update_status_bar1)
        self.aes_output_text.textChanged.connect(self.update_status_bar1)
        encrypt_btn.clicked.connect(self.aes_encrypt_text)
        decrypt_btn.clicked.connect(self.aes_decrypt_text)

        swap_btn.clicked.connect(self.aes_swap_text)
        clear_btn.clicked.connect(self.aes_clear_text)


        # 添加到tab布局
        # layout.addWidget(input_label)
        layout.addWidget(aes_input_group)
        layout.addLayout(button_layout)
        layout.addLayout(button_layout2)
        layout.addLayout(button_layout3)
        # layout.addWidget(output_label)
        layout.addWidget(aes_output_group)

    def init_des_encrypt_tab(self):
        """初始化des加解密"""
        layout = QVBoxLayout(self.des_tab)
        # 输入区域
        des_input_group = QGroupBox("输入区域")
        des_input_layout = QVBoxLayout()
        self.des_input_text = QTextEdit()
        self.des_input_text.setPlaceholderText("请输入...")
        self.des_input_text.setMinimumHeight(100)
        des_input_layout.addWidget(self.des_input_text)
        des_input_group.setLayout(des_input_layout)

        # 第一排操作选项
        button_layout = QHBoxLayout()
        button_layout.setSpacing(5)
        # button_layout.setAlignment(Qt.AlignCenter)
        self.des_mode_combo = QComboBox()
        self.des_mode_combo.addItems(["ECB","CBC"])
        self.des_mode_combo.setCurrentText("ECB")

        # 字符编码选择
        self.des_padding_combo = QComboBox()
        self.des_padding_combo.addItems([
            "PKCS5", "NONE", "ZERO"
        ])
        self.des_padding_combo.setCurrentText("PKCS5")

        # 密码编码选择
        self.des_pass_combo = QComboBox()
        self.des_pass_combo.addItems([
            "UTF-8", "Base64", "Hex"
        ])
        self.des_pass_combo.setCurrentText("UTF-8")

        des_mode_label = QLabel("模式")
        des_padding_label = QLabel("填充")
        des_pass_label = QLabel("密钥key")
        self.des_passwd_inputline = QLineEdit()
        self.des_passwd_inputline.setFont(QFont('Arial', 10))


        # 第二排
        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(5)
        # button_layout2.setAlignment(Qt.AlignCenter)
        # 数据块大小
        self.des_block_combo = QComboBox()
        self.des_block_combo.addItems([
            "64", "128"
        ])
        self.des_block_combo.setCurrentText("64")

        # 输出字符编码选择
        self.des_output_combo = QComboBox()
        self.des_output_combo.addItems([
            "Base64", "Hex"
        ])
        self.des_output_combo.setCurrentText("Base64")

        # 偏移量编码选择
        self.des_iv_combo = QComboBox()
        self.des_iv_combo.addItems([
            "UTF-8", "Base64", "Hex"
        ])
        self.des_iv_combo.setCurrentText("UTF-8")

        des_block_label = QLabel("数据块")
        des_output_label = QLabel("输出")
        des_iv_label = QLabel("偏移量iv")
        self.des_iv_inputline = QLineEdit()
        # des_iv_inputline.setStyleSheet("QLineEdit { padding: 5px; width: 120px;}")
        self.des_iv_inputline.setFont(QFont('Arial', 10))

        # 添加到HBox容器
        button_layout.addWidget(des_mode_label)
        button_layout.addWidget(self.des_mode_combo)
        button_layout.addWidget(des_padding_label)
        button_layout.addWidget(self.des_padding_combo)
        button_layout.addWidget(des_pass_label)
        button_layout.addWidget(self.des_pass_combo)
        button_layout.addWidget(self.des_passwd_inputline)


        button_layout2.addWidget(des_block_label)
        button_layout2.addWidget(self.des_block_combo)
        button_layout2.addWidget(des_output_label)
        button_layout2.addWidget(self.des_output_combo)
        button_layout2.addWidget(des_iv_label)
        button_layout2.addWidget(self.des_iv_combo)
        button_layout2.addWidget(self.des_iv_inputline)


        # 第三排操作按钮
        button_layout3 = QHBoxLayout()
        button_layout3.setSpacing(5)
        button_layout3.setAlignment(Qt.AlignCenter)

        encrypt_btn = QPushButton("🔒 加密")
        decrypt_btn = QPushButton("🔓 解密")
        # brute_btn = QPushButton("爆破")
        swap_btn = QPushButton("🔄 互换内容")
        clear_btn = QPushButton("🗑️ 清空内容")
        button_layout3.addWidget(encrypt_btn)
        button_layout3.addWidget(decrypt_btn)
        # button_layout3.addWidget(brute_btn)
        button_layout3.addWidget(swap_btn)
        button_layout3.addWidget(clear_btn)

        # 输出区域
        des_output_group = QGroupBox("输出区域")
        des_output_layout = QVBoxLayout()
        self.des_output_text = QTextEdit()
        self.des_output_text.setMinimumHeight(100)
        des_output_layout.addWidget(self.des_output_text)
        des_output_group.setLayout(des_output_layout)

        # 按钮绑定功能
        # 添加事件绑定
        self.des_input_text.textChanged.connect(self.update_status_bar2)
        self.des_output_text.textChanged.connect(self.update_status_bar2)
        encrypt_btn.clicked.connect(self.des_encrypt_text)
        decrypt_btn.clicked.connect(self.des_decrypt_text)

        swap_btn.clicked.connect(self.des_swap_text)
        clear_btn.clicked.connect(self.des_clear_text)


        # layout.addWidget(input_label)
        layout.addWidget(des_input_group)
        layout.addLayout(button_layout)
        layout.addLayout(button_layout2)
        layout.addLayout(button_layout3)
        # layout.addWidget(output_label)
        layout.addWidget(des_output_group)

    def init_des3_encrypt_tab(self):
        """初始化des3加解密"""
        layout = QVBoxLayout(self.des3_tab)
        # 输入区域
        des3_input_group = QGroupBox("输入区域")
        des3_input_layout = QVBoxLayout()
        self.des3_input_text = QTextEdit()
        self.des3_input_text.setPlaceholderText("请输入...")
        self.des3_input_text.setMinimumHeight(100)
        des3_input_layout.addWidget(self.des3_input_text)
        des3_input_group.setLayout(des3_input_layout)

        # 第一排操作选项
        button_layout = QHBoxLayout()
        button_layout.setSpacing(5)
        # button_layout.setAlignment(Qt.AlignCenter)
        self.des3_mode_combo = QComboBox()
        self.des3_mode_combo.addItems(["ECB","CBC"])
        self.des3_mode_combo.setCurrentText("ECB")

        # 字符编码选择
        self.des3_padding_combo = QComboBox()
        self.des3_padding_combo.addItems([
            "PKCS5", "NONE", "ZERO"
        ])
        self.des3_padding_combo.setCurrentText("PKCS5")

        # 密码编码选择
        self.des3_pass_combo = QComboBox()
        self.des3_pass_combo.addItems([
            "UTF-8", "Base64", "Hex"
        ])
        self.des3_pass_combo.setCurrentText("UTF-8")

        des3_mode_label = QLabel("模式")
        des3_padding_label = QLabel("填充")
        des3_pass_label = QLabel("密钥key")
        self.des3_passwd_inputline = QLineEdit()
        self.des3_passwd_inputline.setFont(QFont('Arial', 10))

        # 第二排
        button_layout2 = QHBoxLayout()
        button_layout2.setSpacing(5)
        # button_layout2.setAlignment(Qt.AlignCenter)
        # 数据块大小
        self.des3_block_combo = QComboBox()
        self.des3_block_combo.addItems([
            "128", "192"
        ])
        self.des3_block_combo.setCurrentText("192")

        # 输出字符编码选择
        self.des3_output_combo = QComboBox()
        self.des3_output_combo.addItems([
            "Base64", "Hex"
        ])
        self.des3_output_combo.setCurrentText("Base64")

        # 偏移量编码选择
        self.des3_iv_combo = QComboBox()
        self.des3_iv_combo.addItems([
            "UTF-8", "Base64", "Hex"
        ])
        self.des3_iv_combo.setCurrentText("UTF-8")

        des3_block_label = QLabel("数据块")
        des3_output_label = QLabel("输出")
        des3_iv_label = QLabel("偏移量iv")
        self.des3_iv_inputline = QLineEdit()
        # des3_iv_inputline.setStyleSheet("QLineEdit { padding: 5px; width: 120px;}")
        self.des3_iv_inputline.setFont(QFont('Arial', 10))

        # 添加到HBox容器
        button_layout.addWidget(des3_mode_label)
        button_layout.addWidget(self.des3_mode_combo)
        button_layout.addWidget(des3_padding_label)
        button_layout.addWidget(self.des3_padding_combo)
        button_layout.addWidget(des3_pass_label)
        button_layout.addWidget(self.des3_pass_combo)
        button_layout.addWidget(self.des3_passwd_inputline)


        button_layout2.addWidget(des3_block_label)
        button_layout2.addWidget(self.des3_block_combo)
        button_layout2.addWidget(des3_output_label)
        button_layout2.addWidget(self.des3_output_combo)
        button_layout2.addWidget(des3_iv_label)
        button_layout2.addWidget(self.des3_iv_combo)
        button_layout2.addWidget(self.des3_iv_inputline)


        # 第三排操作按钮
        button_layout3 = QHBoxLayout()
        button_layout3.setSpacing(5)
        button_layout3.setAlignment(Qt.AlignCenter)

        encrypt_btn = QPushButton("🔒 加密")
        decrypt_btn = QPushButton("🔓 解密")
        # brute_btn = QPushButton("爆破")
        swap_btn = QPushButton("🔄 互换内容")
        clear_btn = QPushButton("🗑️ 清空内容")
        button_layout3.addWidget(encrypt_btn)
        button_layout3.addWidget(decrypt_btn)
        button_layout3.addWidget(swap_btn)
        button_layout3.addWidget(clear_btn)

        # 输出区域
        des3_output_group = QGroupBox("输出区域")
        des3_output_layout = QVBoxLayout()
        self.des3_output_text = QTextEdit()
        self.des3_output_text.setMinimumHeight(100)
        des3_output_layout.addWidget(self.des3_output_text)
        des3_output_group.setLayout(des3_output_layout)

        # 按钮绑定功能
        # 添加事件绑定
        self.des3_input_text.textChanged.connect(self.update_status_bar3)
        self.des3_output_text.textChanged.connect(self.update_status_bar3)
        encrypt_btn.clicked.connect(self.des3_encrypt_text)
        decrypt_btn.clicked.connect(self.des3_decrypt_text)

        swap_btn.clicked.connect(self.des3_swap_text)
        clear_btn.clicked.connect(self.des3_clear_text)


        # layout.addWidget(input_label)
        layout.addWidget(des3_input_group)
        layout.addLayout(button_layout)
        layout.addLayout(button_layout2)
        layout.addLayout(button_layout3)
        # layout.addWidget(output_label)
        layout.addWidget(des3_output_group)

    '''
    实现功能区
    '''
    def update_status_bar1(self):
        """更新状态栏显示输入框的字符长度"""
        ToolUtils.update_textChanged_statusbar(self.aes_input_text,self.aes_output_text,self.status_bar)

    def update_status_bar2(self):
        """更新状态栏显示输入框的字符长度"""
        ToolUtils.update_textChanged_statusbar(self.des_input_text,self.des_output_text,self.status_bar)

    def update_status_bar3(self):
        """更新状态栏显示输入框的字符长度"""
        ToolUtils.update_textChanged_statusbar(self.des3_input_text,self.des3_output_text,self.status_bar)

    def aes_encrypt_text(self):
        input = self.aes_input_text.toPlainText()
        mode = self.aes_mode_combo.currentText()
        pad = self.aes_padding_combo.currentText()
        key_type = self.aes_pass_combo.currentText()
        key = self.aes_passwd_inputline.text().strip()
        block = self.aes_block_combo.currentText()
        output_type = self.aes_output_combo.currentText()
        iv_type = self.aes_iv_combo.currentText()
        iv = self.aes_iv_inputline.text().strip()
        if (key == ''):
            QMessageBox.information(self,"提示","请输入密钥key")
            return
        try:
            result = AESCipher.encrypt_data(input,key,mode,pad,key_type,iv,iv_type,int(block),output_type)
            self.aes_output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.warning(self,"提示",f'加密失败！{e}')
            self.aes_output_text.setPlainText(f'{e}')


    def aes_decrypt_text(self):
        input = self.aes_input_text.toPlainText()
        mode = self.aes_mode_combo.currentText()
        pad = self.aes_padding_combo.currentText()
        key_type = self.aes_pass_combo.currentText()
        key = self.aes_passwd_inputline.text().strip()
        block = self.aes_block_combo.currentText()
        output_type = self.aes_output_combo.currentText()
        iv_type = self.aes_iv_combo.currentText()
        iv = self.aes_iv_inputline.text().strip()
        if (key == ''):
            QMessageBox.information(self, "提示", "请输入密钥key")
            return
        try:
            result = AESCipher.decrypt_data(input,key,mode,pad,key_type,iv,iv_type,int(block),output_type)
            self.aes_output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.warning(self,"提示",f'解密失败！{e}')
            self.aes_output_text.setPlainText(f'{e}')


    def des_encrypt_text(self):
        input = self.des_input_text.toPlainText()
        mode = self.des_mode_combo.currentText()
        pad = self.des_padding_combo.currentText()
        key_type = self.des_pass_combo.currentText()
        key = self.des_passwd_inputline.text().strip()
        block = self.des_block_combo.currentText()
        output_type = self.des_output_combo.currentText()
        iv_type = self.des_iv_combo.currentText()
        iv = self.des_iv_inputline.text().strip()

        if (key == ''):
            QMessageBox.information(self, "提示", "请输入密钥key")
            return

        try:
            result = DESCipher.encrypt_data(input,key,mode,pad,key_type,iv,iv_type,output_type)
            self.des_output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.warning(self,"提示",f'加密失败！{e}')
            self.des_output_text.setPlainText(f'{e}')


    def des_decrypt_text(self):
        input = self.des_input_text.toPlainText()
        mode = self.des_mode_combo.currentText()
        pad = self.des_padding_combo.currentText()
        key_type = self.des_pass_combo.currentText()
        key = self.des_passwd_inputline.text().strip()
        block = self.des_block_combo.currentText()
        output_type = self.des_output_combo.currentText()
        iv_type = self.des_iv_combo.currentText()
        iv = self.des_iv_inputline.text().strip()
        if (key == ''):
            QMessageBox.information(self, "提示", "请输入密钥key")
            return
        try:
            result = DESCipher.decrypt_data(input,key,mode,pad,key_type,iv,iv_type,output_type)
            self.des_output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.warning(self,"提示",f'解密失败！{e}')
            self.des_output_text.setPlainText(f'{e}')


    def des3_encrypt_text(self):
        input = self.des3_input_text.toPlainText()
        mode = self.des3_mode_combo.currentText()
        pad = self.des3_padding_combo.currentText()
        key_type = self.des3_pass_combo.currentText()
        key = self.des3_passwd_inputline.text().strip()
        block = self.des3_block_combo.currentText()
        output_type = self.des3_output_combo.currentText()
        iv_type = self.des3_iv_combo.currentText()
        iv = self.des3_iv_inputline.text().strip()
        print(key)
        if (key == ''):
            QMessageBox.information(self, "提示", "请输入密钥key")
            return
        try:
            result = TripleDESCipher.encrypt_data(input,key,mode,pad,key_type,iv,iv_type,output_type)
            self.des3_output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.warning(self,"提示",f'加密失败！{e}')
            self.des3_output_text.setPlainText(f'{e}')


    def des3_decrypt_text(self):
        input = self.des3_input_text.toPlainText()
        mode = self.des3_mode_combo.currentText()
        pad = self.des3_padding_combo.currentText()
        key_type = self.des3_pass_combo.currentText()
        key = self.des3_passwd_inputline.text().strip()
        block = self.des3_block_combo.currentText()
        output_type = self.des3_output_combo.currentText()
        iv_type = self.des3_iv_combo.currentText()
        iv = self.des3_iv_inputline.text().strip()
        print(key)
        if (key == ''):
            QMessageBox.information(self, "提示", "请输入密钥key")
            return
        try:
            result = TripleDESCipher.decrypt_data(input,key,mode,pad,key_type,iv,iv_type,output_type)
            self.des3_output_text.setPlainText(result)
        except Exception as e:
            QMessageBox.warning(self,"提示",f'解密失败！{e}')
            self.des3_output_text.setPlainText(f'{e}')

    def aes_clear_text(self):
        ToolUtils.clear_content(self.aes_input_text,self.aes_output_text)

    def aes_swap_text(self):
        ToolUtils.swap_content(self.aes_input_text,self.aes_output_text)

    def des_clear_text(self):
        ToolUtils.clear_content(self.des_input_text,self.des_output_text)

    def des_swap_text(self):
        ToolUtils.swap_content(self.des_input_text,self.des_output_text)

    def des3_clear_text(self):
        ToolUtils.clear_content(self.des3_input_text, self.des3_output_text)

    def des3_swap_text(self):
        ToolUtils.swap_content(self.des3_input_text, self.des3_output_text)