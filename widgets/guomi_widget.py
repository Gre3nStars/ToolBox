import sys
import os
import secrets
import string
import base64
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QTextEdit, QPushButton, QGroupBox, QLabel,
                               QFileDialog, QLineEdit, QComboBox, QMessageBox, QGridLayout,
                               QTabWidget, QSpacerItem, QSizePolicy, QButtonGroup, QRadioButton)
from PySide6.QtCore import Signal, QThread
from PySide6.QtGui import QFont, QClipboard, Qt

# 确保安装了必要的依赖库
try:
    from gmssl import sm2, sm3, sm4
except ImportError:
    QMessageBox.critical(None, "依赖缺失", "请先安装gmssl库：\npip install gmssl")
    sys.exit(1)


# 常量定义
SM2_MAX_ENCRYPT_BLOCK = 64  # SM2单次加密最大字节数
SM4_KEY_SIZE = 16           # SM4密钥长度（字节）
SM4_IV_SIZE = 16            # SM4 IV向量长度（字节）
SM2_PUB_KEY_LEN_1 = 128     # SM2公钥长度（无04前缀）
SM2_PUB_KEY_LEN_2 = 130     # SM2公钥长度（有04前缀）
SM2_PRIV_KEY_LEN = 64       # SM2私钥长度


# 编码转换工具
class CodecUtils:
    @staticmethod
    def encode(data, encoding='utf-8'):
        """将字符串按指定编码转换为字节"""
        if isinstance(data, str):
            return data.encode(encoding)
        return data

    @staticmethod
    def decode(data, encoding='utf-8'):
        """将字节按指定编码转换为字符串"""
        if isinstance(data, bytes):
            return data.decode(encoding, errors='replace')
        return data

    @staticmethod
    def hex_to_bytes(hex_str):
        """十六进制字符串转字节"""
        try:
            return bytes.fromhex(hex_str)
        except ValueError:
            raise Exception("无效的十六进制字符串")

    @staticmethod
    def bytes_to_hex(data):
        """字节转十六进制字符串"""
        return data.hex()

    @staticmethod
    def base64_to_bytes(b64_str):
        """Base64字符串转字节"""
        try:
            return base64.b64decode(b64_str)
        except ValueError:
            raise Exception("无效的Base64字符串")

    @staticmethod
    def bytes_to_base64(data):
        """字节转Base64字符串"""
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def pkcs7_pad(data, block_size=16):
        """PKCS#7填充"""
        pad_length = block_size - (len(data) % block_size)
        return data + bytes([pad_length]) * pad_length

    @staticmethod
    def pkcs7_unpad(data):
        """PKCS#7去填充"""
        if not data:
            return data
        pad_length = data[-1]
        return data[:-pad_length]



# 加密解密线程，避免UI卡顿
class CryptoThread(QThread):
    finished = Signal(str)
    file_finished = Signal(bool)  # 用于文件操作
    error = Signal(str)

    def __init__(self, func, is_file_operation=False, *args, **kwargs):
        super().__init__()
        self.func = func
        self.is_file_operation = is_file_operation
        self.args = args
        self.kwargs = kwargs

    def run(self):
        try:
            result = self.func(*self.args, **self.kwargs)
            if self.is_file_operation:
                self.file_finished.emit(result)
            else:
                self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


# SM2非对称加密解密
class SM2Tool:
    @staticmethod
    def encrypt_text(text, public_key, output_format="HEX"):
        """SM2加密文本"""
        if not text:
            return ""
        if not public_key:
            raise Exception("请提供公钥")

        public_key = public_key.replace(" ", "").upper()
        # 处理公钥格式
        if len(public_key) == SM2_PUB_KEY_LEN_2 and public_key.startswith("04"):
            public_key = public_key[2:]
        elif len(public_key) != SM2_PUB_KEY_LEN_1:
            raise Exception(f"公钥长度无效，应为{SM2_PUB_KEY_LEN_1}位或{SM2_PUB_KEY_LEN_2}位（带04前缀）")

        try:
            # 确保公钥格式正确
            full_public_key = f"04{public_key}" if not public_key.startswith("04") else public_key
            print(full_public_key)

            sm2_crypt = sm2.CryptSM2(
                public_key=full_public_key,
                private_key=""
            )

            data = CodecUtils.encode(text)
            encrypt_data = sm2_crypt.encrypt(data)

            if output_format == "HEX":
                return CodecUtils.bytes_to_hex(encrypt_data)
            elif output_format == "Base64":
                return CodecUtils.bytes_to_base64(encrypt_data)
            else:
                return CodecUtils.decode(encrypt_data)
        except Exception as e:
            raise Exception(f"SM2加密失败: {str(e)}")

    @staticmethod
    def decrypt_text(ciphertext, private_key, output_format="UTF-8"):
        """SM2解密文本"""
        if not ciphertext:
            return ""
        if not private_key:
            raise Exception("请提供私钥")
        if len(private_key) != SM2_PRIV_KEY_LEN:
            raise Exception(f"私钥必须是{SM2_PRIV_KEY_LEN}字符的十六进制字符串")

        try:
            sm2_crypt = sm2.CryptSM2(
                public_key="",
                private_key=private_key
            )

            # 自动识别输入格式
            try:
                data = CodecUtils.hex_to_bytes(ciphertext)
            except:
                try:
                    data = CodecUtils.base64_to_bytes(ciphertext)
                except:
                    data = CodecUtils.encode(ciphertext)

            decrypt_data = sm2_crypt.decrypt(data)

            if output_format == "HEX":
                return CodecUtils.bytes_to_hex(decrypt_data)
            elif output_format == "Base64":
                return CodecUtils.bytes_to_base64(decrypt_data)
            else:
                return CodecUtils.decode(decrypt_data)
        except Exception as e:
            raise Exception(f"SM2解密失败: {str(e)}")

    @staticmethod
    def encrypt_file(input_path, output_path, public_key):
        """SM2加密文件"""
        if not os.path.exists(input_path):
            raise Exception("输入文件不存在")
        if not public_key:
            raise Exception("请提供公钥")

        try:
            full_public_key = f"04{public_key}" if not public_key.startswith("04") else public_key

            sm2_crypt = sm2.CryptSM2(
                public_key=full_public_key,
                private_key=""
            )

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                while True:
                    data = fin.read(SM2_MAX_ENCRYPT_BLOCK)  # SM2单次加密限制
                    if not data:
                        break
                    encrypt_data = sm2_crypt.encrypt(data)
                    # 写入加密数据长度和数据本身（用于解密时正确分割）
                    fout.write(len(encrypt_data).to_bytes(4, byteorder='big'))
                    fout.write(encrypt_data)

            return True
        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            raise Exception(f"SM2文件加密失败: {str(e)}")

    @staticmethod
    def decrypt_file(input_path, output_path, private_key):
        """SM2解密文件"""
        if not os.path.exists(input_path):
            raise Exception("输入文件不存在")
        if not private_key:
            raise Exception("请提供私钥")

        try:
            sm2_crypt = sm2.CryptSM2(
                public_key="",
                private_key=private_key
            )

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                while True:
                    len_bytes = fin.read(4)
                    if not len_bytes:
                        break
                    data_len = int.from_bytes(len_bytes, byteorder='big')
                    encrypt_data = fin.read(data_len)
                    decrypt_data = sm2_crypt.decrypt(encrypt_data)
                    fout.write(decrypt_data)

            return True
        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            raise Exception(f"SM2文件解密失败: {str(e)}")


# SM3哈希计算
class SM3Tool:
    @staticmethod
    def hash_text(text, output_format="HEX"):
        """计算文本的SM3哈希值"""
        if not text:
            return ""
        try:
            data = CodecUtils.encode(text)
            hash_hex = sm3.sm3_hash(list(data))
            hash_bytes = CodecUtils.hex_to_bytes(hash_hex)

            if output_format == "Base64":
                return CodecUtils.bytes_to_base64(hash_bytes)
            return hash_hex
        except Exception as e:
            raise Exception(f"SM3哈希计算失败: {str(e)}")

    @staticmethod
    def hash_file(file_path, output_format="HEX"):
        """计算文件的SM3哈希值"""
        if not os.path.exists(file_path):
            raise Exception("文件不存在")

        try:
            # 读取整个文件内容进行哈希计算（大文件可优化为分块处理）
            with open(file_path, 'rb') as f:
                data = f.read()
                hash_hex = sm3.sm3_hash(list(data))

            if output_format == "Base64":
                return CodecUtils.bytes_to_base64(CodecUtils.hex_to_bytes(hash_hex))
            return hash_hex
        except Exception as e:
            raise Exception(f"文件SM3哈希计算失败: {str(e)}")


# SM4加密解密
class SM4Tool:
    @staticmethod
    def generate_key():
        """生成随机的16字节SM4密钥（使用加密安全的随机数生成器）"""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(SM4_KEY_SIZE))

    @staticmethod
    def generate_iv():
        """生成随机的16字节IV向量（使用加密安全的随机数生成器）"""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(SM4_IV_SIZE))

    @staticmethod
    def _get_key_bytes(key, key_format):
        """将密钥转换为字节，处理不同格式"""
        if key_format == "HEX":
            return CodecUtils.hex_to_bytes(key)
        elif key_format == "Base64":
            return CodecUtils.base64_to_bytes(key)
        else:  # UTF-8
            return CodecUtils.encode(key)

    @staticmethod
    def encrypt_text(text, key, key_format="UTF-8", iv=None, iv_format="UTF-8",
                     output_format="HEX", mode=sm4.SM4_ENCRYPT):
        """SM4加密文本"""
        if not text:
            return ""

        try:
            key_bytes = SM4Tool._get_key_bytes(key, key_format)
            if len(key_bytes) != SM4_KEY_SIZE:
                raise Exception(f"密钥必须是{SM4_KEY_SIZE}字节，当前{len(key_bytes)}字节")

            sm4_crypt = sm4.CryptSM4()
            sm4_crypt.set_key(key_bytes, mode)

            data = CodecUtils.encode(text)

            if mode == sm4.SM4_ENCRYPT:
                data = CodecUtils.pkcs7_pad(data)

                if iv:
                    iv_bytes = SM4Tool._get_key_bytes(iv, iv_format)
                    if len(iv_bytes) != SM4_IV_SIZE:
                        raise Exception(f"IV必须是{SM4_IV_SIZE}字节，当前{len(iv_bytes)}字节")
                    result = sm4_crypt.crypt_cbc(iv_bytes, data)
                else:
                    result = sm4_crypt.crypt_ecb(data)
            else:
                if output_format == "HEX":
                    data = CodecUtils.hex_to_bytes(text)
                elif output_format == "Base64":
                    data = CodecUtils.base64_to_bytes(text)
                else:
                    data = CodecUtils.encode(text)

                if iv:
                    iv_bytes = SM4Tool._get_key_bytes(iv, iv_format)
                    if len(iv_bytes) != SM4_IV_SIZE:
                        raise Exception(f"IV必须是{SM4_IV_SIZE}字节，当前{len(iv_bytes)}字节")
                    result = sm4_crypt.crypt_cbc(iv_bytes, data)
                else:
                    result = sm4_crypt.crypt_ecb(data)

                result = CodecUtils.pkcs7_unpad(result)

            if output_format == "HEX":
                return CodecUtils.bytes_to_hex(result)
            elif output_format == "Base64":
                return CodecUtils.bytes_to_base64(result)
            else:
                return CodecUtils.decode(result)

        except Exception as e:
            raise Exception(f"SM4操作失败: {str(e)}")

    @staticmethod
    def decrypt_text(ciphertext, key, key_format="UTF-8", iv=None, iv_format="UTF-8",
                     input_format="HEX", output_format="UTF-8"):
        """SM4解密文本"""
        return SM4Tool.encrypt_text(
            ciphertext, key, key_format, iv, iv_format,
            output_format=output_format, mode=sm4.SM4_DECRYPT
        )

    @staticmethod
    def encrypt_file_sm4(input_path, output_path, key, key_format="UTF-8",
                         iv=None, iv_format="UTF-8", mode=sm4.SM4_ENCRYPT):
        """SM4加密文件"""
        if not os.path.exists(input_path):
            raise Exception("输入文件不存在")

        try:
            key_bytes = SM4Tool._get_key_bytes(key, key_format)
            if len(key_bytes) != SM4_KEY_SIZE:
                raise Exception(f"密钥必须是{SM4_KEY_SIZE}字节，当前{len(key_bytes)}字节")

            sm4_crypt = sm4.CryptSM4()
            sm4_crypt.set_key(key_bytes, mode)

            # 对于CBC模式，需要IV向量
            iv_bytes = None
            if iv and mode == sm4.SM4_ENCRYPT:
                iv_bytes = SM4Tool._get_key_bytes(iv, iv_format)
                if len(iv_bytes) != SM4_IV_SIZE:
                    raise Exception(f"IV必须是{SM4_IV_SIZE}字节，当前{len(iv_bytes)}字节")

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # 写入IV向量（4字节长度 + 16字节IV）
                if iv_bytes:
                    fout.write(len(iv_bytes).to_bytes(4, byteorder='big'))
                    fout.write(iv_bytes)

                # 加密文件内容
                while True:
                    data = fin.read(4096)
                    if not data:
                        break
                    data = CodecUtils.pkcs7_pad(data)
                    result = sm4_crypt.crypt_cbc(iv_bytes, data) if iv_bytes else sm4_crypt.crypt_ecb(data)
                    fout.write(result)

            return True
        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            raise Exception(f"文件SM4处理失败: {str(e)}")

    @staticmethod
    def decrypt_file_sm4(input_path, output_path, key, key_format="UTF-8"):
        """SM4解密文件"""
        if not os.path.exists(input_path):
            raise Exception("输入文件不存在")

        try:
            key_bytes = SM4Tool._get_key_bytes(key, key_format)
            if len(key_bytes) != SM4_KEY_SIZE:
                raise Exception(f"密钥必须是{SM4_KEY_SIZE}字节，当前{len(key_bytes)}字节")

            sm4_crypt = sm4.CryptSM4()
            sm4_crypt.set_key(key_bytes, sm4.SM4_DECRYPT)

            with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
                # 读取IV向量（如果有）
                iv_bytes = None
                len_bytes = fin.read(4)
                if len_bytes:
                    iv_len = int.from_bytes(len_bytes, byteorder='big')
                    if iv_len == SM4_IV_SIZE:  # IV必须是16字节
                        iv_bytes = fin.read(iv_len)
                        # 如果IV读取不完整，说明文件格式错误
                        if len(iv_bytes) != iv_len:
                            raise Exception("无效的加密文件格式")

                # 解密文件内容
                while True:
                    data = fin.read(4096)
                    if not data:
                        break
                    result = sm4_crypt.crypt_cbc(iv_bytes, data) if iv_bytes else sm4_crypt.crypt_ecb(data)
                    result = CodecUtils.pkcs7_unpad(result)
                    fout.write(result)

            return True
        except Exception as e:
            if os.path.exists(output_path):
                os.remove(output_path)
            raise Exception(f"文件SM4处理失败: {str(e)}")


# 主窗口
class GMCryptoTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_algorithm = "SM2加密"  # 默认算法
        self.init_ui()

    def init_ui(self):
        # 设置窗口基本属性
        self.setWindowTitle("国密算法工具 (SM2/SM3/SM4)")
        self.setMinimumSize(800, 600)

        # 创建主部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. 使用QTabWidget组织不同算法
        self.tab_widget = QTabWidget()

        # 创建各算法标签页
        self.sm2_encrypt_tab = self.create_sm2_encrypt_tab()
        self.sm2_decrypt_tab = self.create_sm2_decrypt_tab()
        self.sm3_tab = self.create_sm3_tab()
        self.sm4_tab = self.create_sm4_tab()
        # self.sm2_general_key_tab = self.create_sm2_general_tab()

        # 添加标签页
        self.tab_widget.addTab(self.sm2_encrypt_tab, "SM2加密")
        self.tab_widget.addTab(self.sm2_decrypt_tab, "SM2解密")
        # self.tab_widget.addTab(self.sm2_general_key_tab,"SM2密钥生成")
        self.tab_widget.addTab(self.sm3_tab, "SM3哈希")
        self.tab_widget.addTab(self.sm4_tab, "SM4对称加密")

        # 连接标签页切换信号
        self.tab_widget.currentChanged.connect(self.on_tab_changed)

        main_layout.addWidget(self.tab_widget)

        # 2. 中间功能按钮区域和输出格式选项
        self.buttons_widget = QWidget()
        self.buttons_layout = QHBoxLayout(self.buttons_widget)

        # 输出格式选择
        self.format_label = QLabel("输出格式:")
        self.output_format = QComboBox()
        self.output_format.addItems(["HEX", "Base64", "UTF-8"])

        # 主要操作按钮
        self.encrypt_btn = QPushButton("🔒 加密")
        self.decrypt_btn = QPushButton("🔓 解密")
        self.hash_btn = QPushButton("🔍 计算哈希")

        # 辅助操作按钮
        self.swap_btn = QPushButton("↔️ 互换")
        self.copy_btn = QPushButton("📋 复制结果")
        self.clear_btn = QPushButton("🗑️ 清空")

        # 添加到布局
        self.buttons_layout.addWidget(self.format_label)
        self.buttons_layout.addWidget(self.output_format)
        self.buttons_layout.addWidget(self.encrypt_btn)
        self.buttons_layout.addWidget(self.decrypt_btn)
        self.buttons_layout.addWidget(self.hash_btn)
        self.buttons_layout.addWidget(self.swap_btn)
        self.buttons_layout.addWidget(self.copy_btn)
        self.buttons_layout.addWidget(self.clear_btn)

        # 居中布局
        self.buttons_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 连接信号槽
        self.encrypt_btn.clicked.connect(self.encrypt_action)
        self.decrypt_btn.clicked.connect(self.decrypt_action)
        self.hash_btn.clicked.connect(self.hash_action)
        self.swap_btn.clicked.connect(self.swap_action)
        self.copy_btn.clicked.connect(self.copy_result)
        self.clear_btn.clicked.connect(self.clear_all)

        main_layout.addWidget(self.buttons_widget)

        # 4. 状态栏
        self.statusBar().showMessage("就绪")

        # 根据默认算法更新按钮状态和输出格式选项
        self.update_buttons_state()
        self.update_output_formats()

    def create_sm2_encrypt_tab(self):
        """创建SM2加密标签页内容"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 密钥区域
        key_group = QGroupBox("SM2加密密钥设置")
        key_layout = QVBoxLayout()

        # 公钥
        pub_key_layout = QHBoxLayout()
        self.sm2_encrypt_pub_key = QTextEdit()
        self.sm2_encrypt_pub_key.setPlaceholderText(f"请输入{SM2_PUB_KEY_LEN_1}或{SM2_PUB_KEY_LEN_2}字符公钥（十六进制）")
        pub_key_layout.addWidget(self.sm2_encrypt_pub_key)

        key_layout.addLayout(pub_key_layout)
        key_group.setLayout(key_layout)

        # 输入区域
        input_group = QGroupBox("输入需要加密的内容")
        input_layout = QVBoxLayout()

        # 文本输入
        self.sm2_encrypt_input_text = QTextEdit()
        self.sm2_encrypt_input_text.setPlaceholderText("请输入需要加密的文本...")

        # 文件输入
        file_layout = QVBoxLayout()

        # 输入文件
        input_file_layout = QHBoxLayout()
        input_file_label = QLabel("输入文件:")
        input_file_label.setMinimumWidth(100)
        self.sm2_encrypt_input_file = QLineEdit()
        self.sm2_encrypt_input_file.setReadOnly(True)
        self.sm2_encrypt_browse_input_btn = QPushButton("📂 浏览")
        input_file_layout.addWidget(input_file_label)
        input_file_layout.addWidget(self.sm2_encrypt_input_file)
        input_file_layout.addWidget(self.sm2_encrypt_browse_input_btn)

        # 输出目录
        output_dir_layout = QHBoxLayout()
        output_dir_label = QLabel("输出目录:")
        output_dir_label.setMinimumWidth(100)
        self.sm2_encrypt_output_dir = QLineEdit()
        self.sm2_encrypt_output_dir.setReadOnly(True)
        self.sm2_encrypt_browse_output_btn = QPushButton("📂 浏览")
        output_dir_layout.addWidget(output_dir_label)
        output_dir_layout.addWidget(self.sm2_encrypt_output_dir)
        output_dir_layout.addWidget(self.sm2_encrypt_browse_output_btn)

        file_layout.addLayout(input_file_layout)
        file_layout.addLayout(output_dir_layout)

        input_layout.addWidget(self.sm2_encrypt_input_text)
        input_layout.addLayout(file_layout)
        input_group.setLayout(input_layout)

        # sm2加密输出结果
        self.sm2_encrypt_output_text = QTextEdit()
        self.sm2_encrypt_output_text.setReadOnly(True)

        output_group = QGroupBox("输出结果")
        output_layout = QVBoxLayout()

        output_layout.addWidget(self.sm2_encrypt_output_text)
        output_group.setLayout(output_layout)

        layout.addWidget(key_group)
        layout.addWidget(input_group)
        layout.addWidget(output_group)

        # 连接信号槽
        self.sm2_encrypt_browse_input_btn.clicked.connect(
            lambda: self.browse_file(self.sm2_encrypt_input_file))
        self.sm2_encrypt_browse_output_btn.clicked.connect(
            lambda: self.browse_directory(self.sm2_encrypt_output_dir))



        return widget

    def create_sm2_decrypt_tab(self):
        """创建SM2解密标签页内容"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 密钥区域
        key_group = QGroupBox("SM2解密密钥设置")
        key_layout = QVBoxLayout()

        # 私钥
        pri_key_layout = QHBoxLayout()
        self.sm2_decrypt_pri_key = QTextEdit()
        self.sm2_decrypt_pri_key.setPlaceholderText(f"请输入{SM2_PRIV_KEY_LEN}字符私钥（十六进制）")
        pri_key_layout.addWidget(self.sm2_decrypt_pri_key)

        key_layout.addLayout(pri_key_layout)
        key_group.setLayout(key_layout)

        # 输入区域
        input_group = QGroupBox("输入需要解密的内容")
        input_layout = QVBoxLayout()

        # 文本输入
        self.sm2_decrypt_input_text = QTextEdit()
        self.sm2_decrypt_input_text.setPlaceholderText("请输入需要解密的密文...")

        # 文件输入
        file_layout = QVBoxLayout()

        # 输入文件
        input_file_layout = QHBoxLayout()
        input_file_label = QLabel("输入文件:")
        input_file_label.setMinimumWidth(100)
        self.sm2_decrypt_input_file = QLineEdit()
        self.sm2_decrypt_input_file.setReadOnly(True)
        self.sm2_decrypt_browse_input_btn = QPushButton("📂 浏览")
        input_file_layout.addWidget(input_file_label)
        input_file_layout.addWidget(self.sm2_decrypt_input_file)
        input_file_layout.addWidget(self.sm2_decrypt_browse_input_btn)

        # 输出目录
        output_dir_layout = QHBoxLayout()
        output_dir_label = QLabel("输出目录:")
        output_dir_label.setMinimumWidth(100)
        self.sm2_decrypt_output_dir = QLineEdit()
        self.sm2_decrypt_output_dir.setReadOnly(True)
        self.sm2_decrypt_browse_output_btn = QPushButton("📂 浏览")
        output_dir_layout.addWidget(output_dir_label)
        output_dir_layout.addWidget(self.sm2_decrypt_output_dir)
        output_dir_layout.addWidget(self.sm2_decrypt_browse_output_btn)

        file_layout.addLayout(input_file_layout)
        file_layout.addLayout(output_dir_layout)

        input_layout.addWidget(self.sm2_decrypt_input_text)
        input_layout.addLayout(file_layout)
        input_group.setLayout(input_layout)

        # sm2解密输出结果
        self.sm2_decrypt_output_text = QTextEdit()
        self.sm2_decrypt_output_text.setReadOnly(True)
        # 3. 下方输出区域
        output_group = QGroupBox("输出结果")
        output_layout = QVBoxLayout()

        output_layout.addWidget(self.sm2_decrypt_output_text)
        output_group.setLayout(output_layout)

        layout.addWidget(key_group)
        layout.addWidget(input_group)
        layout.addWidget(output_group)

        # 连接信号槽
        self.sm2_decrypt_browse_input_btn.clicked.connect(
            lambda: self.browse_file(self.sm2_decrypt_input_file))
        self.sm2_decrypt_browse_output_btn.clicked.connect(
            lambda: self.browse_directory(self.sm2_decrypt_output_dir))

        return widget

    def create_sm3_tab(self):
        """创建SM3标签页内容"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 输入区域
        input_group = QGroupBox("输入需要计算哈希的内容")
        input_layout = QVBoxLayout()

        # 文本输入
        self.sm3_input_text = QTextEdit()
        self.sm3_input_text.setPlaceholderText("请输入需要计算哈希的文本...")

        # 文件输入
        file_layout = QHBoxLayout()
        file_label_inline = QLabel("文件路径:")
        file_label_inline.setMinimumWidth(100)
        self.sm3_input_file = QLineEdit()
        self.sm3_input_file.setReadOnly(True)
        self.sm3_browse_file_btn = QPushButton("📂 浏览")
        file_layout.addWidget(file_label_inline)
        file_layout.addWidget(self.sm3_input_file)
        file_layout.addWidget(self.sm3_browse_file_btn)

        # sm3 输出结果
        self.sm3_encrypt_output_text = QTextEdit()
        self.sm3_encrypt_output_text.setReadOnly(True)

        # 3. 下方输出区域
        output_group = QGroupBox("输出结果")
        output_layout = QVBoxLayout()

        output_layout.addWidget(self.sm3_encrypt_output_text)
        output_group.setLayout(output_layout)


        input_layout.addWidget(self.sm3_input_text)
        input_layout.addLayout(file_layout)
        input_group.setLayout(input_layout)


        layout.addWidget(input_group)
        layout.addWidget(output_group)

        # 连接信号槽
        self.sm3_browse_file_btn.clicked.connect(lambda: self.browse_file(self.sm3_input_file))

        return widget

    def create_sm4_tab(self):
        """创建SM4标签页内容"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)

        # 添加垂直间隔
        layout.addItem(QSpacerItem(20, 10, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # 密钥设置区域
        key_group = QGroupBox("SM4密钥设置")
        key_layout = QVBoxLayout()
        key_layout.setContentsMargins(10, 10, 10, 10)
        key_layout.setSpacing(10)

        # 模式选择
        mode_layout = QHBoxLayout()
        mode_label = QLabel("加密模式:")
        self.sm4_mode = QComboBox()
        self.sm4_mode.addItems(["ECB", "CBC"])
        self.sm4_mode.currentIndexChanged.connect(self.update_iv_visibility)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.sm4_mode)
        mode_layout.addStretch()

        # 密钥设置
        key_grid = QGridLayout()

        # 密钥行
        key_label = QLabel(f"密钥 ({SM4_KEY_SIZE}字节):")
        self.sm4_key = QLineEdit()
        self.sm4_key.setPlaceholderText(f"请输入{SM4_KEY_SIZE}字节密钥")
        self.sm4_gen_key_btn = QPushButton("🎲 生成")

        key_format_label = QLabel("密钥格式:")
        self.sm4_key_format = QComboBox()
        self.sm4_key_format.addItems(["UTF-8", "HEX", "Base64"])

        key_grid.addWidget(key_label, 0, 0)
        key_grid.addWidget(self.sm4_key, 0, 1)
        key_grid.addWidget(self.sm4_gen_key_btn, 0, 2)
        key_grid.addWidget(key_format_label, 0, 3)
        key_grid.addWidget(self.sm4_key_format, 0, 4)

        # IV设置
        self.iv_grid = QGridLayout()

        iv_label = QLabel(f"IV向量 ({SM4_IV_SIZE}字节):")
        self.sm4_iv = QLineEdit()
        self.sm4_iv.setPlaceholderText(f"CBC模式必须输入{SM4_IV_SIZE}字节IV向量")
        self.sm4_gen_iv_btn = QPushButton("🎲 生成")

        iv_format_label = QLabel("IV格式:")
        self.sm4_iv_format = QComboBox()
        self.sm4_iv_format.addItems(["UTF-8", "HEX", "Base64"])

        self.iv_grid.addWidget(iv_label, 0, 0)
        self.iv_grid.addWidget(self.sm4_iv, 0, 1)
        self.iv_grid.addWidget(self.sm4_gen_iv_btn, 0, 2)
        self.iv_grid.addWidget(iv_format_label, 0, 3)
        self.iv_grid.addWidget(self.sm4_iv_format, 0, 4)

        key_layout.addLayout(mode_layout)
        key_layout.addLayout(key_grid)
        key_layout.addLayout(self.iv_grid)
        key_group.setLayout(key_layout)



        # 输入区域
        input_group = QGroupBox("输入内容")
        input_layout = QVBoxLayout()

        # 文本输入
        self.sm4_input_text = QTextEdit()
        self.sm4_input_text.setPlaceholderText("请输入需要加密/解密的文本...")

        # 文件输入
        file_layout = QVBoxLayout()

        # 输入文件
        input_file_layout = QHBoxLayout()
        input_file_label = QLabel("输入文件:")
        self.sm4_input_file = QLineEdit()
        self.sm4_input_file.setReadOnly(True)
        self.sm4_browse_input_btn = QPushButton("📂 浏览")
        input_file_layout.addWidget(input_file_label)
        input_file_layout.addWidget(self.sm4_input_file)
        input_file_layout.addWidget(self.sm4_browse_input_btn)

        # 输出目录
        output_dir_layout = QHBoxLayout()
        output_dir_label = QLabel("输出目录:")
        self.sm4_output_dir = QLineEdit()
        self.sm4_output_dir.setReadOnly(True)
        self.sm4_browse_output_btn = QPushButton("📂 浏览")
        output_dir_layout.addWidget(output_dir_label)
        output_dir_layout.addWidget(self.sm4_output_dir)
        output_dir_layout.addWidget(self.sm4_browse_output_btn)

        file_layout.addLayout(input_file_layout)
        file_layout.addLayout(output_dir_layout)

        # sm4输出结果
        self.sm4_output_text = QTextEdit()
        self.sm4_output_text.setReadOnly(True)

        # 3. 下方输出区域
        output_group = QGroupBox("输出结果")
        output_layout = QVBoxLayout()

        output_layout.addWidget(self.sm4_output_text)
        output_group.setLayout(output_layout)

        input_layout.addWidget(self.sm4_input_text)
        input_layout.addLayout(file_layout)
        input_group.setLayout(input_layout)

        layout.addWidget(key_group)
        layout.addWidget(input_group)
        layout.addWidget(output_group)

        # 初始隐藏IV布局
        self.update_iv_visibility()

        # 连接信号槽
        self.sm4_gen_key_btn.clicked.connect(self.generate_sm4_key)
        self.sm4_gen_iv_btn.clicked.connect(self.generate_sm4_iv)
        self.sm4_browse_input_btn.clicked.connect(lambda: self.browse_file(self.sm4_input_file))
        self.sm4_browse_output_btn.clicked.connect(lambda: self.browse_directory(self.sm4_output_dir))

        return widget

    # def create_sm2_general_tab(self):
    #     # 主布局
    #     widget = QWidget()
    #     main_layout = QVBoxLayout(widget)
    #     main_layout.setContentsMargins(15, 15, 15, 15)
    #     main_layout.setSpacing(20)
    #
    #     # 1. 标题和说明
    #     title_label = QLabel("SM2密钥对生成工具")
    #     title_font = title_label.font()
    #     title_font.setPointSize(12)
    #     title_font.setBold(True)
    #     title_label.setFont(title_font)
    #     title_label.setAlignment(Qt.AlignCenter)
    #
    #     desc_label = QLabel("生成符合国密标准的SM2非对称加密密钥对，支持128位/130位公钥格式")
    #     desc_label.setAlignment(Qt.AlignCenter)
    #     desc_label.setStyleSheet("color: #666;")
    #
    #     main_layout.addWidget(title_label)
    #     main_layout.addWidget(desc_label)
    #
    #     # 2. 公钥格式选择
    #     format_group = QGroupBox("公钥格式选择")
    #     format_layout = QHBoxLayout()
    #
    #     self.prefix_group = QButtonGroup(self)
    #     self.radio_with_prefix = QRadioButton("130位公钥 (带04前缀，非压缩格式)")
    #     self.radio_without_prefix = QRadioButton("128位公钥 (不带04前缀)")
    #
    #     # 默认选择带前缀格式
    #     self.radio_with_prefix.setChecked(True)
    #
    #     self.prefix_group.addButton(self.radio_with_prefix, 1)
    #     self.prefix_group.addButton(self.radio_without_prefix, 2)
    #
    #     format_layout.addWidget(self.radio_with_prefix)
    #     format_layout.addWidget(self.radio_without_prefix)
    #     format_group.setLayout(format_layout)
    #     main_layout.addWidget(format_group)
    #
    #     # 3. 密钥显示区域
    #     key_grid = QGridLayout()
    #
    #     # 私钥区域
    #     priv_label = QLabel("私钥 (64位十六进制):")
    #     priv_label.setAlignment(Qt.AlignTop)
    #     self.priv_key_edit = QTextEdit()
    #     self.priv_key_edit.setReadOnly(True)
    #     self.priv_key_edit.setMinimumHeight(80)
    #     self.copy_priv_btn = QPushButton("📋 复制私钥")
    #     self.copy_priv_btn.clicked.connect(lambda: self.copy_to_clipboard(self.priv_key_edit))
    #
    #     # 公钥区域
    #     pub_label = QLabel("公钥:")
    #     pub_label.setAlignment(Qt.AlignTop)
    #     self.pub_key_edit = QTextEdit()
    #     self.pub_key_edit.setReadOnly(True)
    #     self.pub_key_edit.setMinimumHeight(80)
    #     self.copy_pub_btn = QPushButton("📋 复制公钥")
    #     self.copy_pub_btn.clicked.connect(lambda: self.copy_to_clipboard(self.pub_key_edit))
    #
    #     # 网格布局排列
    #     key_grid.addWidget(priv_label, 0, 0)
    #     key_grid.addWidget(self.priv_key_edit, 0, 1)
    #     key_grid.addWidget(self.copy_priv_btn, 0, 2)
    #
    #     key_grid.addWidget(pub_label, 1, 0)
    #     key_grid.addWidget(self.pub_key_edit, 1, 1)
    #     key_grid.addWidget(self.copy_pub_btn, 1, 2)
    #
    #     # 设置列宽比例
    #     key_grid.setColumnStretch(1, 1)
    #     key_grid.setColumnMinimumWidth(0, 120)
    #     key_grid.setColumnMinimumWidth(2, 100)
    #
    #     main_layout.addLayout(key_grid)
    #
    #     # 4. 生成按钮
    #     btn_layout = QHBoxLayout()
    #     self.gen_btn = QPushButton("🔑 生成SM2密钥对")
    #     self.gen_btn.setMinimumHeight(40)
    #     self.gen_btn.setStyleSheet("font-size: 10pt;")
    #     self.gen_btn.clicked.connect(self.generate_keys)
    #
    #     btn_layout.addStretch()
    #     btn_layout.addWidget(self.gen_btn)
    #     btn_layout.addStretch()
    #     main_layout.addLayout(btn_layout)
    #
    #     # 5. 状态提示
    #     self.status_label = QLabel("就绪：点击生成按钮创建新的密钥对")
    #     self.status_label.setAlignment(Qt.AlignCenter)
    #     self.status_label.setStyleSheet("color: #333; font-style: italic;")
    #     main_layout.addWidget(self.status_label)
    #
    #     # 添加弹性空间
    #     main_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
    #
    #     # 初始化线程
    #     self.keygen_thread = None
    #     return widget
    #
    # def generate_keys(self):
    #     """生成SM2密钥对"""
    #     # 检查是否已有线程在运行
    #     if self.keygen_thread and self.keygen_thread.isRunning():
    #         QMessageBox.information(self, "提示", "密钥生成中，请稍候...")
    #         return
    #
    #     # 更新状态
    #     self.gen_btn.setEnabled(False)
    #     self.status_label.setText("正在生成密钥对...")
    #     self.priv_key_edit.clear()
    #     self.pub_key_edit.clear()
    #
    #     # 确定公钥格式
    #     include_prefix = self.radio_with_prefix.isChecked()
    #
    #     # 创建并启动线程
    #     self.keygen_thread = SM2KeygenThread(include_prefix)
    #     self.keygen_thread.result_ready.connect(self.on_keys_generated)
    #     self.keygen_thread.error_occurred.connect(self.on_keygen_error)
    #     self.keygen_thread.finished.connect(lambda: self.gen_btn.setEnabled(True))
    #     self.keygen_thread.start()
    #
    # def on_keys_generated(self, private_key, public_key):
    #     """密钥生成完成回调"""
    #     self.priv_key_edit.setText(private_key)
    #     self.pub_key_edit.setText(public_key)
    #
    #     # 显示密钥长度信息
    #     pub_length = len(public_key)
    #     self.status_label.setText(
    #         f"密钥生成成功 | 私钥: 64位 | 公钥: {pub_length}位"
    #     )
    #
    # def on_keygen_error(self, error_msg):
    #     """密钥生成错误回调"""
    #     self.status_label.setText("密钥生成失败")
    #     QMessageBox.critical(self, "生成失败", error_msg)
    #
    # def copy_to_clipboard(self, text_edit):
    #     """复制文本到剪贴板"""
    #     text = text_edit.toPlainText().strip()
    #     if not text:
    #         QMessageBox.warning(self, "提示", "没有可复制的内容")
    #         return
    #
    #     clipboard = QApplication.clipboard()
    #     clipboard.setText(text)
    #     self.status_label.setText("已复制到剪贴板")


    def on_tab_changed(self, index):
        """标签页切换处理"""
        algorithms = ["SM2加密", "SM2解密", "SM3", "SM4"]
        self.current_algorithm = algorithms[index]
        self.update_buttons_state()
        self.update_output_formats()
        self.statusBar().showMessage(f"已切换到{algorithms[index]}")

    def update_buttons_state(self):
        """根据当前算法更新按钮状态"""
        if self.current_algorithm == "SM2加密":
            self.encrypt_btn.setVisible(True)
            self.decrypt_btn.setVisible(False)
            self.hash_btn.setVisible(False)
            self.swap_btn.setVisible(True)
        elif self.current_algorithm == "SM2解密":
            self.encrypt_btn.setVisible(False)
            self.decrypt_btn.setVisible(True)
            self.hash_btn.setVisible(False)
            self.swap_btn.setVisible(True)
        elif self.current_algorithm == "SM3":
            self.encrypt_btn.setVisible(False)
            self.decrypt_btn.setVisible(False)
            self.hash_btn.setVisible(True)
            self.swap_btn.setVisible(False)
        elif self.current_algorithm == "SM4":
            self.encrypt_btn.setVisible(True)
            self.decrypt_btn.setVisible(True)
            self.hash_btn.setVisible(False)
            self.swap_btn.setVisible(True)
        else:
            self.output_format.setVisible(False)
            self.encrypt_btn.setVisible(False)
            self.decrypt_btn.setVisible(False)
            self.hash_btn.setVisible(False)
            self.clear_btn.setVisible(False)
            self.swap_btn.setVisible(False)

    def update_output_formats(self):
        """根据当前算法更新输出格式选项"""
        current_format = self.output_format.currentText()
        self.output_format.clear()

        if self.current_algorithm == "SM3":
            # SM3只支持HEX和Base64
            self.output_format.addItems(["HEX", "Base64"])
        else:
            # SM2和SM4支持所有格式
            self.output_format.addItems(["HEX", "Base64", "UTF-8"])

        # 尝试恢复之前选择的格式
        index = self.output_format.findText(current_format)
        if index >= 0:
            self.output_format.setCurrentIndex(index)

    def update_iv_visibility(self):
        """根据加密模式显示或隐藏IV设置"""
        is_cbc = self.sm4_mode.currentText() == "CBC"

        # 显示或隐藏IV相关控件
        for i in range(self.iv_grid.count()):
            item = self.iv_grid.itemAt(i)
            if item.widget():
                item.widget().setVisible(is_cbc)

    # SM2加密相关方法
    def encrypt_sm2_text(self):
        """SM2加密文本"""
        text = self.sm2_encrypt_input_text.toPlainText().strip()
        public_key = self.sm2_encrypt_pub_key.toPlainText().strip().replace(" ", "").upper()
        output_format = self.output_format.currentText()

        if not text:
            QMessageBox.warning(self, "警告", "请输入需要加密的文本")
            return
        if not public_key:
            QMessageBox.warning(self, "警告", "请输入公钥")
            return

        # 验证公钥长度
        if len(public_key) not in [SM2_PUB_KEY_LEN_1, SM2_PUB_KEY_LEN_2]:
            QMessageBox.warning(self, "警告",
                               f"公钥长度无效，应为{SM2_PUB_KEY_LEN_1}位或{SM2_PUB_KEY_LEN_2}位（带04前缀）")
            return

        self.statusBar().showMessage("正在进行SM2加密...")
        self.encrypt_btn.setEnabled(False)

        self.sm2_thread = CryptoThread(
            SM2Tool.encrypt_text, False, text, public_key, output_format)
        self.sm2_thread.finished.connect(self.on_text_operation_finished)
        self.sm2_thread.error.connect(self.on_crypto_error)
        self.sm2_thread.start()

    def encrypt_sm2_file(self):
        """SM2加密文件"""
        input_path = self.sm2_encrypt_input_file.text()
        output_dir = self.sm2_encrypt_output_dir.text()
        public_key = self.sm2_encrypt_pub_key.toPlainText().strip().replace(" ", "").upper()

        # 自动生成输出文件路径
        output_path = self.get_auto_output_path(input_path, output_dir, True)

        if not input_path or not os.path.exists(input_path):
            QMessageBox.warning(self, "警告", "请选择有效的输入文件")
            return
        if not output_dir or not os.path.isdir(output_dir):
            QMessageBox.warning(self, "警告", "请选择有效的输出目录")
            return
        if not output_path:
            QMessageBox.warning(self, "警告", "无法生成输出文件路径")
            return
        if not public_key or len(public_key) not in [SM2_PUB_KEY_LEN_1, SM2_PUB_KEY_LEN_2]:
            QMessageBox.warning(self, "警告",
                               f"请输入有效的{SM2_PUB_KEY_LEN_1}或{SM2_PUB_KEY_LEN_2}字符公钥")
            return

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "确认", f"文件 {output_path} 已存在，是否覆盖？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        self.statusBar().showMessage("正在加密文件...")
        self.encrypt_btn.setEnabled(False)

        self.sm2_file_thread = CryptoThread(
            SM2Tool.encrypt_file, True, input_path, output_path, public_key)
        self.sm2_file_thread.file_finished.connect(lambda: self.on_file_operation_finished(True, output_path))
        self.sm2_file_thread.error.connect(self.on_crypto_error)
        self.sm2_file_thread.start()

    # SM2解密相关方法
    def decrypt_sm2_text(self):
        """SM2解密文本"""
        text = self.sm2_decrypt_input_text.toPlainText().strip()
        private_key = self.sm2_decrypt_pri_key.toPlainText().strip().replace(" ", "").upper()
        output_format = self.output_format.currentText()

        if not text:
            QMessageBox.warning(self, "警告", "请输入需要解密的文本")
            return
        if not private_key:
            QMessageBox.warning(self, "警告", "请输入私钥")
            return
        if len(private_key) != SM2_PRIV_KEY_LEN:
            QMessageBox.warning(self, "警告", f"私钥必须是{SM2_PRIV_KEY_LEN}字符的十六进制字符串")
            return

        self.statusBar().showMessage("正在进行SM2解密...")
        self.decrypt_btn.setEnabled(False)

        self.sm2_thread = CryptoThread(
            SM2Tool.decrypt_text, False, text, private_key, output_format)
        self.sm2_thread.finished.connect(self.on_text_operation_finished)
        self.sm2_thread.error.connect(self.on_crypto_error)
        self.sm2_thread.start()

    def decrypt_sm2_file(self):
        """SM2解密文件"""
        input_path = self.sm2_decrypt_input_file.text()
        output_dir = self.sm2_decrypt_output_dir.text()
        private_key = self.sm2_decrypt_pri_key.toPlainText().strip().replace(" ", "").upper()

        # 自动生成输出文件路径
        output_path = self.get_auto_output_path(input_path, output_dir, False)

        if not input_path or not os.path.exists(input_path):
            QMessageBox.warning(self, "警告", "请选择有效的输入文件")
            return
        if not output_dir or not os.path.isdir(output_dir):
            QMessageBox.warning(self, "警告", "请选择有效的输出目录")
            return
        if not output_path:
            QMessageBox.warning(self, "警告", "无法生成输出文件路径")
            return
        if not private_key or len(private_key) != SM2_PRIV_KEY_LEN:
            QMessageBox.warning(self, "警告", f"请输入有效的{SM2_PRIV_KEY_LEN}字符私钥")
            return

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "确认", f"文件 {output_path} 已存在，是否覆盖？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        self.statusBar().showMessage("正在解密文件...")
        self.decrypt_btn.setEnabled(False)

        self.sm2_file_thread = CryptoThread(
            SM2Tool.decrypt_file, True, input_path, output_path, private_key)
        self.sm2_file_thread.file_finished.connect(lambda: self.on_file_operation_finished(False, output_path))
        self.sm2_file_thread.error.connect(self.on_crypto_error)
        self.sm2_file_thread.start()

    # SM3相关方法
    def calculate_sm3_text(self):
        """计算文本的SM3哈希"""
        text = self.sm3_input_text.toPlainText().strip()
        output_format = self.output_format.currentText()

        if not text:
            QMessageBox.warning(self, "警告", "请输入需要计算哈希的文本")
            return

        self.statusBar().showMessage("正在计算SM3哈希...")
        self.hash_btn.setEnabled(False)

        self.sm3_thread = CryptoThread(
            SM3Tool.hash_text, False, text, output_format)
        self.sm3_thread.finished.connect(self.on_text_operation_finished)
        self.sm3_thread.error.connect(self.on_crypto_error)
        self.sm3_thread.start()

    def calculate_sm3_file(self):
        """计算文件的SM3哈希"""
        file_path = self.sm3_input_file.text()
        output_format = self.output_format.currentText()

        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "警告", "请选择有效的文件")
            return

        self.statusBar().showMessage("正在计算文件SM3哈希...")
        self.hash_btn.setEnabled(False)

        self.sm3_file_thread = CryptoThread(
            SM3Tool.hash_file, False, file_path, output_format)
        self.sm3_file_thread.finished.connect(self.on_text_operation_finished)
        self.sm3_file_thread.error.connect(self.on_crypto_error)
        self.sm3_file_thread.start()

    # SM4相关方法
    def generate_sm4_key(self):
        """生成SM4密钥"""
        key = SM4Tool.generate_key()
        self.sm4_key.setText(key)

    def generate_sm4_iv(self):
        """生成IV向量"""
        iv = SM4Tool.generate_iv()
        self.sm4_iv.setText(iv)

    def encrypt_sm4_text(self):
        """SM4加密文本"""
        text = self.sm4_input_text.toPlainText().strip()
        key = self.sm4_key.text().strip()
        key_format = self.sm4_key_format.currentText()
        mode = self.sm4_mode.currentText()
        output_format = self.output_format.currentText()

        iv = self.sm4_iv.text().strip() if mode == "CBC" else None
        iv_format = self.sm4_iv_format.currentText() if mode == "CBC" else None

        if not text:
            QMessageBox.warning(self, "警告", "请输入需要加密的文本")
            return
        if not key:
            QMessageBox.warning(self, "警告", "请输入密钥")
            return
        if mode == "CBC" and not iv:
            QMessageBox.warning(self, "警告", "CBC模式必须输入IV向量")
            return

        self.statusBar().showMessage("正在进行SM4加密...")
        self.encrypt_btn.setEnabled(False)

        self.sm4_thread = CryptoThread(
            SM4Tool.encrypt_text, False, text, key, key_format,
            iv, iv_format, output_format, sm4.SM4_ENCRYPT)
        self.sm4_thread.finished.connect(self.on_text_operation_finished)
        self.sm4_thread.error.connect(self.on_crypto_error)
        self.sm4_thread.start()

    def decrypt_sm4_text(self):
        """SM4解密文本"""
        text = self.sm4_input_text.toPlainText().strip()
        key = self.sm4_key.text().strip()
        key_format = self.sm4_key_format.currentText()
        mode = self.sm4_mode.currentText()
        output_format = self.output_format.currentText()

        iv = self.sm4_iv.text().strip() if mode == "CBC" else None
        iv_format = self.sm4_iv_format.currentText() if mode == "CBC" else None

        if not text:
            QMessageBox.warning(self, "警告", "请输入需要解密的文本")
            return
        if not key:
            QMessageBox.warning(self, "警告", "请输入密钥")
            return
        if mode == "CBC" and not iv:
            QMessageBox.warning(self, "警告", "CBC模式必须输入IV向量")
            return

        self.statusBar().showMessage("正在进行SM4解密...")
        self.decrypt_btn.setEnabled(False)

        self.sm4_thread = CryptoThread(
            SM4Tool.decrypt_text, False, text, key, key_format,
            iv, iv_format, "HEX" if output_format == "HEX" else "Base64", output_format)
        self.sm4_thread.finished.connect(self.on_text_operation_finished)
        self.sm4_thread.error.connect(self.on_crypto_error)
        self.sm4_thread.start()

    def encrypt_sm4_file(self):
        """SM4加密文件"""
        input_path = self.sm4_input_file.text()
        output_dir = self.sm4_output_dir.text()
        key = self.sm4_key.text().strip()
        key_format = self.sm4_key_format.currentText()
        mode = self.sm4_mode.currentText()

        iv = self.sm4_iv.text().strip() if mode == "CBC" else None
        iv_format = self.sm4_iv_format.currentText() if mode == "CBC" else None

        # 自动生成输出文件路径
        output_path = self.get_auto_output_path(input_path, output_dir, True)

        if not input_path or not os.path.exists(input_path):
            QMessageBox.warning(self, "警告", "请选择有效的输入文件")
            return
        if not output_dir or not os.path.isdir(output_dir):
            QMessageBox.warning(self, "警告", "请选择有效的输出目录")
            return
        if not output_path:
            QMessageBox.warning(self, "警告", "无法生成输出文件路径")
            return
        if not key:
            QMessageBox.warning(self, "警告", "请输入密钥")
            return
        if mode == "CBC" and not iv:
            QMessageBox.warning(self, "警告", "CBC模式必须输入IV向量")
            return

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "确认", f"文件 {output_path} 已存在，是否覆盖？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        self.statusBar().showMessage("正在加密文件...")
        self.encrypt_btn.setEnabled(False)

        self.sm4_file_thread = CryptoThread(
            SM4Tool.encrypt_file_sm4, True, input_path, output_path,
            key, key_format, iv, iv_format, sm4.SM4_ENCRYPT)
        self.sm4_file_thread.file_finished.connect(lambda: self.on_file_operation_finished(True, output_path))
        self.sm4_file_thread.error.connect(self.on_crypto_error)
        self.sm4_file_thread.start()

    def decrypt_sm4_file(self):
        """SM4解密文件"""
        input_path = self.sm4_input_file.text()
        output_dir = self.sm4_output_dir.text()
        key = self.sm4_key.text().strip()
        key_format = self.sm4_key_format.currentText()

        # 自动生成输出文件路径
        output_path = self.get_auto_output_path(input_path, output_dir, False)

        if not input_path or not os.path.exists(input_path):
            QMessageBox.warning(self, "警告", "请选择有效的输入文件")
            return
        if not output_dir or not os.path.isdir(output_dir):
            QMessageBox.warning(self, "警告", "请选择有效的输出目录")
            return
        if not output_path:
            QMessageBox.warning(self, "警告", "无法生成输出文件路径")
            return
        if not key:
            QMessageBox.warning(self, "警告", "请输入密钥")
            return

        if os.path.exists(output_path):
            reply = QMessageBox.question(self, "确认", f"文件 {output_path} 已存在，是否覆盖？",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        self.statusBar().showMessage("正在解密文件...")
        self.decrypt_btn.setEnabled(False)

        self.sm4_file_thread = CryptoThread(
            SM4Tool.decrypt_file_sm4, True, input_path, output_path, key, key_format)
        self.sm4_file_thread.file_finished.connect(lambda: self.on_file_operation_finished(False, output_path))
        self.sm4_file_thread.error.connect(self.on_crypto_error)
        self.sm4_file_thread.start()

    # 通用操作方法
    def get_auto_output_path(self, input_path, output_dir, is_encrypt):
        """根据输入文件路径、输出目录和操作类型自动生成输出文件路径"""
        if not input_path or not output_dir:
            return None

        # 获取文件名和扩展名
        file_name = os.path.basename(input_path)
        name, ext = os.path.splitext(file_name)

        # 根据操作类型添加后缀
        if is_encrypt:
            new_name = f"{name}_enc{ext}"
        else:
            new_name = f"{name}_decrypted{ext}"

        # 组合完整路径
        return os.path.join(output_dir, new_name)

    def encrypt_action(self):
        """加密操作入口"""
        if self.current_algorithm == "SM2加密":
            if self.sm2_encrypt_input_file.text().strip():
                self.encrypt_sm2_file()
            else:
                self.encrypt_sm2_text()
        elif self.current_algorithm == "SM4":
            if self.sm4_input_file.text().strip():
                self.encrypt_sm4_file()
            else:
                self.encrypt_sm4_text()

    def decrypt_action(self):
        """解密操作入口"""
        if self.current_algorithm == "SM2解密":
            if self.sm2_decrypt_input_file.text().strip():
                self.decrypt_sm2_file()
            else:
                self.decrypt_sm2_text()
        elif self.current_algorithm == "SM4":
            if self.sm4_input_file.text().strip():
                self.decrypt_sm4_file()
            else:
                self.decrypt_sm4_text()

    def hash_action(self):
        """哈希计算入口"""
        if self.current_algorithm == "SM3":
            if self.sm3_input_file.text().strip():
                self.calculate_sm3_file()
            else:
                self.calculate_sm3_text()

    def swap_action(self):
        """互换输入输出内容"""
        if self.current_algorithm == "SM2加密":
            input_text = self.sm2_encrypt_input_text.toPlainText()
            output_text = self.sm2_encrypt_output_text.toPlainText()
            self.sm2_encrypt_input_text.setPlainText(output_text)
            self.sm2_encrypt_output_text.setPlainText(input_text)
        elif self.current_algorithm == "SM2解密":
            input_text = self.sm2_decrypt_input_text.toPlainText()
            output_text = self.sm2_decrypt_output_text.toPlainText()
            self.sm2_decrypt_input_text.setPlainText(output_text)
            self.sm2_decrypt_output_text.setPlainText(input_text)
        elif self.current_algorithm == "SM4":
            input_text = self.sm4_input_text.toPlainText()
            output_text = self.sm4_output_text.toPlainText()
            self.sm4_input_text.setPlainText(output_text)
            self.sm4_output_text.setPlainText(input_text)

        self.statusBar().showMessage("已互换输入输出内容")

    def copy_result(self):
        """复制结果到剪贴板"""
        result = ''
        if self.current_algorithm == "SM2加密":
            result = self.sm2_encrypt_output_text.toPlainText().strip()
        elif self.current_algorithm == "SM2解密":
            result = self.sm2_decrypt_output_text.toPlainText().strip()
        elif self.current_algorithm == "SM3":
            result = self.sm3_encrypt_output_text.toPlainText().strip()
        elif self.current_algorithm == "SM4":
            result = self.sm4_output_text.toPlainText().strip()

        if result:
            clipboard = QApplication.clipboard()
            clipboard.setText(result)
            self.statusBar().showMessage("已复制结果到剪贴板")
        else:
            self.statusBar().showMessage("没有可复制的内容")

    def clear_all(self):
        """清空所有输入输出内容"""
        if self.current_algorithm == "SM2加密":
            self.sm2_encrypt_input_text.clear()
            self.sm2_encrypt_input_file.clear()
            self.sm2_encrypt_output_dir.clear()
            self.sm2_encrypt_output_text.clear()
            self.sm2_encrypt_pub_key.clear()
        elif self.current_algorithm == "SM2解密":
            self.sm2_decrypt_input_text.clear()
            self.sm2_decrypt_input_file.clear()
            self.sm2_decrypt_output_dir.clear()
            self.sm2_encrypt_output_text.clear()
            self.sm2_decrypt_pri_key.clear()
        elif self.current_algorithm == "SM3":
            self.sm3_input_text.clear()
            self.sm3_encrypt_output_text.clear()
            self.sm3_input_file.clear()
        elif self.current_algorithm == "SM4":
            self.sm4_input_text.clear()
            self.sm4_input_file.clear()
            self.sm4_output_dir.clear()
            self.sm4_output_text.clear()
            # self.sm4_key.clear()
            # self.sm4_iv.clear()


        self.statusBar().showMessage("已清空所有内容")

    def browse_file(self, line_edit):
        """浏览选择文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")

        if file_path:
            line_edit.setText(file_path)
            # 清空文本输入框
            if self.current_algorithm == "SM2加密":
                self.sm2_encrypt_input_text.clear()
            elif self.current_algorithm == "SM2解密":
                self.sm2_decrypt_input_text.clear()
            elif self.current_algorithm == "SM3":
                self.sm3_input_text.clear()
            elif self.current_algorithm == "SM4":
                self.sm4_input_text.clear()

    def browse_directory(self, line_edit):
        """浏览选择目录"""
        dir_path = QFileDialog.getExistingDirectory(self, "选择输出目录", "")
        if dir_path:
            line_edit.setText(dir_path)

    def on_text_operation_finished(self, result):
        """文本操作完成回调"""
        if self.current_algorithm == "SM2加密":
            self.sm2_encrypt_output_text.setPlainText(result)
        elif self.current_algorithm == "SM2解密":
            self.sm2_decrypt_output_text.setPlainText(result)
        elif self.current_algorithm == "SM3":
            self.sm3_encrypt_output_text.setPlainText(result)
        elif self.current_algorithm == "SM4":
            self.sm4_output_text.setPlainText(result)

        if self.current_algorithm in ["SM2加密", "SM2解密"]:
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)
            self.statusBar().showMessage(f"{self.current_algorithm}文本操作完成")
        elif self.current_algorithm == "SM3":
            self.hash_btn.setEnabled(True)
            self.statusBar().showMessage("SM3哈希计算完成")
        elif self.current_algorithm == "SM4":
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)
            self.statusBar().showMessage("SM4文本操作完成")

    def on_file_operation_finished(self, is_encrypt, output_path):
        """文件操作完成回调"""
        action = "加密" if is_encrypt else "解密"
        algorithm = self.current_algorithm

        if algorithm.startswith("SM2") or algorithm == "SM4":
            self.encrypt_btn.setEnabled(True)
            self.decrypt_btn.setEnabled(True)

        self.statusBar().showMessage(f"{algorithm}文件{action}完成")
        QMessageBox.information(self, "完成", f"{algorithm}文件{action}成功！\n保存路径: {output_path}")

    def on_crypto_error(self, error_msg):
        """处理加密解密错误"""
        QMessageBox.critical(self, "操作失败", f"错误详情:\n{error_msg}")
        self.statusBar().showMessage("操作失败: " + error_msg.split('\n')[0])

        # 重新启用按钮
        self.encrypt_btn.setEnabled(True)
        self.decrypt_btn.setEnabled(True)
        self.hash_btn.setEnabled(True)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = GMCryptoTool()
    window.show()
    sys.exit(app.exec())
