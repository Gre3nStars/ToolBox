import binascii
import sys
import hashlib
import base64
import os
import time
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QLineEdit, QTableWidget,
                             QTableWidgetItem, QHeaderView, QComboBox, QFrame,
                             QSplitter, QScrollArea, QTextEdit, QPushButton,
                             QMenu, QMessageBox, QFileDialog, QProgressBar,
                             QGroupBox, QCheckBox, QRadioButton, QButtonGroup, QTabWidget,
                             QListWidget, QListWidgetItem, QFileIconProvider, QTreeWidget,
                             QTreeWidgetItem)
from PySide6.QtCore import Qt, Signal, QObject, QThread, QMimeData
from PySide6.QtGui import QFont, QColor, QDragEnterEvent, QDropEvent, QIcon

import binascii
import mimetypes
import os
from typing import Tuple, Optional, List


class FileTypeDetector:
    """文件类型检测器，使用魔数和文件结构分析"""

    # 常见文件类型的魔数签名 (扩展版本)
    MAGIC_NUMBERS = {
        # 图片格式
        b'\xFF\xD8\xFF': ('image/jpeg', 'JPEG Image'),
        b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A': ('image/png', 'PNG Image'),
        b'\x47\x49\x46\x38\x37\x61': ('image/gif', 'GIF Image (v87a)'),
        b'\x47\x49\x46\x38\x39\x61': ('image/gif', 'GIF Image (v89a)'),
        b'\x42\x4D': ('image/bmp', 'BMP Image'),
        b'\x49\x49\x2A\x00': ('image/tiff', 'TIFF Image (Little Endian)'),
        b'\x4D\x4D\x00\x2A': ('image/tiff', 'TIFF Image (Big Endian)'),
        b'\x00\x00\x01\x00': ('image/x-icon', 'ICO Image'),
        b'\x52\x49\x46\x46': ('image/webp', 'WebP Image'),  # RIFF header
        b'\x52\x49\x46\x46....\x57\x45\x42\x50': ('image/webp', 'WebP Image'),  # Full signature

        # 视频格式
        b'\x00\x00\x00\x14\x66\x74\x79\x70': ('video/mp4', 'MP4 Video'),
        b'\x46\x4C\x56\x01': ('video/flv', 'FLV Video'),
        b'\x52\x49\x46\x46....\x57\x41\x56\x45': ('video/x-msvideo', 'AVI Video'),
        b'\x1A\x45\xDF\xA3': ('video/webm', 'WebM Video'),
        b'\x00\x00\x01\xBA': ('video/mpeg', 'MPEG Video'),
        b'\x00\x00\x01\xB3': ('video/mpeg', 'MPEG Video'),

        # 音频格式
        b'\x49\x44\x33': ('audio/mpeg', 'MP3 Audio'),
        b'\x52\x49\x46\x46....\x57\x41\x56\x45': ('audio/wav', 'WAV Audio'),
        b'\x4F\x67\x67\x53': ('audio/ogg', 'OGG Audio'),
        b'\x2E\x73\x6E\x64': ('audio/basic', 'AU Audio'),
        b'\x4D\x54\x68\x64': ('audio/midi', 'MIDI Audio'),
        b'\x46\x52\x4D\x41': ('audio/amr', 'AMR Audio'),
        b'\x23\x21': ('audio/x-mpegurl', 'M3U Playlist'),

        # 文档格式
        b'\x25\x50\x44\x46': ('application/pdf', 'PDF Document'),
        b'\x50\x4B\x03\x04\x14\x00\x06\x00': ('application/msword', 'DOC Document'),
        b'\x50\x4B\x03\x04\x14\x00\x08\x00': (
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'DOCX Document'),
        b'\x50\x4B\x03\x04\x14\x00\x06\x00\x08\x00': (
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'XLSX Spreadsheet'),
        b'\x50\x4B\x03\x04\x14\x00\x06\x00\x08\x00\x00\x00': (
        'application/vnd.openxmlformats-officedocument.presentationml.presentation', 'PPTX Presentation'),
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': ('application/vnd.ms-excel', 'XLS Spreadsheet'),
        b'\x3C\x3F\x78\x6D\x6C\x20': ('application/xml', 'XML Document'),
        b'\x3C\x68\x74\x6D\x6C\x3E': ('text/html', 'HTML Document'),

        # 压缩格式
        b'\x50\x4B\x03\x04': ('application/zip', 'ZIP Archive'),
        b'\x50\x4B\x05\x06': ('application/zip', 'ZIP Archive (Empty)'),
        b'\x50\x4B\x07\x08': ('application/zip', 'ZIP Archive (Spanned)'),
        b'\x1F\x8B\x08': ('application/gzip', 'GZIP Compressed File'),
        b'\x52\x61\x72\x21\x1A\x07\x00': ('application/x-rar-compressed', 'RAR Archive'),
        b'\x42\x5A\x68': ('application/x-bzip2', 'BZ2 Compressed File'),
        b'\x75\x73\x74\x61\x72': ('application/x-tar', 'TAR Archive'),
        b'\x37\x7A\xBC\xAF\x27\x1C': ('application/x-7z-compressed', '7-Zip Archive'),

        # 可执行文件
        b'\x4D\x5A': ('application/x-dosexec', 'DOS/Windows Executable (EXE/DLL)'),
        b'\x7F\x45\x4C\x46': ('application/x-executable', 'ELF Executable (Linux/Unix)'),
        b'\xCA\xFE\xBA\xBE': ('application/x-java-applet', 'Java Class (Big Endian)'),
        b'\xBE\xBA\xFE\xCA': ('application/x-java-applet', 'Java Class (Little Endian)'),
        b'\x4D\x5A\x90\x00': ('application/x-msdownload', 'Windows PE Executable'),
        b'\x23\x21\x2F\x62\x69\x6E\x2F\x73\x68': ('application/x-sh', 'Bash Script'),
        b'\x23\x21\x2F\x75\x73\x72\x2F\x62\x69\x6E\x2F\x70\x68\x70': ('application/x-php', 'PHP Script'),
        b'\x23\x21\x2F\x75\x73\x72\x2F\x62\x69\x6E\x2F\x70\x79\x74\x68\x6F\x6E': (
        'application/x-python', 'Python Script'),
        b'\x23\x21\x2F\x75\x73\x72\x2F\x62\x69\x6E\x2F\x65\x6E\x76\x20\x70\x79\x74\x68\x6F\x6E': (
        'application/x-python', 'Python Script'),
        b'\x23\x21\x2F\x75\x73\x72\x2F\x62\x69\x6E\x2F\x65\x6E\x76\x20\x6A\x73': (
        'application/javascript', 'Node.js Script'),

        # 数据库
        b'\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00': (
        'application/x-sqlite3', 'SQLite Database'),
        b'\x49\x54\x53\x46': ('application/x-ittf', 'InterBase/Firebird Database'),
        b'\x00\x06\x1A\x0A': ('application/x-mysql', 'MySQL Dump'),

        # 字体
        b'\x00\x01\x00\x00\x00': ('application/font-ttf', 'TrueType Font'),
        b'\x4F\x54\x54\x4F': ('application/font-otf', 'OpenType Font'),
        b'\x77\x4F\x46\x46': ('application/font-woff', 'WOFF Font'),
        b'\x77\x4F\x46\x46\x32\x00': ('application/font-woff2', 'WOFF2 Font'),

        # 其他文件类型
        b'\x49\x4E\x49\x54': ('application/x-msi', 'Windows Installer Package'),
        b'\x42\x4D': ('image/bmp', 'BMP Image'),
        b'\x4D\x4F\x5A\x49\x4C\x4C\x41': ('application/x-mozilla', 'Mozilla Archive'),
        b'\x46\x4F\x52\x4D': ('application/x-iso9660-image', 'ISO Image'),
        b'\x49\x4E\x46\x4F': ('text/plain', 'INFO File'),
        b'\x53\x43\x52\x49\x50\x54': ('application/x-script', 'Windows Script File'),
        b'\x4D\x4D\x4D\x4D': ('application/x-mmf', 'MultiMedia File'),
        b'\x50\x4B\x03\x04\x14\x00\x00\x08': ('application/vnd.oasis.opendocument.text', 'ODT Document'),
        b'\x50\x4B\x03\x04\x14\x00\x00\x06': ('application/vnd.oasis.opendocument.spreadsheet', 'ODS Spreadsheet'),
        b'\x50\x4B\x03\x04\x14\x00\x00\x05': ('application/vnd.oasis.opendocument.presentation', 'ODP Presentation'),
        b'\x23\x20\x50\x79\x74\x68\x6F\x6E\x20\x43\x6F\x6D\x6D\x65\x6E\x74': ('text/x-python', 'Python Source Code'),
        b'\xEF\xBB\xBF\x23\x20\x4A\x61\x76\x61\x53\x63\x72\x69\x70\x74': (
        'application/javascript', 'JavaScript Source Code'),
    }

    @staticmethod
    def get_file_magic(file_path: str, bytes_to_read: int = 32) -> bytes:
        """读取文件的魔数签名

        Args:
            file_path: 文件路径
            bytes_to_read: 读取的字节数，默认为32字节

        Returns:
            文件的魔数签名字节
        """
        try:
            with open(file_path, 'rb') as f:
                return f.read(bytes_to_read)
        except Exception as e:
            print(f"读取文件失败: {e}")
            return b''

    @staticmethod
    def detect_from_bytes(file_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
        """从文件字节中检测文件类型

        Args:
            file_bytes: 文件的字节数据

        Returns:
            元组 (MIME类型, 文件类型描述)，如果未找到匹配则返回 (None, None)
        """
        # 检查是否有精确匹配的魔数
        for magic, (mime, description) in FileTypeDetector.MAGIC_NUMBERS.items():
            # 处理包含通配符的魔数
            if b'....' in magic:
                parts = magic.split(b'....')
                if len(parts) == 2 and parts[0] == file_bytes[:len(parts[0])] and \
                        parts[1] == file_bytes[len(file_bytes) - len(parts[1]):]:
                    return mime, description
            # 处理普通魔数
            elif file_bytes.startswith(magic):
                return mime, description

        # 如果没有找到匹配，尝试基于扩展名猜测
        return None, None

    @staticmethod
    def detect_from_file(file_path: str) -> Tuple[Optional[str], Optional[str]]:
        """从文件路径检测文件类型

        Args:
            file_path: 文件路径

        Returns:
            元组 (MIME类型, 文件类型描述)，如果未找到匹配则返回 (None, None)
        """
        # 读取文件魔数
        file_magic = FileTypeDetector.get_file_magic(file_path)

        # 首先尝试通过魔数检测
        mime, description = FileTypeDetector.detect_from_bytes(file_magic)

        # 如果魔数检测失败，尝试通过文件扩展名
        if mime is None and os.path.exists(file_path):
            ext = os.path.splitext(file_path)[1].lower()
            if ext:
                mime = mimetypes.guess_type(file_path)[0]
                if mime:
                    description = mime.split('/')[1].upper() + " File"

        return mime, description

    @staticmethod
    def is_image(file_path: str) -> bool:
        """检查文件是否为图片

        Args:
            file_path: 文件路径

        Returns:
            如果是图片返回True，否则返回False
        """
        mime, _ = FileTypeDetector.detect_from_file(file_path)
        return mime is not None and mime.startswith('image/')

    @staticmethod
    def is_video(file_path: str) -> bool:
        """检查文件是否为视频

        Args:
            file_path: 文件路径

        Returns:
            如果是视频返回True，否则返回False
        """
        mime, _ = FileTypeDetector.detect_from_file(file_path)
        return mime is not None and mime.startswith('video/')

    @staticmethod
    def is_audio(file_path: str) -> bool:
        """检查文件是否为音频

        Args:
            file_path: 文件路径

        Returns:
            如果是音频返回True，否则返回False
        """
        mime, _ = FileTypeDetector.detect_from_file(file_path)
        return mime is not None and mime.startswith('audio/')

    @staticmethod
    def is_archive(file_path: str) -> bool:
        """检查文件是否为压缩文件

        Args:
            file_path: 文件路径

        Returns:
            如果是压缩文件返回True，否则返回False
        """
        mime, _ = FileTypeDetector.detect_from_file(file_path)
        return mime is not None and (
                'zip' in mime or 'rar' in mime or 'gz' in mime or
                '7z' in mime or 'tar' in mime or 'bz2' in mime
        )

    @staticmethod
    def is_executable(file_path: str) -> bool:
        """检查文件是否为可执行文件

        Args:
            file_path: 文件路径

        Returns:
            如果是可执行文件返回True，否则返回False
        """
        mime, _ = FileTypeDetector.detect_from_file(file_path)
        return mime is not None and (
                'executable' in mime or 'dosexec' in mime or
                'java' in mime or 'script' in mime
        )

# md5爆破
# class MD5CrackerThread(QThread):
#     """MD5爆破线程，用于在后台执行MD5爆破任务"""
#
#     progress_updated = pyqtSignal(int, str)  # 进度更新 (当前进度, 当前尝试)
#     crack_completed = pyqtSignal(bool, str)  # 爆破完成 (是否成功, 结果)
#     status_updated = pyqtSignal(str)  # 状态更新
#
#     def __init__(self, md5_hash, wordlist_path=None, charset="abcdefghijklmnopqrstuvwxyz0123456789", min_length=1,
#                  max_length=6):
#         super().__init__()
#         self.md5_hash = md5_hash.lower()  # 转为小写以匹配标准MD5格式
#         self.wordlist_path = wordlist_path
#         self.charset = charset
#         self.min_length = min_length
#         self.max_length = max_length
#         self.stopped = False
#         self.total_attempts = 0
#         self.current_attempt = 0
#
#     def run(self):
#         """执行MD5爆破任务"""
#         self.status_updated.emit("开始爆破...")
#
#         if self.wordlist_path:
#             # 使用字典文件爆破
#             self.crack_with_wordlist()
#         else:
#             # 使用字符集生成所有可能组合进行爆破
#             self.crack_with_charset()
#
#         if not self.stopped:
#             self.crack_completed.emit(False, "未能找到匹配的明文")
#
#     def crack_with_wordlist(self):
#         """使用字典文件进行爆破"""
#         if not os.path.exists(self.wordlist_path):
#             self.crack_completed.emit(False, f"错误: 字典文件 '{self.wordlist_path}' 不存在")
#             return
#
#         try:
#             total_lines = sum(1 for _ in open(self.wordlist_path, 'r', errors='ignore'))
#             self.total_attempts = total_lines
#             self.current_attempt = 0
#
#             with open(self.wordlist_path, 'r', errors='ignore') as f:
#                 for line in f:
#                     if self.stopped:
#                         return
#
#                     self.current_attempt += 1
#                     password = line.strip()
#                     hash_attempt = hashlib.md5(password.encode('utf-8')).hexdigest()
#
#                     # 更新进度
#                     progress = int((self.current_attempt / self.total_attempts) * 100)
#                     self.progress_updated.emit(progress, password)
#
#                     if hash_attempt == self.md5_hash:
#                         self.crack_completed.emit(True, password)
#                         return
#
#                     # 每1000次尝试更新一次状态，避免UI过载
#                     if self.current_attempt % 1000 == 0:
#                         self.status_updated.emit(f"正在尝试: {password}")
#
#         except Exception as e:
#             self.crack_completed.emit(False, f"错误: 执行爆破时出错 - {str(e)}")
#
#     def crack_with_charset(self):
#         """使用字符集生成所有可能组合进行爆破"""
#         from itertools import product
#
#         # 计算总尝试次数（近似值）
#         self.total_attempts = 0
#         for length in range(self.min_length, self.max_length + 1):
#             self.total_attempts += len(self.charset) ** length
#
#         self.current_attempt = 0
#
#         for length in range(self.min_length, self.max_length + 1):
#             if self.stopped:
#                 return
#
#             # 使用itertools.product生成所有可能的组合
#             for combination in product(self.charset, repeat=length):
#                 if self.stopped:
#                     return
#
#                 self.current_attempt += 1
#                 password = ''.join(combination)
#                 hash_attempt = hashlib.md5(password.encode('utf-8')).hexdigest()
#
#                 # 更新进度
#                 progress = int((self.current_attempt / self.total_attempts) * 100)
#                 self.progress_updated.emit(progress, password)
#
#                 if hash_attempt == self.md5_hash:
#                     self.crack_completed.emit(True, password)
#                     return
#
#                 # 每1000次尝试更新一次状态，避免UI过载
#                 if self.current_attempt % 1000 == 0:
#                     self.status_updated.emit(f"正在尝试: {password}")
#
#     def stop(self):
#         """停止爆破任务"""
#         self.stopped = True
#         self.wait()


class Encryptor:
    """加密工具类，包含所有支持的加密算法"""

    @staticmethod
    def md5(text: str) -> str:
        return hashlib.md5(text.encode('utf-8')).hexdigest()

    @staticmethod
    def md5_16(text: str) -> str:
        return Encryptor.md5(text)[8:24]

    @staticmethod
    def md5_double(text: str) -> str:
        return Encryptor.md5(Encryptor.md5(text))

    @staticmethod
    def md5_triple(text: str) -> str:
        return Encryptor.md5(Encryptor.md5(Encryptor.md5(text)))

    @staticmethod
    def md5_double_with_salt(text: str, salt: str) -> str:
        return Encryptor.md5(Encryptor.md5(text) + salt)

    @staticmethod
    def md5_sha1(text: str) -> str:
        sha1_hash = hashlib.sha1(text.encode('utf-8')).hexdigest()
        return Encryptor.md5(sha1_hash)

    @staticmethod
    def md5_pass_salt(text: str, salt: str) -> str:
        return Encryptor.md5(text + salt)

    @staticmethod
    def md5_salt_pass(text: str, salt: str) -> str:
        return Encryptor.md5(salt + text)

    @staticmethod
    def md5_salt_pass_salt(text: str, salt: str) -> str:
        return Encryptor.md5(salt + text + salt)

    @staticmethod
    def md5_salt_md5pass(text: str, salt: str) -> str:
        return Encryptor.md5(salt + Encryptor.md5(text))

    @staticmethod
    def md5_md5salt_pass(text: str, salt: str) -> str:
        return Encryptor.md5(Encryptor.md5(salt) + text)

    @staticmethod
    def md5_pass_md5salt(text: str, salt: str) -> str:
        return Encryptor.md5(text + Encryptor.md5(salt))

    @staticmethod
    def md5_md5salt_md5pass(text: str, salt: str) -> str:
        return Encryptor.md5(Encryptor.md5(salt) + Encryptor.md5(text))

    @staticmethod
    def md5_md5pass_md5salt(text: str, salt: str) -> str:
        return Encryptor.md5(Encryptor.md5(text) + Encryptor.md5(salt))

    @staticmethod
    def md5_substring(text: str) -> str:
        full_md5 = Encryptor.md5(text)
        return Encryptor.md5(full_md5[8:24])

    @staticmethod
    def md5_base64(text: str) -> str:
        encoded = base64.b64encode(text.encode('utf-8')).decode('utf-8')
        return Encryptor.md5(encoded)

    @staticmethod
    def md5_unicode(text: str) -> str:
        return Encryptor.md5(text.encode('unicode_escape').decode('utf-8'))

    @staticmethod
    def mysql(text: str) -> str:
        return "*" + hashlib.sha1(hashlib.sha1(text.encode('utf-8')).digest()).hexdigest().upper()

    @staticmethod
    def mysql5(text: str) -> str:
        return "*" + hashlib.sha1(hashlib.sha1(text.encode('utf-8')).digest()).hexdigest().upper()

    @staticmethod
    def ntlm(text: str) -> str:
        return hashlib.new('md4', text.encode('utf-16le')).hexdigest()

    @staticmethod
    def sha1(text: str) -> str:
        return hashlib.sha1(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha1_sha1(text: str) -> str:
        return hashlib.sha1(hashlib.sha1(text.encode('utf-8')).digest()).hexdigest()

    @staticmethod
    def sha1_md5(text: str) -> str:
        return hashlib.sha1(Encryptor.md5(text).encode('utf-8')).hexdigest()

    @staticmethod
    def sha256(text: str) -> str:
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha256_md5(text: str) -> str:
        return hashlib.sha256(Encryptor.md5(text).encode('utf-8')).hexdigest()

    @staticmethod
    def sha1_pass_salt(text: str, salt: str) -> str:
        return hashlib.sha1((text + salt).encode('utf-8')).hexdigest()

    @staticmethod
    def sha1_salt_pass(text: str, salt: str) -> str:
        return hashlib.sha1((salt + text).encode('utf-8')).hexdigest()

    @staticmethod
    def sha256_pass_salt(text: str, salt: str) -> str:
        return hashlib.sha256((text + salt).encode('utf-8')).hexdigest()

    @staticmethod
    def sha256_salt_pass(text: str, salt: str) -> str:
        return hashlib.sha256((salt + text).encode('utf-8')).hexdigest()

    @staticmethod
    def sha224(text: str) -> str:
        return hashlib.sha224(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha384(text: str) -> str:
        return hashlib.sha384(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha512(text: str) -> str:
        return hashlib.sha512(text.encode('utf-8')).hexdigest()

    @staticmethod
    def sha512_pass_salt(text: str, salt: str) -> str:
        return hashlib.sha512((text + salt).encode('utf-8')).hexdigest()

    @staticmethod
    def sha512_salt_pass(text: str, salt: str) -> str:
        return hashlib.sha512((salt + text).encode('utf-8')).hexdigest()


class Signals(QObject):
    """信号类，用于在加密计算和UI更新之间通信"""
    update_result = Signal(int, str)
    crack_started = Signal()
    crack_progress = Signal(int, int)
    crack_found = Signal(str, str)
    crack_complete = Signal()
    file_hash_started = Signal(str)
    file_hash_progress = Signal(int)
    file_hash_complete = Signal(dict)


class HashCrackerThread(QThread):
    """哈希碰撞破解线程"""

    def __init__(self, target_hash, dictionary_path, salt="", mode=0):
        super().__init__()
        self.target_hash = target_hash.lower()
        self.dictionary_path = dictionary_path
        self.salt = salt
        self.mode = mode  # 0: 明文, 1: 明文+盐, 2: 盐+明文, 3: 盐+明文+盐
        self.signals = Signals()
        self.stopped = False

    def run(self):
        """执行破解任务"""
        self.signals.crack_started.emit()

        try:
            with open(self.dictionary_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                total = len(lines)

                for i, line in enumerate(lines):
                    if self.stopped:
                        break

                    word = line.strip()

                    # 根据模式计算哈希
                    if self.mode == 0:  # 明文
                        current_hash = hashlib.md5(word.encode('utf-8')).hexdigest()
                    elif self.mode == 1:  # 明文+盐
                        current_hash = hashlib.md5((word + self.salt).encode('utf-8')).hexdigest()
                    elif self.mode == 2:  # 盐+明文
                        current_hash = hashlib.md5((self.salt + word).encode('utf-8')).hexdigest()
                    elif self.mode == 3:  # 盐+明文+盐
                        current_hash = hashlib.md5((self.salt + word + self.salt).encode('utf-8')).hexdigest()
                    else:
                        current_hash = ""

                    # 检查是否匹配
                    if current_hash == self.target_hash:
                        self.signals.crack_found.emit(word, current_hash)
                        self.stopped = True
                        return

                    # 更新进度
                    if i % 100 == 0:
                        self.signals.crack_progress.emit(i, total)

                # 完成但未找到
                self.signals.crack_complete.emit()

        except Exception as e:
            self.signals.crack_complete.emit()
            print(f"破解过程中出错: {str(e)}")

    def stop(self):
        """停止破解任务"""
        self.stopped = True


class FileHashThread(QThread):
    """文件哈希计算线程"""

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.signals = Signals()
        self.stopped = False

    def run(self):
        """执行文件哈希计算"""
        self.signals.file_hash_started.emit(self.file_path)

        try:
            # 初始化哈希对象
            md5_hash = hashlib.md5()
            sha1_hash = hashlib.sha1()
            sha256_hash = hashlib.sha256()
            sha512_hash = hashlib.sha512()
            crc32_hash = 0  # 初始化CRC32值

            # 获取文件大小用于进度计算
            file_size = os.path.getsize(self.file_path)
            bytes_read = 0

            # 分块读取文件以处理大文件
            with open(self.file_path, 'rb') as f:
                while not self.stopped:
                    chunk = f.read(8192)  # 8KB 块
                    if not chunk:
                        break

                    # 更新哈希值
                    md5_hash.update(chunk)
                    sha1_hash.update(chunk)
                    sha256_hash.update(chunk)
                    sha512_hash.update(chunk)
                    crc32_hash = binascii.crc32(chunk, crc32_hash)  # 更新CRC32值

                    # 更新进度
                    bytes_read += len(chunk)
                    progress = int((bytes_read / file_size) * 100)
                    self.signals.file_hash_progress.emit(progress)

            if not self.stopped:
                # 计算最终哈希值
                results = {
                    'md5': md5_hash.hexdigest(),
                    'sha1': sha1_hash.hexdigest(),
                    'sha256': sha256_hash.hexdigest(),
                    'sha512': sha512_hash.hexdigest(),
                    'crc32': f"{crc32_hash & 0xFFFFFFFF:08x}",  # 转换为无符号十六进制字符串
                    'file_path': self.file_path
                }

                # 获取文件信息
                file_stats = os.stat(self.file_path)
                results['file_size'] = self.format_size(file_stats.st_size)
                results['creation_time'] = time.ctime(file_stats.st_ctime)
                results['modification_time'] = time.ctime(file_stats.st_mtime)
                results['file_name'] = os.path.basename(self.file_path)
                results['file_ext'] = os.path.splitext(self.file_path)[1]

                # 添加文件类型信息
                mime_type, file_description = FileTypeDetector.detect_from_file(self.file_path)
                results['mime_type'] = mime_type
                results['file_description'] = file_description

                self.signals.file_hash_complete.emit(results)

                self.signals.file_hash_complete.emit(results)

        except Exception as e:
            print(f"计算文件哈希时出错: {str(e)}")
            self.signals.file_hash_complete.emit({
                'error': str(e),
                'file_path': self.file_path
            })

    def stop(self):
        """停止哈希计算"""
        self.stopped = True

    def format_size(self, size_bytes):
        """格式化文件大小显示"""
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0

        while size_bytes >= 1024 and unit_index < len(units) - 1:
            size_bytes /= 1024
            unit_index += 1

        return f"{size_bytes:.2f} {units[unit_index]}"


class FileDropWidget(QWidget):
    """支持文件拖拽的Widget"""

    file_dropped = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """处理拖入事件"""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        """处理放下事件"""
        urls = event.mimeData().urls()
        if urls:
            file_path = urls[0].toLocalFile()
            if os.path.isfile(file_path):
                self.file_dropped.emit(file_path)


class EncryptionTool(QMainWindow):
    """md5加密工具主窗口"""

    def __init__(self):
        super().__init__()
        self.signals = Signals()
        self.signals.update_result.connect(self.update_result_display)
        self.signals.crack_started.connect(self.on_crack_started)
        self.signals.crack_progress.connect(self.on_crack_progress)
        self.signals.crack_found.connect(self.on_crack_found)
        self.signals.crack_complete.connect(self.on_crack_complete)
        self.signals.file_hash_started.connect(self.on_file_hash_started)
        self.signals.file_hash_progress.connect(self.on_file_hash_progress)
        self.signals.file_hash_complete.connect(self.on_file_hash_complete)

        # 设置窗口属性
        self.setWindowTitle("MD5工具")
        self.setMinimumSize(1000, 700)

        # 加密算法列表
        self.algorithms = [
            ("md5_16", "16位MD5"),
            ("md5", "标准MD5"),
            ("md5_double", "md5(md5($pass))"),
            ("md5_triple", "md5(md5(md5($pass)))"),
            ("md5_double_with_salt", "md5(md5($pass).$salt)"),
            ("md5_sha1", "md5(sha1($pass))"),
            ("md5_pass_salt", "md5($pass.$salt)"),
            ("md5_salt_pass", "md5($salt.$pass)"),
            ("md5_salt_pass_salt", "md5($salt.$pass.$salt)"),
            ("md5_salt_md5pass", "md5($salt.md5($pass))"),
            ("md5_md5salt_pass", "md5(md5($salt).$pass)"),
            ("md5_pass_md5salt", "md5($pass.md5($salt))"),
            ("md5_md5salt_md5pass", "md5(md5($salt).md5($pass))"),
            ("md5_md5pass_md5salt", "md5(md5($pass).md5($salt))"),
            ("md5_substring", "md5(substring(md5($pass),8,24))"),
            ("md5_base64", "md5(base64)"),
            ("md5_unicode", "md5(unicode)"),
            ("mysql", "MySQL"),
            ("mysql5", "MySQL5"),
            ("ntlm", "NTLM"),
            ("sha1", "SHA-1"),
            ("sha1_sha1", "sha1(sha1($pass))"),
            ("sha1_md5", "sha1(md5($pass))"),
            ("sha256", "SHA-256"),
            ("sha256_md5", "sha256(md5($pass))"),
            ("sha1_pass_salt", "sha1($pass.$salt)"),
            ("sha1_salt_pass", "sha1($salt.$pass)"),
            ("sha256_pass_salt", "sha256($pass.$salt)"),
            ("sha256_salt_pass", "sha256($salt.$pass)"),
            ("sha224", "SHA-224"),
            ("sha384", "SHA-384"),
            ("sha512", "SHA-512"),
            ("sha512_pass_salt", "sha512($pass.$salt)"),
            ("sha512_salt_pass", "sha512($salt.$pass)"),
        ]

        self.md5_upper_case = False

        # 破解线程
        self.cracker_thread = None

        # 文件哈希计算线程
        self.file_hash_thread = None

        # 初始化UI
        self.init_ui()

    def init_ui(self):
        """初始化用户界面"""
        # 创建中心部件和主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页控件
        self.tabs = QTabWidget()

        # 添加加密标签页
        self.encryption_tab = QWidget()
        self.tabs.addTab(self.encryption_tab, "MD5加密")

        # 添加破解标签页
        self.cracking_tab = QWidget()
        self.tabs.addTab(self.cracking_tab, "MD5破解")

        # 添加文件哈希标签页
        self.file_hash_tab = FileDropWidget()
        self.file_hash_tab.file_dropped.connect(self.on_file_dropped)
        self.tabs.addTab(self.file_hash_tab, "文件哈希")

        # 设置加密标签页内容
        self.setup_encryption_tab()

        # 设置破解标签页内容
        self.setup_cracking_tab()

        # 设置文件哈希标签页内容
        self.setup_file_hash_tab()

        # 将标签页添加到主布局
        main_layout.addWidget(self.tabs)

    def setup_encryption_tab(self):
        """设置加密标签页内容"""
        tab_layout = QVBoxLayout(self.encryption_tab)

        # 创建顶部输入区域
        input_frame = QGroupBox()
        # input_frame.setFrameShape(QFrame.StyledPanel)
        # input_frame.setStyleSheet("background-color: #f2f2f2; padding: 10px;")
        input_layout = QVBoxLayout(input_frame)

        # 创建输入行1: 明文和盐值
        input_row1 = QHBoxLayout()

        # 明文输入
        plaintext_layout = QHBoxLayout()
        plaintext_label = QLabel("明文:")
        # plaintext_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.plaintext_input = QLineEdit()
        self.plaintext_input.setPlaceholderText("请输入要加密的文本")
        # self.plaintext_input.setMinimumHeight(35)
        self.plaintext_input.textChanged.connect(self.calculate_encryptions)

        plaintext_layout.addWidget(plaintext_label)
        plaintext_layout.addWidget(self.plaintext_input)

        # 盐值输入
        salt_layout = QHBoxLayout()
        salt_label = QLabel("salt盐值:")
        self.salt_input = QLineEdit()
        self.salt_input.setPlaceholderText("可选的盐值")
        # self.salt_input.setMinimumHeight(35)
        self.salt_input.textChanged.connect(self.calculate_encryptions)
        salt_layout.addWidget(salt_label)
        salt_layout.addWidget(self.salt_input)

        input_row1.addLayout(plaintext_layout, 3)
        input_row1.addLayout(salt_layout, 1)

        # 创建输入行2: 搜索和算法选择
        input_row2 = QHBoxLayout()

        # 搜索框
        search_layout = QHBoxLayout()
        search_label = QLabel("搜索算法:")
        # search_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索加密算法...")
        # self.search_input.setMinimumHeight(35)
        self.search_input.textChanged.connect(self.filter_algorithms)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)

        # 算法选择下拉框
        algorithm_layout = QHBoxLayout()
        algorithm_label = QLabel("显示方式:")
        # algorithm_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["全部", "仅MD5", "仅SHA", "仅数据库"])
        self.algorithm_combo.currentTextChanged.connect(self.filter_algorithms)
        algorithm_layout.addWidget(algorithm_label)
        algorithm_layout.addWidget(self.algorithm_combo)

        # 新增：MD5大小写转换按钮
        case_layout = QHBoxLayout()
        case_label = QLabel("MD5格式:")
        self.case_button = QPushButton("小写")
        # self.case_button.setMinimumHeight(35)
        self.case_button.setStyleSheet("background-color: #4CAF50; color: white;")
        self.case_button.clicked.connect(self.toggle_md5_case)
        case_layout.addWidget(case_label)
        case_layout.addWidget(self.case_button)

        # input_row2.addLayout(search_layout, 3)
        # input_row2.addLayout(algorithm_layout, 1)
        input_row2.addLayout(search_layout)
        input_row2.addLayout(algorithm_layout)
        input_row2.addLayout(case_layout)

        input_layout.addLayout(input_row1)
        input_layout.addLayout(input_row2)

        # 创建结果区域

        results_frame = QGroupBox("MD5加密结果")
        # results_frame.setFrameShape(QFrame.StyledPanel)
        results_layout = QVBoxLayout(results_frame)

        # 创建结果表格
        self.results_table = QTableWidget(len(self.algorithms), 2)
        self.results_table.setHorizontalHeaderLabels(["密文类型", "加密结果"])
        self.results_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)

        # 设置右键菜单
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_context_menu)

        # 初始化表格内容
        for row, (func_name, display_name) in enumerate(self.algorithms):
            # 添加算法名称
            name_item = QTableWidgetItem(display_name)
            name_item.setData(Qt.UserRole, func_name)
            self.results_table.setItem(row, 0, name_item)

            # 添加结果项
            result_item = QTableWidgetItem("")
            self.results_table.setItem(row, 1, result_item)

        results_layout.addWidget(self.results_table)

        # 将输入区域和结果区域添加到主布局
        tab_layout.addWidget(input_frame)
        tab_layout.addWidget(results_frame, 4)

        # 初始计算
        self.calculate_encryptions()

    def setup_cracking_tab(self):
        """设置破解标签页内容"""
        tab_layout = QVBoxLayout(self.cracking_tab)

        # 创建破解设置区域
        settings_frame = QFrame()
        settings_frame.setFrameShape(QFrame.StyledPanel)
        # settings_frame.setStyleSheet("background-color: #f5f5f5; padding: 10px;")
        settings_layout = QVBoxLayout(settings_frame)

        # 目标哈希输入
        hash_layout = QHBoxLayout()
        hash_label = QLabel("目标MD5哈希:")
        # hash_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.target_hash_input = QLineEdit()
        self.target_hash_input.setPlaceholderText("请输入要破解的MD5哈希值")
        hash_layout.addWidget(hash_label)
        hash_layout.addWidget(self.target_hash_input)
        settings_layout.addLayout(hash_layout)

        # 字典文件选择
        dict_layout = QHBoxLayout()
        dict_label = QLabel("字典文件:")
        # dict_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.dict_path_input = QLineEdit()
        self.dict_path_input.setReadOnly(True)
        self.dict_path_input.setPlaceholderText("请选择字典文件")
        self.browse_dict_btn = QPushButton("浏览...")
        self.browse_dict_btn.clicked.connect(self.browse_dictionary)
        dict_layout.addWidget(dict_label)
        dict_layout.addWidget(self.dict_path_input)
        dict_layout.addWidget(self.browse_dict_btn)
        settings_layout.addLayout(dict_layout)

        # 盐值设置
        salt_layout = QHBoxLayout()
        salt_label = QLabel("盐值:")
        # salt_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.crack_salt_input = QLineEdit()
        self.crack_salt_input.setPlaceholderText("可选的盐值")
        salt_layout.addWidget(salt_label)
        salt_layout.addWidget(self.crack_salt_input)
        settings_layout.addLayout(salt_layout)

        # 哈希模式选择
        mode_group = QGroupBox("哈希模式")
        mode_layout = QVBoxLayout(mode_group)

        self.mode_radio_1 = QRadioButton("明文")
        self.mode_radio_2 = QRadioButton("明文+盐")
        self.mode_radio_3 = QRadioButton("盐+明文")
        self.mode_radio_4 = QRadioButton("盐+明文+盐")

        self.mode_radio_1.setChecked(True)

        mode_layout.addWidget(self.mode_radio_1)
        mode_layout.addWidget(self.mode_radio_2)
        mode_layout.addWidget(self.mode_radio_3)
        mode_layout.addWidget(self.mode_radio_4)

        settings_layout.addWidget(mode_group)

        # 操作按钮
        btn_layout = QHBoxLayout()
        self.start_crack_btn = QPushButton("开始破解")
        # self.start_crack_btn.setMinimumHeight(35)
        self.start_crack_btn.clicked.connect(self.start_cracking)

        self.stop_crack_btn = QPushButton("停止破解")
        # self.stop_crack_btn.setMinimumHeight(35)
        self.stop_crack_btn.clicked.connect(self.stop_cracking)
        self.stop_crack_btn.setEnabled(False)

        btn_layout.addWidget(self.start_crack_btn)
        btn_layout.addWidget(self.stop_crack_btn)
        btn_layout.setAlignment(Qt.AlignCenter)
        settings_layout.addLayout(btn_layout)

        # 进度条
        progress_layout = QHBoxLayout()
        progress_label = QLabel("进度:")
        # progress_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.crack_progress_bar = QProgressBar()
        self.crack_progress_bar.setTextVisible(True)
        progress_layout.addWidget(progress_label)
        progress_layout.addWidget(self.crack_progress_bar)
        settings_layout.addLayout(progress_layout)

        # 结果显示
        self.crack_result_text = QTextEdit()
        self.crack_result_text.setReadOnly(True)
        self.crack_result_text.setPlaceholderText("破解结果将显示在这里...")
        settings_layout.addWidget(self.crack_result_text)

        # 将设置区域添加到标签页布局
        tab_layout.addWidget(settings_frame)

    def setup_file_hash_tab(self):
        """设置文件哈希标签页内容"""
        tab_layout = QVBoxLayout(self.file_hash_tab)

        # 创建文件选择区域
        file_frame = QGroupBox()
        # file_frame.setFrameShape(QFrame.StyledPanel)
        # file_frame.setStyleSheet("background-color: #f5f5f5; padding: ;")
        file_layout = QVBoxLayout(file_frame)

        # 文件路径显示
        file_path_layout = QHBoxLayout()
        file_path_label = QLabel("文件:")
        # file_path_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setPlaceholderText("请选择文件或拖拽文件到此处")


        self.browse_file_btn = QPushButton("浏览...")
        self.browse_file_btn.clicked.connect(self.browse_file)

        file_path_layout.addWidget(file_path_label)
        file_path_layout.addWidget(self.file_path_input)
        file_path_layout.addWidget(self.browse_file_btn)

        # 操作按钮
        btn_layout = QHBoxLayout()
        self.calculate_hash_btn = QPushButton("计算哈希")
        # self.calculate_hash_btn.setMinimumHeight(35)
        self.calculate_hash_btn.clicked.connect(self.calculate_file_hash)
        self.calculate_hash_btn.setEnabled(False)

        self.stop_hash_btn = QPushButton("停止")
        # self.stop_hash_btn.setMinimumHeight(35)
        self.stop_hash_btn.clicked.connect(self.stop_file_hash)
        self.stop_hash_btn.setEnabled(False)

        btn_layout.addWidget(self.calculate_hash_btn)
        btn_layout.addWidget(self.stop_hash_btn)
        btn_layout.setAlignment(Qt.AlignCenter)

        # 进度条
        progress_layout = QHBoxLayout()
        progress_label = QLabel("进度:")
        # progress_label.setFont(QFont("YaHei", 10, QFont.Bold))
        self.hash_progress_bar = QProgressBar()
        self.hash_progress_bar.setTextVisible(True)
        progress_layout.addWidget(progress_label)
        progress_layout.addWidget(self.hash_progress_bar)

        file_layout.addLayout(file_path_layout)
        file_layout.addLayout(btn_layout)
        file_layout.addLayout(progress_layout)

        # 文件信息区域
        info_group = QGroupBox("文件信息")
        info_layout = QVBoxLayout(info_group)

        self.file_info_tree = QTreeWidget()
        self.file_info_tree.setHeaderLabels(["属性", "值"])
        self.file_info_tree.setColumnWidth(0, 150)
        info_layout.addWidget(self.file_info_tree)

        # 哈希结果区域
        hash_group = QGroupBox("哈希值")
        hash_layout = QVBoxLayout(hash_group)

        self.hash_result_table = QTableWidget(5, 2)
        self.hash_result_table.setHorizontalHeaderLabels(["算法", "哈希值"])
        self.hash_result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.hash_result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.hash_result_table.verticalHeader().setVisible(False)
        self.hash_result_table.setEditTriggers(QTableWidget.NoEditTriggers)

        # 初始化哈希结果表格
        for row, algo in enumerate(["MD5", "SHA-1", "SHA-256", "SHA-512", "CRC32"]):  # 增加CRC32
            self.hash_result_table.setItem(row, 0, QTableWidgetItem(algo))
            self.hash_result_table.setItem(row, 1, QTableWidgetItem(""))

        # 设置右键菜单
        self.hash_result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hash_result_table.customContextMenuRequested.connect(self.show_hash_context_menu)

        hash_layout.addWidget(self.hash_result_table)

        # 将所有组件添加到标签页布局
        tab_layout.addWidget(file_frame)
        tab_layout.addWidget(info_group, 1)
        tab_layout.addWidget(hash_group, 3)

    def calculate_encryptions(self):
        """计算所有加密结果"""
        plaintext = self.plaintext_input.text()
        salt = self.salt_input.text()

        # 如果明文为空，清空所有结果
        if not plaintext:
            for row in range(self.results_table.rowCount()):
                self.results_table.item(row, 1).setText("")
            return

        # 为每种算法创建一个任务
        for row, (func_name, _) in enumerate(self.algorithms):
            try:
                # 获取对应的加密函数
                encrypt_func = getattr(Encryptor, func_name)

                # 根据函数是否需要盐值来调用
                if "salt" in encrypt_func.__code__.co_varnames:
                    result = encrypt_func(plaintext, salt)
                else:
                    result = encrypt_func(plaintext)

                # 新增：处理MD5结果的大小写
                if func_name.startswith("md5"):
                    result = result.upper() if self.md5_upper_case else result.lower()

                # 更新结果（通过信号在主线程中更新UI）
                self.signals.update_result.emit(row, result)
            except Exception as e:
                self.signals.update_result.emit(row, f"错误: {str(e)}")

    def toggle_md5_case(self):
        """切换MD5结果的大小写格式"""
        self.md5_upper_case = not self.md5_upper_case
        self.case_button.setText("大写" if self.md5_upper_case else "小写")

        # 更新MD5结果的大小写
        plaintext = self.plaintext_input.text()
        if plaintext:
            self.calculate_encryptions()

    def update_result_display(self, row: int, result: str):
        """更新结果显示"""
        self.results_table.item(row, 1).setText(result)

    def filter_algorithms(self):
        """根据搜索文本和算法类型过滤显示的算法"""
        search_text = self.search_input.text().lower()
        category = self.algorithm_combo.currentText()

        for row in range(self.results_table.rowCount()):
            name_item = self.results_table.item(row, 0)
            func_name = name_item.data(Qt.UserRole)
            display_name = name_item.text()

            # 检查类别过滤
            if category == "仅MD5" and not func_name.startswith("md5") and func_name not in ["mysql", "mysql5", "ntlm"]:
                self.results_table.setRowHidden(row, True)
                continue
            elif category == "仅SHA" and not (
                    func_name.startswith("sha") or func_name in ["sha1_sha1", "sha1_md5", "sha256_md5"]):
                self.results_table.setRowHidden(row, True)
                continue
            elif category == "仅数据库" and func_name not in ["mysql", "mysql5", "ntlm"]:
                self.results_table.setRowHidden(row, True)
                continue

            # 检查搜索文本过滤
            if search_text and search_text not in display_name.lower() and search_text not in func_name.lower():
                self.results_table.setRowHidden(row, True)
                continue

            # 如果都通过，则显示该行
            self.results_table.setRowHidden(row, False)

    def show_context_menu(self, position):
        """显示右键菜单"""
        indexes = self.results_table.selectedIndexes()
        if not indexes:
            return

        menu = QMenu()
        copy_action = menu.addAction("复制结果")
        copy_name_action = menu.addAction("复制算法名称")

        action = menu.exec_(self.results_table.viewport().mapToGlobal(position))

        if action == copy_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.results_table.item(indexes[0].row(), 1).text())
        elif action == copy_name_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.results_table.item(indexes[0].row(), 0).text())

    def browse_dictionary(self):
        """浏览并选择字典文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )

        if file_path:
            self.dict_path_input.setText(file_path)

    def start_cracking(self):
        """开始MD5破解"""
        target_hash = self.target_hash_input.text().strip()
        dict_path = self.dict_path_input.text().strip()

        if not target_hash:
            QMessageBox.warning(self, "警告", "请输入要破解的MD5哈希值")
            return

        if not dict_path or not os.path.isfile(dict_path):
            QMessageBox.warning(self, "警告", "请选择有效的字典文件")
            return

        # 获取当前选择的哈希模式
        if self.mode_radio_1.isChecked():
            mode = 0
        elif self.mode_radio_2.isChecked():
            mode = 1
        elif self.mode_radio_3.isChecked():
            mode = 2
        else:
            mode = 3

        salt = self.crack_salt_input.text()
        # print(salt)

        # 创建并启动破解线程
        self.cracker_thread = HashCrackerThread(target_hash, dict_path, salt, mode)
        self.cracker_thread.signals.crack_started.connect(self.on_crack_started)
        self.cracker_thread.signals.crack_progress.connect(self.on_crack_progress)
        self.cracker_thread.signals.crack_found.connect(self.on_crack_found)
        self.cracker_thread.signals.crack_complete.connect(self.on_crack_complete)
        self.cracker_thread.start()

    def stop_cracking(self):
        """停止MD5破解"""
        print("stop!!")
        if self.cracker_thread and self.cracker_thread.isRunning():
            print("状态："+self.cracker_thread.isRunning())
            self.cracker_thread.stop()
        else:
            print("到这了")

    def on_crack_started(self):
        """破解开始时的处理"""
        self.start_crack_btn.setEnabled(False)
        self.stop_crack_btn.setEnabled(True)
        self.crack_result_text.clear()
        self.crack_result_text.append("开始破解MD5哈希...")

    def on_crack_progress(self, current: int, total: int):
        """更新破解进度"""
        progress = int((current / total) * 100)
        self.crack_progress_bar.setValue(progress)
        self.crack_result_text.append(f"已尝试 {current}/{total} 个密码 ({progress}%)")

    def on_crack_found(self, password: str, hash_value: str):
        """找到匹配密码时的处理"""
        self.crack_result_text.append("\n=== 找到匹配 ===")
        self.crack_result_text.append(f"密码: {password}")
        self.crack_result_text.append(f"MD5: {hash_value}")
        self.crack_progress_bar.setValue(100)
        self.start_crack_btn.setEnabled(True)
        self.stop_crack_btn.setEnabled(False)

    def on_crack_complete(self):
        """破解完成时的处理"""
        self.start_crack_btn.setEnabled(True)
        self.stop_crack_btn.setEnabled(False)
        self.crack_progress_bar.setValue(100)

        if not self.cracker_thread or not self.cracker_thread.stopped:
            self.crack_result_text.append("\n=== 破解完成 ===")
            self.crack_result_text.append("未能在字典中找到匹配的密码")

    def browse_file(self):
        """浏览并选择文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择文件", "", "所有文件 (*)"
        )

        if file_path:
            self.file_path_input.setText(file_path)
            self.calculate_hash_btn.setEnabled(True)

    def on_file_dropped(self, file_path):
        """处理文件拖拽事件"""
        self.file_path_input.setText(file_path)
        self.calculate_hash_btn.setEnabled(True)
        self.tabs.setCurrentWidget(self.file_hash_tab)

    def calculate_file_hash(self):
        """计算文件哈希值"""
        file_path = self.file_path_input.text()

        if not file_path or not os.path.isfile(file_path):
            QMessageBox.warning(self, "警告", "请选择有效的文件")
            return

        # 重置结果
        self.reset_file_hash_results()

        # 创建并启动文件哈希计算线程
        self.file_hash_thread = FileHashThread(file_path)
        self.file_hash_thread.signals.file_hash_started.connect(self.on_file_hash_started)
        self.file_hash_thread.signals.file_hash_progress.connect(self.on_file_hash_progress)
        self.file_hash_thread.signals.file_hash_complete.connect(self.on_file_hash_complete)
        self.file_hash_thread.start()

        # 更新UI状态
        self.calculate_hash_btn.setEnabled(False)
        self.stop_hash_btn.setEnabled(True)

    def stop_file_hash(self):
        """停止文件哈希计算"""
        if self.file_hash_thread and self.file_hash_thread.isRunning():
            self.file_hash_thread.stop()

    def reset_file_hash_results(self):
        """重置文件哈希结果显示"""
        # 清空文件信息树
        self.file_info_tree.clear()

        # 清空哈希结果表
        for row in range(self.hash_result_table.rowCount()):
            self.hash_result_table.item(row, 1).setText("")

    def on_file_hash_started(self, file_path):
        """文件哈希计算开始时的处理"""
        self.hash_progress_bar.setValue(0)
        self.file_info_tree.clear()

        # 添加文件路径信息
        root = QTreeWidgetItem(self.file_info_tree)
        root.setText(0, "文件路径")
        root.setText(1, file_path)
        self.file_info_tree.addTopLevelItem(root)

        # 添加计算中信息
        status = QTreeWidgetItem(self.file_info_tree)
        status.setText(0, "状态")
        status.setText(1, "正在计算哈希...")
        self.file_info_tree.addTopLevelItem(status)

    def on_file_hash_progress(self, progress):
        """更新文件哈希计算进度"""
        self.hash_progress_bar.setValue(progress)

    def on_file_hash_complete(self, results):
        """文件哈希计算完成时的处理"""
        # 更新UI状态
        self.calculate_hash_btn.setEnabled(True)
        self.stop_hash_btn.setEnabled(False)
        self.hash_progress_bar.setValue(100)

        # 检查是否有错误
        if 'error' in results:
            QMessageBox.critical(self, "错误", f"计算文件哈希时出错: {results['error']}")
            return

        # 更新文件信息
        self.file_info_tree.clear()

        # 添加基本文件信息
        info_items = [
            ("文件名", results['file_name']),
            ("文件扩展名", results['file_ext']),
            ("MIME类型", results['mime_type']),  # 添加MIME类型
            ("文件类型", results['file_description']),
            ("文件大小", results['file_size']),
            ("创建时间", results['creation_time']),
            ("修改时间", results['modification_time']),
            ("文件路径", results['file_path'])
        ]

        for key, value in info_items:
            item = QTreeWidgetItem(self.file_info_tree)
            item.setText(0, key)
            item.setText(1, value)
            self.file_info_tree.addTopLevelItem(item)

        # 更新哈希结果
        hash_map = {
            "MD5": results['md5'],
            "SHA-1": results['sha1'],
            "SHA-256": results['sha256'],
            "SHA-512": results['sha512'],
            "CRC32": results['crc32']
        }

        for row, algo in enumerate(["MD5", "SHA-1", "SHA-256", "SHA-512","CRC32"]):
            self.hash_result_table.item(row, 1).setText(hash_map[algo])

    def show_hash_context_menu(self, position):
        """显示哈希结果的右键菜单"""
        indexes = self.hash_result_table.selectedIndexes()
        if not indexes:
            return

        menu = QMenu()
        copy_action = menu.addAction("复制哈希值")
        copy_algo_action = menu.addAction("复制算法名称")

        action = menu.exec_(self.hash_result_table.viewport().mapToGlobal(position))

        if action == copy_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.hash_result_table.item(indexes[0].row(), 1).text())
        elif action == copy_algo_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(self.hash_result_table.item(indexes[0].row(), 0).text())


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 确保中文显示正常
    # font = QFont("YaHei")
    # app.setFont(font)

    window = EncryptionTool()
    window.show()

    sys.exit(app.exec_())