import sys
import base64
import binascii
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QComboBox, QPushButton, QGroupBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QMenu
)
from PySide6.QtCore import Qt, QPoint
import hmac
import hashlib

# 检查RIPEMD160支持
def get_ripemd160():
    try:
        return hashlib.new("ripemd160")
    except Exception:
        return None

HASH_ALGOS = {
    "MD5": hashlib.md5,
    "RIPEMD160": lambda: hashlib.new("ripemd160"),
    "SHA1": hashlib.sha1,
    "SHA224": hashlib.sha224,
    "SHA256": hashlib.sha256,
    "SHA384": hashlib.sha384,
    "SHA512": hashlib.sha512,
    "SHA3-224": hashlib.sha3_224,
    "SHA3-256": hashlib.sha3_256,
    "SHA3-384": hashlib.sha3_384,
    "SHA3-512": hashlib.sha3_512,
}

def get_supported_algos():
    algos = []
    for name, func in HASH_ALGOS.items():
        try:
            func()
            algos.append(name)
        except Exception:
            continue
    return algos

class HmacTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HMAC算法工具")
        self.resize(800, 600)
        self.init_ui()

    def init_ui(self):
        central = QWidget()
        layout = QVBoxLayout()

        # 输入明文
        input_group = QGroupBox("输入内容")
        input_layout = QVBoxLayout()
        self.input_edit = QTextEdit()
        self.input_edit.textChanged.connect(self.update_result)
        input_layout.addWidget(self.input_edit)
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 密钥
        format_layout = QHBoxLayout()
        format_layout.addStretch()
        key_label = QLabel("密钥:")
        self.key_edit = QLineEdit()
        self.key_edit.setMaximumWidth(200)
        self.key_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.key_edit.textChanged.connect(self.update_result)
        format_layout.addWidget(key_label)
        format_layout.addWidget(self.key_edit)
        layout.addLayout(format_layout)

        # 输出格式
        # format_layout = QHBoxLayout()
        format_label = QLabel("输出格式:")
        self.format_combo = QComboBox()
        self.format_combo.addItems(["HEX", "二进制", "Base64"])
        self.format_combo.currentIndexChanged.connect(self.update_result)
        format_layout.addWidget(format_label)
        format_layout.addWidget(self.format_combo)

        # HEX大小写切换按钮
        self.case_btn = QPushButton("HEX大写")
        self.case_btn.setStyleSheet("background-color: #4CAF50; color: white;")
        self.case_upper = True  # True: upper, False: lower
        self.case_btn.setCheckable(True)
        self.case_btn.setChecked(True)
        self.case_btn.clicked.connect(self.toggle_case)
        format_layout.addWidget(self.case_btn)

        format_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        format_layout.addStretch()
        layout.addLayout(format_layout)

        # 输出结果表格
        result_group = QGroupBox("加密结果")
        result_layout = QVBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.resizeColumnsToContents()
        self.result_table.setColumnCount(2)
        self.result_table.setHorizontalHeaderLabels(["算法", "结果"])
        self.result_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.result_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.result_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.result_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_table.customContextMenuRequested.connect(self.show_table_context_menu)
        result_layout.addWidget(self.result_table)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        # 复制按钮
        # btn_layout = QHBoxLayout()
        # self.copy_btn = QPushButton("复制结果")
        # self.copy_btn.clicked.connect(self.copy_result)
        # btn_layout.addStretch()
        # btn_layout.addWidget(self.copy_btn)
        # layout.addLayout(btn_layout)

        central.setLayout(layout)
        self.setCentralWidget(central)

        self.update_case_btn_state()

    def update_case_btn_state(self):
        # 仅在HEX格式下可用
        if self.format_combo.currentText() == "HEX":
            self.case_btn.setEnabled(True)
        else:
            self.case_btn.setEnabled(False)

    def toggle_case(self):
        self.case_upper = self.case_btn.isChecked()
        if self.case_upper:
            self.case_btn.setText("HEX大写")
        else:
            self.case_btn.setText("HEX小写")
        self.update_result()

    def update_result(self):
        text = self.input_edit.toPlainText()
        key = self.key_edit.text()
        self.update_case_btn_state()
        algos = get_supported_algos()
        self.result_table.setRowCount(len(algos))
        if not key or not text:
            for i, algo in enumerate(algos):
                self.result_table.setItem(i, 0, QTableWidgetItem(algo))
                self.result_table.setItem(i, 1, QTableWidgetItem(""))
            return

        fmt = self.format_combo.currentText()
        for i, algo in enumerate(algos):
            try:
                hash_func = HASH_ALGOS[algo]
                hm = hmac.new(key.encode('utf-8'), text.encode('utf-8'), hash_func)
                digest = hm.digest()
                if fmt == "HEX":
                    result = binascii.hexlify(digest).decode('ascii')
                    if self.case_upper:
                        result = result.upper()
                    else:
                        result = result.lower()
                elif fmt == "Base64":
                    result = base64.b64encode(digest).decode('ascii')
                else:  # 二进制
                    result = ' '.join(f'{b:08b}' for b in digest)
            except Exception as e:
                result = f"错误: {e}"
            self.result_table.setItem(i, 0, QTableWidgetItem(algo))
            self.result_table.setItem(i, 1, QTableWidgetItem(result))

    def copy_result(self):
        # 复制选中行的内容为文本，如果没有选中则复制全部
        selected_ranges = self.result_table.selectedRanges()
        lines = []
        if selected_ranges:
            selected_rows = set()
            for r in selected_ranges:
                for row in range(r.topRow(), r.bottomRow() + 1):
                    selected_rows.add(row)
            for row in sorted(selected_rows):
                algo = self.result_table.item(row, 0).text() if self.result_table.item(row, 0) else ""
                result = self.result_table.item(row, 1).text() if self.result_table.item(row, 1) else ""
                lines.append(f"{algo}: {result}")
        else:
            for row in range(self.result_table.rowCount()):
                algo = self.result_table.item(row, 0).text() if self.result_table.item(row, 0) else ""
                result = self.result_table.item(row, 1).text() if self.result_table.item(row, 1) else ""
                # lines.append(f"{algo}: {result}")
                lines.append(f"{result}")
        result_text = "\n".join(lines)
        if result_text:
            QApplication.clipboard().setText(result_text)

    def show_table_context_menu(self, pos: QPoint):
        menu = QMenu(self)
        copy_row_action = menu.addAction("复制选中行")
        copy_all_action = menu.addAction("复制全部")
        action = menu.exec_(self.result_table.viewport().mapToGlobal(pos))
        if action == copy_row_action:
            self.copy_result()
        elif action == copy_all_action:
            # 清除选择，复制全部
            self.result_table.clearSelection()
            self.copy_result()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = HmacTool()
    win.show()
    sys.exit(app.exec())



