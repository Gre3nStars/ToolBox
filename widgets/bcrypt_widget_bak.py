import threading

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTextEdit, QLabel, QComboBox, QMessageBox, QGroupBox, QFileDialog, QStatusBar
)
from PySide6.QtCore import Qt, QThread, Signal, QObject, QRunnable, QThreadPool
from PySide6.QtGui import QColor, QPalette
import bcrypt
import os


class BruteForceThread(QThread):
    progress = Signal(int, int)
    result = Signal(str)
    finished = Signal()

    def __init__(self, hash_text, dict_path):
        super().__init__()
        self.hash_text = hash_text
        self.dict_path = dict_path
        self._is_running = True

    def run(self):
        try:
            hash_bytes = self.hash_text.encode("utf-8")
            total = 0
            with open(self.dict_path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in f:
                    total += 1
            with open(self.dict_path, "r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f, 1):
                    if not self._is_running:
                        break
                    candidate = line.strip()
                    if not candidate:
                        continue
                    try:
                        if bcrypt.checkpw(candidate.encode("utf-8"), hash_bytes):
                            self.result.emit(candidate)
                            self.progress.emit(total, total)  # 直接100%
                            self.finished.emit()
                            return
                    except Exception:
                        continue
                    self.progress.emit(idx, total)
            if self._is_running:
                self.result.emit("")
        except Exception as e:
            self.result.emit("")
        self.finished.emit()

    def stop(self):
        self._is_running = False

class BcryptEncryptor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Bcrypt加密工具")
        # self.resize(600, 500)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        main_layout = QVBoxLayout(self.central_widget)

        # 输入区域（QGroupBox）
        input_group = QGroupBox("输入明文或密文Hash")
        input_layout = QVBoxLayout()
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("请输入要加密的明文，或输入Bcrypt Hash进行爆破")
        input_layout.addWidget(self.input_edit)
        input_group.setLayout(input_layout)
        main_layout.addWidget(input_group)

        # 功能按钮区（第一排）
        func_layout1 = QHBoxLayout()
        salt_label = QLabel("盐长度：")
        self.salt_combo = QComboBox()
        # 直接添加4-31的纯数值
        salt_var =  [
            "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16",
            "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31"
        ]
        self.salt_combo.addItems(salt_var)
        self.salt_combo.setCurrentText("10")
        encrypt_btn = QPushButton("🔒 加密")
        encrypt_btn.clicked.connect(self.encrypt_text)
        clear_btn = QPushButton("🗑️ 清空")
        clear_btn.clicked.connect(self.clear_fields)
        func_layout1.addWidget(salt_label)
        func_layout1.addWidget(self.salt_combo)
        func_layout1.addStretch()
        func_layout1.addWidget(encrypt_btn)
        func_layout1.addWidget(clear_btn)
        main_layout.addLayout(func_layout1)

        # 功能按钮区（第二排）
        func_layout2 = QHBoxLayout()
        self.dict_label = QLabel("字典文件：")
        self.dict_path_edit = QLineEdit()
        self.dict_path_edit.setPlaceholderText("字典文件路径")
        self.dict_path_edit.setReadOnly(True)
        dict_btn = QPushButton("📂 选择字典")
        dict_btn.clicked.connect(self.choose_dict_file)
        self.brute_btn = QPushButton("🚀 爆破验证")
        self.brute_btn.clicked.connect(self.start_brute_force)
        self.brute_btn.setEnabled(False)
        self.stop_brute_btn = QPushButton("🛑 停止爆破")
        self.stop_brute_btn.clicked.connect(self.stop_brute_force)
        self.stop_brute_btn.setEnabled(False)
        func_layout2.addWidget(self.dict_label)
        func_layout2.addWidget(self.dict_path_edit)
        func_layout2.addWidget(dict_btn)
        func_layout2.addWidget(self.brute_btn)
        func_layout2.addWidget(self.stop_brute_btn)
        main_layout.addLayout(func_layout2)

        # 输出区域（QGroupBox）
        output_group = QGroupBox("加密结果 / 爆破结果")
        output_layout = QVBoxLayout()
        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        output_layout.addWidget(self.output_edit)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)

        # 状态栏用于进度显示
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.status_label = QLabel("")
        self.statusbar.addWidget(self.status_label)
        self.statusbar.setStyleSheet("QStatusBar{background: #f0f0f0;}")

        self.brute_thread = None

        # 监听输入变化，自动判断是否为hash
        self.input_edit.textChanged.connect(self.on_input_changed)

    def on_input_changed(self):
        text = self.input_edit.toPlainText().strip()
        # 简单判断是否为bcrypt hash
        if text.startswith("$2a$") or text.startswith("$2b$") or text.startswith("$2y$"):
            self.brute_btn.setEnabled(bool(self.dict_path_edit.text().strip()))
        else:
            self.brute_btn.setEnabled(False)

    def encrypt_text(self):
        plain_text = self.input_edit.toPlainText().strip()
        # 判断是否为hash，如果是hash则不加密
        if not plain_text:
            QMessageBox.warning(self, "提示", "请输入要加密的内容！")
            return
        if plain_text.startswith("$2a$") or plain_text.startswith("$2b$") or plain_text.startswith("$2y$"):
            QMessageBox.information(self, "提示", "检测到输入为Hash，如需爆破请使用爆破功能。")
            return
        try:
            cost = int(self.salt_combo.currentText())
            if not (4 <= cost <= 31):
                raise ValueError("盐长度（cost）必须在4-31之间")
            salt = bcrypt.gensalt(rounds=cost)
            hashed = bcrypt.hashpw(plain_text.encode("utf-8"), salt)
            self.output_edit.setPlainText(hashed.decode("utf-8"))
            self.set_status("加密成功", 100, QColor("#4CAF50"))
        except Exception as e:
            self.set_status(f"加密失败: {e}", 100, QColor("#F44336"))
            QMessageBox.critical(self, "错误", f"加密失败: {e}")

    def clear_fields(self):
        self.input_edit.clear()
        self.output_edit.clear()
        self.set_status("", 0, QColor("#f0f0f0"))

    def choose_dict_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择字典文件", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.dict_path_edit.setText(file_path)
            # 检查输入是否为hash
            text = self.input_edit.toPlainText().strip()
            if text.startswith("$2a$") or text.startswith("$2b$") or text.startswith("$2y$"):
                self.brute_btn.setEnabled(True)
            else:
                self.brute_btn.setEnabled(False)
        else:
            self.brute_btn.setEnabled(False)

    def start_brute_force(self):
        hash_text = self.input_edit.toPlainText().strip()
        dict_path = self.dict_path_edit.text().strip()
        if not hash_text or not dict_path or not os.path.isfile(dict_path):
            QMessageBox.warning(self, "提示", "请在输入区输入Bcrypt Hash并选择有效的字典文件！")
            return
        if not (hash_text.startswith("$2a$") or hash_text.startswith("$2b$") or hash_text.startswith("$2y$")):
            QMessageBox.warning(self, "提示", "输入内容不是有效的Bcrypt Hash！")
            return
        self.output_edit.append("开始爆破，请稍候...")
        self.set_status("爆破中: 0%", 0, QColor("#2196F3"))
        self.brute_btn.setEnabled(False)
        self.stop_brute_btn.setEnabled(True)
        self.brute_thread = BruteForceThread(hash_text, dict_path)
        self.brute_thread.progress.connect(self.update_progress)
        self.brute_thread.result.connect(self.show_brute_result)
        self.brute_thread.finished.connect(self.brute_finished)
        self.brute_thread.start()

    def stop_brute_force(self):
        if self.brute_thread and self.brute_thread.isRunning():
            self.brute_thread.stop()
            self.output_edit.append("爆破已手动停止。")
            self.set_status("爆破已停止", 100, QColor("#F44336"))
            self.stop_brute_btn.setEnabled(False)
            self.brute_btn.setEnabled(True)

    def update_progress(self, current, total):
        if total > 0:
            percent = int(current / total * 100)
            if percent >= 100:
                percent = 100
            color = "#4CAF50" if percent == 100 else "#2196F3"
            self.set_status(f"爆破进度: {percent}% ({current}/{total})", percent, QColor(color))
        else:
            self.set_status("爆破进度: 0%", 0, QColor("#2196F3"))

    def show_brute_result(self, result):
        if result:
            self.output_edit.append(f"✅ 爆破成功！明文为: {result}")
            self.set_status("爆破成功！100%", 100, QColor("#4CAF50"))
        else:
            self.output_edit.append("❌ 爆破失败，未找到匹配明文。")
            self.set_status("爆破失败", 100, QColor("#F44336"))

    def brute_finished(self):
        self.brute_btn.setEnabled(True)
        self.stop_brute_btn.setEnabled(False)

    def set_status(self, text, percent, color: QColor):
        self.status_label.setText(text)
        # 设置背景色和进度条效果
        palette = self.statusbar.palette()
        palette.setColor(QPalette.Window, color)
        self.statusbar.setPalette(palette)
        self.statusbar.setAutoFillBackground(True)
        # 进度条效果用背景渐变模拟
        if percent > 0 and percent < 100:
            grad = f"QStatusBar{{background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {color.name()}, stop:{percent/100:.2f} {color.name()}, stop:{percent/100:.2f} #f0f0f0, stop:1 #f0f0f0);}}"
            self.statusbar.setStyleSheet(grad)
        elif percent == 100:
            self.statusbar.setStyleSheet(f"QStatusBar{{background: {color.name()}; color: white;}}")
        else:
            self.statusbar.setStyleSheet("QStatusBar{background: #f0f0f0;}")

    def closeEvent(self, event):
        if self.brute_thread and self.brute_thread.isRunning():
            self.brute_thread.stop()
            self.brute_thread.wait()
        event.accept()

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    win = BcryptEncryptor()
    win.show()
    sys.exit(app.exec())








