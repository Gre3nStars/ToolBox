"""
Author: Gre3nStars
Date: 2025-07-21 17:11:32
LastEditTime: 2025-08-07 14:36:37
Description: 
FilePath: ToolBox_internal/widgets/jwt_widget.py
Copyright: Copyright (c) 2025 by Gre3nStars, All Rights Reserved. 
"""
import sys
import jwt
import time
import base64
import json
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QLineEdit, QStatusBar, QFileDialog,
    QComboBox, QMessageBox, QDialog, QGridLayout, QGroupBox
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QPalette, QColor, QFont

from widgets.json_widget import JsonHighlighterCode


class JWTUtility(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("JSONWebToken工具")
        self.resize(800, 600)

        self.init_ui()

    def init_ui(self):
        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        main_layout = QVBoxLayout(central_widget)

        # 输入区域布局
        input_layout = QVBoxLayout()
        # JWT 输入框

        input_group = QGroupBox("输入区域")

        self.jwt_input = QTextEdit()
        self.jwt_input.setPlaceholderText("请输入 JWT")
        input_layout.addWidget(self.jwt_input)
        input_group.setLayout(input_layout)


        # 功能区域
        # 密钥输入框和选择
        buttom_layout = QVBoxLayout()

        self.key_layout = QHBoxLayout()
        self.key_label = QLabel("密钥:")
        self.key_label.setMaximumWidth(40)
        self.key_input = QLineEdit()
        self.key_input.setFixedWidth(320)
        font = QFont()
        font.setPointSize(10)  # 设置字体大小为12
        # font.setBold(True)  # 设置为粗体
        self.key_input.setFont(font)
        self.key_input.setAlignment(Qt.AlignCenter)
        self.key_file_btn = QPushButton("📁 从文件加载密钥")
        self.key_file_btn.setMaximumWidth(160)
        self.key_file_btn.clicked.connect(self.load_key_from_file)
        self.key_layout.addWidget(self.key_label)
        self.key_layout.addWidget(self.key_input)
        self.key_layout.addWidget(self.key_file_btn)
        self.key_layout.setAlignment(Qt.AlignCenter)
        buttom_layout.addLayout(self.key_layout)
        buttom_layout.setAlignment(Qt.AlignCenter)
        # 算法选择
        self.alg_layout = QHBoxLayout()
        self.alg_label = QLabel("算法:")
        self.alg_combo = QComboBox()
        self.alg_combo.addItems(["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"])
        self.alg_layout.addWidget(self.alg_label)
        self.alg_layout.addWidget(self.alg_combo)
        self.alg_layout.setAlignment(Qt.AlignCenter)
        buttom_layout.addLayout(self.alg_layout)

        # 功能按钮布局
        btn_layout = QHBoxLayout()
        self.decode_btn = QPushButton("🔓 解码JWT")
        self.decode_btn.clicked.connect(self.decode_jwt)
        self.verify_btn = QPushButton("✅ 验证JWT")
        self.verify_btn.clicked.connect(self.verify_jwt)
        self.generate_btn = QPushButton("🧬 生成JWT")
        self.generate_btn.clicked.connect(self.generate_jwt)
        self.brute_force_btn = QPushButton("💣 密钥爆破")
        self.brute_force_btn.clicked.connect(self.brute_force_key)
        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self.clear_text)

        btn_layout.setAlignment(Qt.AlignCenter)
        btn_layout.addWidget(self.decode_btn)
        btn_layout.addWidget(self.verify_btn)
        btn_layout.addWidget(self.generate_btn)
        btn_layout.addWidget(self.brute_force_btn)
        btn_layout.addWidget(self.clear_btn)
        buttom_layout.addLayout(btn_layout)

        main_layout.addWidget(input_group)
        main_layout.addLayout(buttom_layout)

        # 输出区域
        out_group = QGroupBox("输出区域")
        out_layout = QVBoxLayout()
        self.output = QTextEdit()
        self.json_highlighter = JsonHighlighterCode(self.output.document())
        out_layout.addWidget(self.output)
        out_group.setLayout(out_layout)
        # self.output.setReadOnly(True)
        main_layout.addWidget(out_group)

        # 状态栏
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def load_key_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择密钥文件", "", "文本文件 (*.txt)","所有文件 (*.*)")
        if file_path:
            with open(file_path, "r",errors='ignore') as f:
                key = f.read().strip()
                self.key_input.setText(key)

    def clear_text(self):
        self.jwt_input.clear()
        self.output.clear()

    def decode_jwt(self):
        jwt_str = self.jwt_input.toPlainText().strip()
        if not jwt_str:
            QMessageBox.warning(self, "警告", "请输入 JWT")
            return

        try:
            # 分割 JWT 的三个部分
            parts = jwt_str.split('.')
            if len(parts) != 3:
                raise ValueError("JWT 格式不正确，应为三段式（Headers.Payload.Signature）")

            header_part, payload_part, signature_part = parts

            # 解析 Headers
            header = json.loads(base64.urlsafe_b64decode(header_part + '==').decode('utf-8'))
            # 解析 Payload
            payload = json.loads(base64.urlsafe_b64decode(payload_part + '==').decode('utf-8'))
            # 保留 Signature 原始内容
            signature = signature_part

            self.output.clear()
            # 格式化输出 Headers
            self.output.append("Headers = {")
            for k, v in header.items():
                self.output.append(f'    "{k}": "{v}",')
            self.output.append("}")
            self.output.append("\n")

            # 格式化输出 Payload
            self.output.append("Payload = {")
            for k, v in payload.items():
                # 处理时间戳转时间字符串（如果有 exp 字段等需要的话，这里简单示例，可扩展）
                if k == "exp":
                    exp_datetime = time.ctime(v)
                    self.output.append(f'    "{k}": {v}  # {exp_datetime},')
                else:
                    self.output.append(f'    "{k}": "{v}",')
            self.output.append("}")
            self.output.append("\n")

            # 输出 Signature
            self.output.append(f'Signature = "{signature}"')

            # 检查过期状态并设置状态栏
            if "exp" in payload:
                exp_time = payload["exp"]
                current_time = time.time()
                if exp_time > current_time:
                    self.set_status_bar_color("green")
                    self.status_bar.showMessage(f"✅ 未过期，过期时间: {time.ctime(exp_time)}")
                else:
                    self.set_status_bar_color("red")
                    self.status_bar.showMessage(f"❌ 已过期，过期时间: {time.ctime(exp_time)}")
            else:
                self.set_status_bar_color("yellow")
                self.status_bar.showMessage("JWT 未设置过期时间")

        except Exception as e:
            self.set_status_bar_color("red")
            QMessageBox.critical(self, "错误", f"解码失败: {str(e)}")

    def verify_jwt(self):
        jwt_str = self.jwt_input.toPlainText().strip()
        key = self.key_input.text().strip()
        alg = self.alg_combo.currentText()

        if not jwt_str or not key:
            QMessageBox.warning(self, "警告", "请输入 JWT 和密钥")
            return

        try:
            # 验证签名并解码
            decoded = jwt.decode(jwt_str, key, algorithms=[alg])
            self.output.clear()
            self.output.append("=== 验证结果 ===")
            self.output.append(f"JWT 验证通过，密钥为：{key}")
            self.output.append("=== 解码内容 ===")
            # 同样可以按照上面解码的格式化方式展示 decoded 内容，这里简单示例
            self.output.append(json.dumps(decoded, indent=4))
            self.set_status_bar_color("default")
            if "exp" in decoded:
                self.status_bar.showMessage(f"过期时间: {time.ctime(decoded['exp'])}")
            else:
                self.status_bar.showMessage("JWT 未设置过期时间")
        except jwt.ExpiredSignatureError:
            self.set_status_bar_color("red")
            QMessageBox.warning(self, "警告", "JWT 已过期")
        except jwt.InvalidTokenError as e:
            self.set_status_bar_color("red")
            QMessageBox.critical(self, "错误", f"验证失败: {str(e)}")
            self.output.setText(f'=== 验证结果 ===\nJWT 验证失败：{e}\n')
        except Exception as e:
            self.set_status_bar_color("red")
            QMessageBox.critical(self, "错误", f"发生异常: {str(e)}")
            self.output.setText(f'=== 验证结果 ===\nJWT 验证失败：{e}\n')

    def generate_jwt(self):
        key = self.key_input.text().strip()
        alg = self.alg_combo.currentText()

        if not key:
            QMessageBox.warning(self, "警告", "请输入密钥")
            return

        # 创建自定义载荷对话框
        dialog = QDialog(self)
        dialog.setWindowTitle("自定义 JWT 载荷")
        dialog.setMinimumWidth(600)

        layout = QVBoxLayout(dialog)

        # JSON 输入框
        json_label = QLabel("请输入 JSON 格式的载荷数据:")
        self.json_input = QTextEdit()
        self.json_input.setPlaceholderText('{"sub": "user123", "name": "John Doe", "exp": 1689340800}')

        # 常用字段快捷设置
        fields_group = QGroupBox("常用字段")
        fields_layout = QGridLayout(fields_group)

        # 过期时间设置
        self.exp_checkbox = QPushButton("添加过期时间 (1小时后)")
        self.exp_checkbox.clicked.connect(lambda: self.add_claim("exp", int(time.time() + 3600)))

        # 发布时间设置
        self.iat_checkbox = QPushButton("添加发布时间")
        self.iat_checkbox.clicked.connect(lambda: self.add_claim("iat", int(time.time())))

        # 发行人设置
        self.iss_label = QLabel("发行人 (iss):")
        self.iss_input = QLineEdit()

        # 主题设置
        self.sub_label = QLabel("主题 (sub):")
        self.sub_input = QLineEdit()

        # 添加常用字段到布局
        fields_layout.addWidget(self.exp_checkbox, 0, 0)
        fields_layout.addWidget(self.iat_checkbox, 0, 1)
        fields_layout.addWidget(self.iss_label, 1, 0)
        fields_layout.addWidget(self.iss_input, 1, 1)
        fields_layout.addWidget(self.sub_label, 2, 0)
        fields_layout.addWidget(self.sub_input, 2, 1)

        # 按钮布局
        btn_layout = QHBoxLayout()
        generate_btn = QPushButton("生成 JWT")
        generate_btn.clicked.connect(dialog.accept)
        cancel_btn = QPushButton("取消")
        cancel_btn.clicked.connect(dialog.reject)
        btn_layout.addWidget(generate_btn)
        btn_layout.addWidget(cancel_btn)

        # 添加所有组件到对话框布局
        layout.addWidget(json_label)
        layout.addWidget(self.json_input)
        layout.addWidget(fields_group)
        layout.addLayout(btn_layout)

        # 显示对话框
        if dialog.exec_():
            try:
                # 获取用户输入的 JSON 载荷
                json_text = self.json_input.toPlainText().strip()

                if json_text:
                    payload = json.loads(json_text)
                else:
                    payload = {}

                # 添加常用字段
                if self.iss_input.text().strip():
                    payload["iss"] = self.iss_input.text().strip()

                if self.sub_input.text().strip():
                    payload["sub"] = self.sub_input.text().strip()

                # 生成 JWT
                encoded = jwt.encode(payload, key, algorithm=alg)
                self.jwt_input.setText(encoded)
                self.output.clear()
                self.output.append("=== 生成结果 ===")
                self.output.append(f"生成的 JWT: {encoded}")

                # 显示过期时间和状态
                if "exp" in payload:
                    exp_time = payload["exp"]
                    exp_datetime = time.ctime(exp_time)

                    current_time = time.time()
                    if exp_time > current_time:
                        self.set_status_bar_color("green")
                        status_text = f"✅ 未过期: {exp_datetime}"
                    else:
                        self.set_status_bar_color("red")
                        status_text = f"❌ 已过期: {exp_datetime}"

                    self.status_bar.showMessage(status_text)
                else:
                    self.set_status_bar_color("yellow")
                    self.status_bar.showMessage("JWT 未设置过期时间")

            except json.JSONDecodeError:
                self.set_status_bar_color("red")
                QMessageBox.critical(self, "错误", "无效的 JSON 格式")
            except Exception as e:
                self.set_status_bar_color("red")
                QMessageBox.critical(self, "错误", f"生成失败: {str(e)}")

    def add_claim(self, key, value):
        """向 JSON 输入框添加声明"""
        try:
            current_text = self.json_input.toPlainText().strip()

            if not current_text:
                # 空输入，创建新的 JSON 对象
                payload = {key: value}
                self.json_input.setText(json.dumps(payload, indent=2))
            else:
                # 解析现有 JSON 并添加新声明
                payload = json.loads(current_text)
                payload[key] = value
                self.json_input.setText(json.dumps(payload, indent=2))
        except json.JSONDecodeError:
            QMessageBox.warning(self, "警告", "现有内容不是有效的 JSON 格式")

    def brute_force_key(self):
        jwt_str = self.jwt_input.toPlainText().strip()
        if not jwt_str:
            QMessageBox.warning(self, "警告", "请输入 JWT")
            return

        try:
            # 手动解析头部获取算法
            parts = jwt_str.split('.')
            if len(parts) != 3:
                raise ValueError("JWT 格式不正确")

            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8'))
            alg = header.get("alg", "HS256")

            # 确保使用对称加密算法进行爆破
            if alg not in ["HS256", "HS384", "HS512"]:
                QMessageBox.warning(self, "警告", f"当前算法 {alg} 不支持密钥爆破")
                return

            # 从文件加载字典或使用内置字典
            file_path, _ = QFileDialog.getOpenFileName(
                self, "选择字典文件", "", "文本文件 (*.txt);;所有文件 (*)",
                options=QFileDialog.Options()
            )

            if file_path:
                with open(file_path, "r", encoding="utf-8",errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            else:
                # 默认简单字典
                wordlist = ["secret", "key", "password", "123456", "admin", "test"]

            self.output.clear()
            self.output.append(f"=== 开始使用 {alg} 算法爆破密钥 ===")
            self.output.append(f"字典大小: {len(wordlist)} 个候选")

            # 设置状态栏为处理中状态
            self.set_status_bar_color("blue")
            self.status_bar.showMessage("正在进行密钥爆破...")

            found = False
            for i, candidate in enumerate(wordlist):
                try:
                    # 每1000次尝试更新一次界面
                    if i % 1000 == 0:
                        self.output.append(f"尝试中... ({i}/{len(wordlist)})")
                        QApplication.processEvents()

                    # 尝试验证签名
                    jwt.decode(jwt_str, candidate, algorithms=[alg])
                    self.output.append(f"\n✅ 找到密钥: {candidate}")

                    # 找到密钥 - 绿色
                    self.set_status_bar_color("green")
                    self.status_bar.showMessage(f"找到密钥: {candidate}")
                    found = True
                    break
                except jwt.InvalidTokenError:
                    continue

            if not found:
                # 未找到 - 红色
                self.set_status_bar_color("red")
                self.output.append("\n❌ 未找到有效密钥")
                self.status_bar.showMessage("密钥爆破完成: 未找到有效密钥")

        except Exception as e:
            # 错误 - 红色
            self.set_status_bar_color("red")
            QMessageBox.critical(self, "错误", f"爆破失败: {str(e)}")

    def set_status_bar_color(self, color):
        """设置状态栏背景颜色"""
        palette = self.status_bar.palette()

        if color == "red":
            palette.setColor(QPalette.Window, QColor(255, 200, 200))
        elif color == "green":
            palette.setColor(QPalette.Window, QColor(200, 255, 200))
        elif color == "yellow":
            palette.setColor(QPalette.Window, QColor(255, 255, 200))
        elif color == "blue":
            palette.setColor(QPalette.Window, QColor(200, 200, 255))
        else:  # 默认
            palette.setColor(QPalette.Window, QColor(240, 240, 240))

        self.status_bar.setAutoFillBackground(True)
        self.status_bar.setPalette(palette)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = JWTUtility()
    window.show()
    sys.exit(app.exec_())