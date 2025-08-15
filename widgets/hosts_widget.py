"""
Author: Gre3nStars
Date: 2025-07-21 17:11:32
LastEditTime: 2025-08-08 17:23:29
Description: 
FilePath: ToolBox_internal/widgets/hosts_widget.py
Copyright: Copyright (c) 2025 by Gre3nStars, All Rights Reserved. 
"""
import sys
import os
import re
import json

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QTextEdit, QPushButton, QLabel, QMessageBox,
    QMenuBar, QMenu, QFrame, QProgressDialog, QGroupBox
)
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QFont, QColor
from PySide6.QtCore import Qt, QUrl, QThread, QEventLoop, QRegularExpression
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QNetworkReply

# hosts 文件路径
HOSTS_PATH = "C:/Windows/System32/drivers/etc/hosts" if os.name == "nt" else "/etc/hosts"

class HostsHighlighter(QSyntaxHighlighter):
    """语法高亮器，用于高亮显示hosts文件内容"""

    def __init__(self, parent=None):
        super().__init__(parent)

        # 定义不同部分的格式
        ip_format = QTextCharFormat()
        ip_format.setForeground(QColor("#0000FF"))  # 蓝色
        ip_format.setFontWeight(QFont.Bold)

        domain_format = QTextCharFormat()
        domain_format.setForeground(QColor("#008000"))  # 绿色

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#808080"))  # 灰色
        comment_format.setFontItalic(True)

        localhost_format = QTextCharFormat()
        localhost_format.setForeground(QColor("#9370DB"))  # 紫色
        localhost_format.setFontWeight(QFont.Bold)

        # 匹配规则
        self.highlighting_rules = [
            (QRegularExpression(r"#.*"), comment_format),  # 注释 - 放在前面以优先匹配
            (QRegularExpression(r"\b127\.0\.0\.1\b"), localhost_format),  # 本地主机IP
            (QRegularExpression(r"\b::1\b"), localhost_format),  # IPv6本地主机
            (QRegularExpression(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), ip_format),  # IP地址
            (QRegularExpression(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"), domain_format),  # 域名
        ]

    # def highlightBlock(self, text):
    #     """应用高亮规则到文本块"""
    #     for pattern, format in self.highlighting_rules:
    #         expression = QRegularExpression(pattern)
    #         index = expression.indexIn(text)
    #         while index >= 0:
    #             length = expression.matchedLength()
    #             self.setFormat(index, length, format)
    #             index = expression.indexIn(text, index + length)

    def highlightBlock(self, text):
        """应用高亮规则到文本块"""
        for pattern, format in self.highlighting_rules:
            expression = QRegularExpression(pattern)
            # 使用globalMatch()获取所有匹配
            iterator = expression.globalMatch(text)
            while iterator.hasNext():
                match = iterator.next()
                # 获取匹配的起始位置和长度
                start = match.capturedStart()
                length = match.capturedLength()
                self.setFormat(start, length, format)


class HostsTool(QWidget):
    def __init__(self):
        super().__init__()
        # 先初始化核心组件
        self.init_core_components()
        # 再初始化UI
        self.init_ui()
        # 最后加载内容
        self.refresh_hosts()

    def init_core_components(self):
        """初始化核心组件，确保在其他方法调用前创建"""
        # 创建带语法高亮的文本编辑框
        self.text_edit = QTextEdit()
        self.text_edit.setLineWrapMode(QTextEdit.NoWrap)  # 不自动换行
        self.highlighter = HostsHighlighter(self.text_edit.document())

        # 网络访问管理器
        self.network_manager = QNetworkAccessManager(self)

    def init_ui(self):
        # 设置窗口基本属性
        self.setWindowTitle("Hosts编辑工具")
        self.setGeometry(100, 100, 800, 600)

        # 创建主布局
        main_layout = QVBoxLayout()
        # 创建主窗口groupbox
        display_group = QGroupBox()
        text_layout = QVBoxLayout()
        text_layout.addWidget(self.text_edit)
        display_group.setLayout(text_layout)
        # 顶部操作按钮布局 - 居中显示
        button_container = QFrame()
        button_layout = QHBoxLayout(button_container)
        button_layout.setAlignment(Qt.AlignCenter)  # 按钮居中对齐

        # 设置按钮样式
        # button_style = """
        #     QPushButton {
        #         padding: 6px 10px;
        #         margin: 0 5px;
        #         font-size: 10px;
        #         border-radius: 4px;
        #         background-color: #f0f0f0;
        #         border: 1px solid #ccc;
        #     }
        #     QPushButton:hover {
        #         background-color: #e0e0e0;
        #     }
        #     QPushButton:pressed {
        #         background-color: #d0d0d0;
        #     }
        # """
        button_group = QGroupBox()

        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.setToolTip("重新加载hosts文件内容")
        self.btn_refresh.clicked.connect(self.refresh_hosts)
        # self.btn_refresh.setStyleSheet(button_style)

        self.btn_save = QPushButton("保存")
        self.btn_save.setToolTip("保存修改到hosts文件")
        self.btn_save.clicked.connect(self.save_hosts)
        # self.btn_save.setStyleSheet(button_style)

        self.btn_format = QPushButton("格式化")
        self.btn_format.setToolTip("格式化内容，使其更易读")
        self.btn_format.clicked.connect(self.format_hosts)
        # self.btn_format.setStyleSheet(button_style)

        self.btn_clear = QPushButton("清空")
        self.btn_clear.setToolTip("清空当前编辑区内容")
        self.btn_clear.clicked.connect(self.clear_content)
        # self.btn_clear.setStyleSheet(button_style)

        button_layout.addWidget(self.btn_refresh)
        button_layout.addWidget(self.btn_save)
        button_layout.addWidget(self.btn_format)
        # button_layout.addWidget(self.btn_add_github)
        button_layout.addWidget(self.btn_clear)

        # 底部状态栏
        status_layout = QHBoxLayout()
        status_layout.setAlignment(Qt.AlignRight)
        self.status_label = QLabel("就绪")

        status_layout.addStretch()
        status_layout.addWidget(self.status_label)

        # 组装主布局
        button_group.setLayout(button_layout)

        main_layout.addWidget(display_group)

        main_layout.addWidget(button_group)
        main_layout.addLayout(status_layout)

        self.setLayout(main_layout)

    def refresh_hosts(self):
        """读取并显示hosts文件内容"""
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                content = f.read()
                self.text_edit.setText(content)
                self.status_label.setText(f"已加载: {HOSTS_PATH}")
        except FileNotFoundError:
            QMessageBox.critical(self, "错误", f"未找到hosts文件: {HOSTS_PATH}")
            self.status_label.setText("加载失败: 文件未找到")
        except PermissionError:
            QMessageBox.critical(self, "权限错误",
                                 f"没有足够权限读取hosts文件，请以管理员身份运行。\n路径: {HOSTS_PATH}")
            self.status_label.setText("加载失败: 权限不足")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"读取hosts文件时出错: {str(e)}")
            self.status_label.setText(f"加载失败: {str(e)}")

    def save_hosts(self):
        """保存修改到hosts文件"""
        content = self.text_edit.toPlainText()
        try:
            # 保存前先创建备份
            self.create_backup(silent=True)

            with open(HOSTS_PATH, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "成功", "hosts文件已成功保存")
            self.status_label.setText("已保存修改")
        except PermissionError:
            QMessageBox.critical(self, "权限错误",
                                 f"没有足够权限写入hosts文件，请以管理员身份运行。\n路径: {HOSTS_PATH}")
            self.status_label.setText("保存失败: 权限不足")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"保存hosts文件时出错: {str(e)}")
            self.status_label.setText(f"保存失败: {str(e)}")

    def format_hosts(self):
        """格式化hosts内容，使其更易读"""
        content = self.text_edit.toPlainText()
        lines = content.split('\n')
        formatted_lines = []
        ip_domain_pattern = re.compile(r'^(\s*)(\d+\.\d+\.\d+\.\d+|\:\:1)(\s+)(.*?)(\s*#.*)?(\s*)$')

        for line in lines:
            original_line = line.strip()

            if not original_line:  # 空行保留
                formatted_lines.append('')
                continue

            if original_line.startswith('#'):  # 注释行
                # 处理注释，保持原有格式
                formatted_lines.append(line.rstrip())
                continue

            # 处理包含IP和域名的行
            match = ip_domain_pattern.match(line)
            if match:
                # 提取各个部分
                leading_space, ip, spaces, domain, comment, trailing_space = match.groups()
                # 标准化格式：IP + 多个空格 + 域名 + 注释（如果有）
                formatted_line = f"{ip}\t{domain}"
                if comment:
                    formatted_line += f" {comment.strip()}"
                formatted_lines.append(formatted_line)
            else:
                # 无法识别的行，保持原样
                formatted_lines.append(line.rstrip())

        # 重新组合所有行
        formatted_content = '\n'.join(formatted_lines)
        self.text_edit.setText(formatted_content)
        self.status_label.setText("内容已格式化")

    def get_current_time(self):
        """获取当前时间字符串"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def clear_content(self):
        """清空编辑区内容"""
        reply = QMessageBox.question(self, "确认",
                                     "确定要清空当前内容吗？未保存的修改将会丢失。",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.text_edit.clear()
            self.status_label.setText("内容已清空")

    def create_backup(self, silent=False):
        """创建hosts文件备份"""
        backup_path = f"{HOSTS_PATH}.backup"
        try:
            with open(HOSTS_PATH, "r", encoding="utf-8") as f:
                content = f.read()

            with open(backup_path, "w", encoding="utf-8") as f:
                f.write(content)

            if not silent:
                QMessageBox.information(self, "成功", f"已创建备份: {backup_path}")
                self.status_label.setText(f"已创建备份")
            return True
        except Exception as e:
            if not silent:
                QMessageBox.critical(self, "错误", f"创建备份失败: {str(e)}")
            return False

    def restore_from_backup(self):
        """从备份恢复hosts文件"""
        backup_path = f"{HOSTS_PATH}.backup"
        try:
            if not os.path.exists(backup_path):
                QMessageBox.warning(self, "警告", f"未找到备份文件: {backup_path}")
                return

            with open(backup_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.text_edit.setText(content)
            QMessageBox.information(self, "成功", f"已从备份恢复: {backup_path}")
            self.status_label.setText(f"已从备份恢复")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"恢复备份失败: {str(e)}")



if __name__ == "__main__":
    app = QApplication(sys.argv)
    # 设置全局字体，确保中文显示正常
    tool = HostsTool()
    tool.show()
    sys.exit(app.exec_())