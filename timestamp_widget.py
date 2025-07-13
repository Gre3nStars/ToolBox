import sys
import time
import datetime
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QTextEdit, QGroupBox,
    QGridLayout, QTabWidget, QScrollArea, QFrame, QDateTimeEdit, QDateEdit, QTimeEdit
)
from PySide6.QtCore import Qt, QTimer, QDateTime, QDate, QTime
from PySide6.QtGui import QFont, QTextCursor


class TimestampTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Unix时间戳工具")
        self.setGeometry(100, 100, 1000, 700)

        # 时间戳类型（用于自动识别）
        self.timestamp_types = {
            "秒级时间戳": 1,
            "毫秒级时间戳": 1000,
            "微秒级时间戳": 1000000,
            "纳秒级时间戳": 1000000000
        }

        # 时区选项
        self.timezones = {
            "UTC": 0,
            "北京时间 (UTC+8)": 8,
            "东京时间 (UTC+9)": 9,
            "纽约时间 (UTC-5)": -5,
            "伦敦时间 (UTC+0)": 0,
            "巴黎时间 (UTC+1)": 1,
            "莫斯科时间 (UTC+3)": 3,
            "悉尼时间 (UTC+10)": 10,
            "洛杉矶时间 (UTC-8)": -8,
            "芝加哥时间 (UTC-6)": -6
        }

        # 当前时间更新定时器
        self.current_time_timer = QTimer()
        self.current_time_timer.timeout.connect(self.update_current_time)
        self.current_time_timer.start(1000)  # 每秒更新一次

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 创建主布局
        main_layout = QVBoxLayout(central_widget)

        # 创建标签页
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # 时间戳转换页面
        convert_tab = self.create_convert_tab()
        tab_widget.addTab(convert_tab, "时间戳转换")

        # 当前时间页面
        current_tab = self.create_current_time_tab()
        tab_widget.addTab(current_tab, "当前时间")

        # 批量转换页面
        batch_tab = self.create_batch_tab()
        tab_widget.addTab(batch_tab, "批量转换")

        # 帮助页面


    def create_convert_tab(self):
        """创建时间戳转换页面"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 时间戳转日期时间
        timestamp_to_datetime_group = QGroupBox("时间戳 → 日期时间 (自动识别类型)")
        timestamp_to_datetime_layout = QVBoxLayout(timestamp_to_datetime_group)

        # 输入区域
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("时间戳:"))
        self.timestamp_input = QLineEdit()
        self.timestamp_input.setPlaceholderText("输入时间戳，自动识别类型...")
        self.timestamp_input.textChanged.connect(self.on_timestamp_changed)
        self.timestamp_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
            QLineEdit:focus {
                border-color: #2196F3;
            }
        """)
        input_layout.addWidget(self.timestamp_input)

        # 时区选择
        input_layout.addWidget(QLabel("时区:"))
        self.timezone_combo = QComboBox()
        self.timezone_combo.addItems(self.timezones.keys())
        self.timezone_combo.currentTextChanged.connect(self.on_timestamp_changed)
        input_layout.addWidget(self.timezone_combo)

        # 转换按钮
        self.convert_btn = QPushButton("转换")
        self.convert_btn.clicked.connect(self.convert_timestamp)
        self.convert_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        input_layout.addWidget(self.convert_btn)

        timestamp_to_datetime_layout.addLayout(input_layout)

        # 结果显示
        self.timestamp_result = QTextEdit()
        self.timestamp_result.setReadOnly(True)
        # self.timestamp_result.setMaximumHeight(120)
        self.timestamp_result.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        timestamp_to_datetime_layout.addWidget(self.timestamp_result)

        layout.addWidget(timestamp_to_datetime_group)

        # 日期时间转时间戳
        datetime_to_timestamp_group = QGroupBox("日期时间 → 时间戳")
        datetime_to_timestamp_layout = QVBoxLayout(datetime_to_timestamp_group)

        # 使用QDateTimeEdit进行日期时间选择
        datetime_input_layout = QHBoxLayout()
        datetime_input_layout.addWidget(QLabel("选择日期时间:"))

        # 日期时间选择器
        self.datetime_edit = QDateTimeEdit()
        self.datetime_edit.setDateTime(QDateTime.currentDateTime())
        self.datetime_edit.setCalendarPopup(True)  # 启用日历弹出
        self.datetime_edit.setDisplayFormat("yyyy-MM-dd hh:mm:ss")
        self.datetime_edit.setStyleSheet("""
            QDateTimeEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
            }
            QDateTimeEdit:focus {
                border-color: #2196F3;
            }
        """)
        datetime_input_layout.addWidget(self.datetime_edit)

        # 转换按钮
        self.datetime_convert_btn = QPushButton("转换")
        self.datetime_convert_btn.clicked.connect(self.convert_datetime)
        self.datetime_convert_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        datetime_input_layout.addWidget(self.datetime_convert_btn)

        # 填充当前时间按钮
        self.fill_current_btn = QPushButton("当前时间")
        self.fill_current_btn.clicked.connect(self.fill_current_datetime)
        self.fill_current_btn.setStyleSheet("""
            QPushButton {
                background-color: #ff9800;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f57c00;
            }
        """)
        datetime_input_layout.addWidget(self.fill_current_btn)

        datetime_input_layout.addStretch()
        datetime_to_timestamp_layout.addLayout(datetime_input_layout)

        # 结果显示
        self.datetime_result = QTextEdit()
        self.datetime_result.setReadOnly(True)
        # self.datetime_result.setMaximumHeight(120)
        self.datetime_result.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        datetime_to_timestamp_layout.addWidget(self.datetime_result)

        layout.addWidget(datetime_to_timestamp_group)

        # 快速转换区域
        quick_convert_group = QGroupBox("快速转换")
        quick_convert_layout = QVBoxLayout(quick_convert_group)

        quick_buttons_layout = QHBoxLayout()

        # 常用时间戳转换按钮
        self.now_btn = QPushButton("当前时间戳")
        self.now_btn.clicked.connect(self.get_current_timestamp)
        self.now_btn.setStyleSheet("""
            QPushButton {
                background-color: #9C27B0;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #7B1FA2;
            }
        """)
        quick_buttons_layout.addWidget(self.now_btn)

        self.today_start_btn = QPushButton("今日开始")
        self.today_start_btn.clicked.connect(self.get_today_start)
        self.today_start_btn.setStyleSheet("""
            QPushButton {
                background-color: #607D8B;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #455A64;
            }
        """)
        quick_buttons_layout.addWidget(self.today_start_btn)

        self.today_end_btn = QPushButton("今日结束")
        self.today_end_btn.clicked.connect(self.get_today_end)
        self.today_end_btn.setStyleSheet("""
            QPushButton {
                background-color: #607D8B;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #455A64;
            }
        """)
        quick_buttons_layout.addWidget(self.today_end_btn)

        self.yesterday_btn = QPushButton("昨天")
        self.yesterday_btn.clicked.connect(self.get_yesterday)
        self.yesterday_btn.setStyleSheet("""
            QPushButton {
                background-color: #795548;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5D4037;
            }
        """)
        quick_buttons_layout.addWidget(self.yesterday_btn)

        self.tomorrow_btn = QPushButton("明天")
        self.tomorrow_btn.clicked.connect(self.get_tomorrow)
        self.tomorrow_btn.setStyleSheet("""
            QPushButton {
                background-color: #795548;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #5D4037;
            }
        """)
        quick_buttons_layout.addWidget(self.tomorrow_btn)

        quick_convert_layout.addLayout(quick_buttons_layout)

        # 快速转换结果
        self.quick_result = QTextEdit()
        self.quick_result.setReadOnly(True)
        # self.quick_result.setMaximumHeight(80)
        self.quick_result.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
            }
        """)
        quick_convert_layout.addWidget(self.quick_result)

        layout.addWidget(quick_convert_group)

        return widget

    def create_current_time_tab(self):
        """创建当前时间页面"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 当前时间显示
        current_time_group = QGroupBox("当前时间")
        current_time_layout = QVBoxLayout(current_time_group)

        # 实时时间显示
        self.current_time_label = QLabel()
        self.current_time_label.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                padding: 20px;
                background-color: #f8f9fa;
                border: 2px solid #2196F3;
                border-radius: 8px;
            }
        """)
        self.current_time_label.setAlignment(Qt.AlignCenter)
        current_time_layout.addWidget(self.current_time_label)

        # 不同时区的当前时间
        timezone_group = QGroupBox("各时区当前时间")
        timezone_layout = QVBoxLayout(timezone_group)

        self.timezone_labels = {}
        for timezone_name in self.timezones.keys():
            label = QLabel()
            label.setStyleSheet("""
                QLabel {
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    padding: 5px;
                }
            """)
            self.timezone_labels[timezone_name] = label
            timezone_layout.addWidget(label)

        current_time_layout.addWidget(timezone_group)

        # 当前时间戳
        current_timestamp_group = QGroupBox("当前时间戳")
        current_timestamp_layout = QVBoxLayout(current_timestamp_group)

        self.current_timestamp_labels = {}
        for timestamp_type in self.timestamp_types.keys():
            label = QLabel()
            label.setStyleSheet("""
                QLabel {
                    font-family: 'Courier New', monospace;
                    font-size: 14px;
                    padding: 5px;
                    background-color: #f0f0f0;
                    border-radius: 4px;
                }
            """)
            self.current_timestamp_labels[timestamp_type] = label
            current_timestamp_layout.addWidget(label)

        current_time_layout.addWidget(current_timestamp_group)

        layout.addWidget(current_time_group)

        return widget

    def create_batch_tab(self):
        """创建批量转换页面"""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # 批量输入
        batch_input_group = QGroupBox("批量时间戳输入 (自动识别类型)")
        batch_input_layout = QVBoxLayout(batch_input_group)

        batch_input_layout.addWidget(QLabel("每行一个时间戳:"))

        self.batch_input = QTextEdit()
        self.batch_input.setPlaceholderText(
            "输入多个时间戳，每行一个，自动识别类型...\n例如:\n1704067200\n1704153600000\n1704240000000000")
        # self.batch_input.setMaximumHeight(150)
        batch_input_layout.addWidget(self.batch_input)

        # 批量转换控制
        batch_control_layout = QHBoxLayout()

        batch_control_layout.addWidget(QLabel("时区:"))
        self.batch_timezone = QComboBox()
        self.batch_timezone.addItems(self.timezones.keys())
        batch_control_layout.addWidget(self.batch_timezone)

        self.batch_convert_btn = QPushButton("批量转换")
        self.batch_convert_btn.clicked.connect(self.batch_convert)
        self.batch_convert_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        batch_control_layout.addWidget(self.batch_convert_btn)

        batch_control_layout.addStretch()
        batch_input_layout.addLayout(batch_control_layout)

        layout.addWidget(batch_input_group)

        # 批量结果
        batch_result_group = QGroupBox("转换结果")
        batch_result_layout = QVBoxLayout(batch_result_group)

        self.batch_result = QTextEdit()
        self.batch_result.setReadOnly(True)
        batch_result_layout.addWidget(self.batch_result)

        layout.addWidget(batch_result_group)

        return widget


    def auto_detect_timestamp_type(self, timestamp_str):
        """自动识别时间戳类型"""
        try:
            timestamp = float(timestamp_str)
            timestamp_len = len(str(int(timestamp)))

            if timestamp_len == 10:
                return "秒级时间戳", 1
            elif timestamp_len == 13:
                return "毫秒级时间戳", 1000
            elif timestamp_len == 16:
                return "微秒级时间戳", 1000000
            elif timestamp_len == 19:
                return "纳秒级时间戳", 1000000000
            else:
                # 如果长度不匹配，尝试根据数值范围判断
                if timestamp < 10000000000:  # 小于10位，可能是秒级
                    return "秒级时间戳", 1
                elif timestamp < 10000000000000:  # 小于14位，可能是毫秒级
                    return "毫秒级时间戳", 1000
                elif timestamp < 10000000000000000:  # 小于17位，可能是微秒级
                    return "微秒级时间戳", 1000000
                else:
                    return "纳秒级时间戳", 1000000000
        except:
            return "未知类型", 1

    def update_current_time(self):
        """更新当前时间显示"""
        now = datetime.datetime.now()
        current_time_str = now.strftime("%Y-%m-%d %H:%M:%S")
        self.current_time_label.setText(f"当前时间: {current_time_str}")

        # 更新各时区时间
        for timezone_name, offset in self.timezones.items():
            if timezone_name in self.timezone_labels:
                utc_time = datetime.datetime.utcnow()
                local_time = utc_time + datetime.timedelta(hours=offset)
                time_str = local_time.strftime("%Y-%m-%d %H:%M:%S")
                self.timezone_labels[timezone_name].setText(f"{timezone_name}: {time_str}")

        # 更新当前时间戳
        current_timestamp = time.time()
        for timestamp_type, multiplier in self.timestamp_types.items():
            if timestamp_type in self.current_timestamp_labels:
                timestamp_value = int(current_timestamp * multiplier)
                self.current_timestamp_labels[timestamp_type].setText(f"{timestamp_type}: {timestamp_value}")

    def on_timestamp_changed(self):
        """时间戳输入变化时自动转换"""
        if self.timestamp_input.text().strip():
            self.convert_timestamp()

    def convert_timestamp(self):
        """转换时间戳为日期时间（自动识别类型）"""
        try:
            timestamp_str = self.timestamp_input.text().strip()
            if not timestamp_str:
                self.timestamp_result.setText("请输入时间戳")
                return

            # 自动识别时间戳类型
            detected_type, multiplier = self.auto_detect_timestamp_type(timestamp_str)
            timestamp = float(timestamp_str)

            # 转换为秒级时间戳
            seconds_timestamp = timestamp / multiplier

            # 转换为UTC时间
            utc_time = datetime.datetime.utcfromtimestamp(seconds_timestamp)

            # 应用时区偏移
            timezone_name = self.timezone_combo.currentText()
            offset = self.timezones[timezone_name]
            local_time = utc_time + datetime.timedelta(hours=offset)

            # 格式化输出
            result_text = f"输入时间戳: {timestamp_str}\n"
            result_text += f"自动识别类型: {detected_type}\n"
            result_text += f"UTC时间: {utc_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            result_text += f"{timezone_name}: {local_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            result_text += f"星期: {local_time.strftime('%A')}\n"
            result_text += f"秒级时间戳: {int(seconds_timestamp)}"

            self.timestamp_result.setText(result_text)

        except ValueError:
            self.timestamp_result.setText("错误: 无效的时间戳格式")
        except Exception as e:
            self.timestamp_result.setText(f"错误: {str(e)}")

    def convert_datetime(self):
        """转换日期时间为时间戳"""
        try:
            # 获取QDateTimeEdit的值
            qdatetime = self.datetime_edit.dateTime()

            # 转换为Python datetime
            dt = qdatetime.toPython()

            # 应用时区偏移
            timezone_name = self.timezone_combo.currentText()
            offset = self.timezones[timezone_name]
            utc_time = dt - datetime.timedelta(hours=offset)

            # 转换为时间戳
            timestamp = utc_time.timestamp()

            # 生成不同格式的时间戳
            result_text = f"输入时间: {dt.strftime('%Y-%m-%d %H:%M:%S')} ({timezone_name})\n"
            result_text += f"UTC时间: {utc_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            result_text += "时间戳:\n"
            result_text += f"秒级: {int(timestamp)}\n"
            result_text += f"毫秒级: {int(timestamp * 1000)}\n"
            result_text += f"微秒级: {int(timestamp * 1000000)}\n"
            result_text += f"纳秒级: {int(timestamp * 1000000000)}"

            self.datetime_result.setText(result_text)

        except Exception as e:
            self.datetime_result.setText(f"错误: {str(e)}")

    def fill_current_datetime(self):
        """填充当前时间"""
        current_datetime = QDateTime.currentDateTime()
        self.datetime_edit.setDateTime(current_datetime)

    def get_current_timestamp(self):
        """获取当前时间戳"""
        current_timestamp = time.time()
        result_text = "当前时间戳:\n"
        for timestamp_type, multiplier in self.timestamp_types.items():
            timestamp_value = int(current_timestamp * multiplier)
            result_text += f"{timestamp_type}: {timestamp_value}\n"
        self.quick_result.setText(result_text)

    def get_today_start(self):
        """获取今日开始时间戳"""
        today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        timestamp = today.timestamp()
        result_text = "今日开始时间戳:\n"
        for timestamp_type, multiplier in self.timestamp_types.items():
            timestamp_value = int(timestamp * multiplier)
            result_text += f"{timestamp_type}: {timestamp_value}\n"
        result_text += f"时间: {today.strftime('%Y-%m-%d %H:%M:%S')}"
        self.quick_result.setText(result_text)

    def get_today_end(self):
        """获取今日结束时间戳"""
        today_end = datetime.datetime.now().replace(hour=23, minute=59, second=59, microsecond=999999)
        timestamp = today_end.timestamp()
        result_text = "今日结束时间戳:\n"
        for timestamp_type, multiplier in self.timestamp_types.items():
            timestamp_value = int(timestamp * multiplier)
            result_text += f"{timestamp_type}: {timestamp_value}\n"
        result_text += f"时间: {today_end.strftime('%Y-%m-%d %H:%M:%S')}"
        self.quick_result.setText(result_text)

    def get_yesterday(self):
        """获取昨天时间戳"""
        yesterday = datetime.datetime.now() - datetime.timedelta(days=1)
        yesterday = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        timestamp = yesterday.timestamp()
        result_text = "昨天开始时间戳:\n"
        for timestamp_type, multiplier in self.timestamp_types.items():
            timestamp_value = int(timestamp * multiplier)
            result_text += f"{timestamp_type}: {timestamp_value}\n"
        result_text += f"时间: {yesterday.strftime('%Y-%m-%d %H:%M:%S')}"
        self.quick_result.setText(result_text)

    def get_tomorrow(self):
        """获取明天时间戳"""
        tomorrow = datetime.datetime.now() + datetime.timedelta(days=1)
        tomorrow = tomorrow.replace(hour=0, minute=0, second=0, microsecond=0)
        timestamp = tomorrow.timestamp()
        result_text = "明天开始时间戳:\n"
        for timestamp_type, multiplier in self.timestamp_types.items():
            timestamp_value = int(timestamp * multiplier)
            result_text += f"{timestamp_type}: {timestamp_value}\n"
        result_text += f"时间: {tomorrow.strftime('%Y-%m-%d %H:%M:%S')}"
        self.quick_result.setText(result_text)

    def batch_convert(self):
        """批量转换时间戳（自动识别类型）"""
        try:
            input_text = self.batch_input.toPlainText().strip()
            if not input_text:
                self.batch_result.setText("请输入要转换的时间戳")
                return

            timestamp_list = input_text.split('\n')
            timezone_name = self.batch_timezone.currentText()
            offset = self.timezones[timezone_name]

            result_text = f"批量转换结果 ({timezone_name}):\n"
            result_text += "=" * 50 + "\n\n"

            for i, timestamp_str in enumerate(timestamp_list, 1):
                timestamp_str = timestamp_str.strip()
                if not timestamp_str:
                    continue

                try:
                    # 自动识别时间戳类型
                    detected_type, multiplier = self.auto_detect_timestamp_type(timestamp_str)
                    timestamp = float(timestamp_str)
                    seconds_timestamp = timestamp / multiplier
                    utc_time = datetime.datetime.utcfromtimestamp(seconds_timestamp)
                    local_time = utc_time + datetime.timedelta(hours=offset)

                    result_text += f"{i}. 时间戳: {timestamp_str}\n"
                    result_text += f"   识别类型: {detected_type}\n"
                    result_text += f"   时间: {local_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    result_text += f"   星期: {local_time.strftime('%A')}\n\n"

                except ValueError:
                    result_text += f"{i}. 时间戳: {timestamp_str} (格式错误)\n\n"
                except Exception as e:
                    result_text += f"{i}. 时间戳: {timestamp_str} (转换错误: {str(e)})\n\n"

            self.batch_result.setText(result_text)

        except Exception as e:
            self.batch_result.setText(f"批量转换错误: {str(e)}")


def main():
    app = QApplication(sys.argv)

    # 设置应用样式
    # app.setStyle('Fusion')

    # 设置应用信息
    app.setApplicationName("Unix时间戳工具")
    app.setApplicationVersion("2.0")

    # 创建主窗口
    window = TimestampTool()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()