import sys
import re
import ipaddress
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
    QPushButton, QGridLayout, QVBoxLayout, QHBoxLayout,
    QComboBox, QGroupBox, QTextEdit, QTabWidget, QScrollArea,
    QFormLayout, QSpacerItem, QSizePolicy, QToolBar,
    QMenu, QMenuBar, QMessageBox, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, QSize, QTimer, Signal, Slot
from PySide6.QtGui import (
    QFont, QPalette, QColor, QIcon, QIntValidator, QDoubleValidator,
    QGuiApplication, QClipboard, QPixmap, QAction
)


class IPAddressCalculator(QMainWindow):
    def __init__(self):
        super().__init__()
        # 保存历史记录
        self.calculation_history = []
        self.max_history_count = 10

        # 初始化样式
        self.is_dark_mode = False
        self.init_styles()

        # 设置窗口基本属性
        self.setWindowTitle("IP地址计算器工具")
        self.setGeometry(100, 100, 1000, 650)


        # 创建中心部件和主布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        # main_layout.setContentsMargins(8, 8, 8, 8)
        # main_layout.setSpacing(8)


        # 创建标签页控件 - 直接作为主内容
        self.tab_widget = QTabWidget()
        # self.tab_widget.setTabShape(QTabWidget.Rounded)
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        main_layout.addWidget(self.tab_widget)

        # 创建滚动区域用于每个标签页
        self.create_tabs()

        # 创建状态栏
        self.statusBar().showMessage("就绪")

        # 应用初始样式
        self.apply_styles()

    def init_styles(self):
        """初始化样式表 - 重点优化分组栏样式"""
        # 亮色主题
        self.light_style = """
            QMainWindow {
                background-color: #f5f5f7;
            }
            QLineEdit {
                padding: 7px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                background-color: #ffffff;
            }
            QLineEdit:readOnly {
                background-color: #f0f0f0;
                color: #555555;
            }
            QLineEdit.error {
                border: 1px solid #ff6b6b;
                background-color: #fff5f5;
            }
            QLineEdit.success {
                border: 1px solid #4ecdc4;
            }
            QPushButton {
                background-color: #4285f4;
                color: white;
                border-radius: 5px;
                padding: 7px 14px;
                border: none;
                transition: all 0.2s ease;
            }
            QPushButton:hover {
                background-color: #3367d6;
                transform: scale(1.02);
            }
            QPushButton:pressed {
                background-color: #2850b3;
                transform: scale(0.98);
            }
            QPushButton#clearBtn {
                background-color: #f0f0f0;
                color: #555555;
            }
            QPushButton#clearBtn:hover {
                background-color: #e0e0e0;
            }
            QPushButton#copyBtn {
                background-color: #4ecdc4;
                color: white;
            }
            QPushButton#copyBtn:hover {
                background-color: #3dbbaf;
            }
            QTextEdit {
                border: 1px solid #cccccc;
                border-radius: 5px;
                padding: 7px;
            }
            QComboBox {
                padding: 7px;
                border: 1px solid #cccccc;
                border-radius: 5px;
                background-color: white;
            }
            QTabBar::tab {
                padding: 9px 18px;
                border: 1px solid #e0e0e0;
                border-bottom-color: #e0e0e0;
                border-radius: 6px 6px 0 0;
                background-color: #f0f0f0;
                transition: all 0.2s ease;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-color: #e0e0e0;
                border-bottom-color: white;
                font-weight: bold;
            }
            QTabBar::tab:hover:!selected {
                background-color: #e8e8e8;
            }
            QToolBar {
                background-color: #f0f0f0;
                border: none;
                spacing: 5px;
            }
            QListWidget {
                border: 1px solid #cccccc;
                border-radius: 5px;
                padding: 5px;
            }
        """

    def apply_styles(self):
        """应用当前主题样式"""
        self.setStyleSheet(self.light_style)

        # 更新所有结果区域的样式
        for attr in dir(self):
            if attr.startswith('txt_result') or attr.startswith('txt_') and 'usable' in attr or 'mask' in attr:
                widget = getattr(self, attr, None)
                if isinstance(widget, (QLineEdit, QTextEdit)):
                    widget.setStyleSheet("")  # 触发样式重绘



    def create_tabs(self):
        """创建各个功能标签页"""
        # 1. 网络和IP地址计算器
        self.create_network_ip_tab()

        # 2. 掩码位元数计算器
        self.create_cidr_to_subnet_tab()

        # 3. 掩码位元数转换
        self.create_cidr_convert_tab()

        # 4. 主机数量计算子网掩码
        self.create_host_count_tab()

        # 5. IP地址子网掩码计算器
        self.create_ip_subnet_tab()

        # 6. 网络/节点计算器
        self.create_network_node_tab()

        # 7. 子网掩码换算器
        self.create_subnet_converter_tab()

        # 8. 历史记录
        self.create_history_tab()

        # 9. 帮助说明
        self.create_help_tab()

    def create_scrollable_tab(self, title):
        """创建带滚动区域的标签页"""
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(10, 10, 10, 10)
        scroll_layout.setSpacing(15)
        scroll_area.setWidget(scroll_content)
        self.tab_widget.addTab(scroll_area, title)
        return scroll_layout

    def create_clear_button(self):
        """创建清除按钮"""
        btn = QPushButton("清除")
        btn.setObjectName("clearBtn")
        btn.setMinimumHeight(30)
        return btn

    def create_copy_button(self, target_widgets):
        """创建复制按钮"""
        btn = QPushButton("复制结果")
        btn.setObjectName("copyBtn")
        btn.clicked.connect(lambda: self.copy_results(target_widgets))
        return btn

    def copy_results(self, widgets):
        """复制结果到剪贴板"""
        clipboard = QGuiApplication.clipboard()
        result_text = []

        for widget in widgets:
            if isinstance(widget, tuple) and len(widget) == 2:
                label, field = widget
                if hasattr(label, 'text') and hasattr(field, 'text'):
                    result_text.append(f"{label.text().rstrip(':')}: {field.text()}")
            elif hasattr(widget, 'text'):
                result_text.append(widget.text())

        clipboard.setText("\n".join(result_text))
        self.statusBar().showMessage("结果已复制到剪贴板")

        # 显示短暂提示
        temp_label = QLabel("✓ 已复制")
        temp_label.setStyleSheet("""
            background-color: #4ecdc4; 
            color: white; 
            padding: 5px 10px; 
            border-radius: 4px;
        """)
        temp_label.setParent(self.centralWidget())
        temp_label.move(self.width() - 100, 20)
        temp_label.show()

        # 3秒后隐藏提示
        QTimer.singleShot(3000, temp_label.hide)

    def add_to_history(self, operation, result):
        """添加计算记录到历史"""
        self.calculation_history.insert(0, (operation, result))
        if len(self.calculation_history) > self.max_history_count:
            self.calculation_history.pop()
        self.update_history_list()

    def clear_history(self):
        """清除计算历史"""
        self.calculation_history = []
        self.update_history_list()
        self.statusBar().showMessage("计算历史已清除")

    def update_history_list(self):
        """更新历史记录列表"""
        if hasattr(self, 'history_list'):
            self.history_list.clear()
            for i, (op, res) in enumerate(self.calculation_history):
                item = QListWidgetItem(f"{i + 1}. {op}")
                item.setData(Qt.UserRole, res)
                self.history_list.addItem(item)

    def create_history_tab(self):
        """创建历史记录标签页"""
        layout = self.create_scrollable_tab("📜 计算历史")

        history_group = QGroupBox("最近计算记录")
        history_layout = QVBoxLayout(history_group)

        self.history_list = QListWidget()
        self.history_list.setMinimumHeight(300)
        self.history_list.itemClicked.connect(self.load_history_item)

        btn_layout = QHBoxLayout()
        btn_clear_history = QPushButton("清除历史")
        btn_clear_history.clicked.connect(self.clear_history)

        btn_layout.addWidget(btn_clear_history)
        btn_layout.addStretch()

        history_layout.addWidget(self.history_list)
        history_layout.addLayout(btn_layout)

        layout.addWidget(history_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def load_history_item(self, item):
        """加载历史记录项"""
        result_data = item.data(Qt.UserRole)
        if result_data and 'tab_index' in result_data:
            # 切换到相应的标签页
            self.tab_widget.setCurrentIndex(result_data['tab_index'])

            # 填充输入数据
            if 'inputs' in result_data:
                for input_field, value in result_data['inputs'].items():
                    if hasattr(self, input_field) and hasattr(getattr(self, input_field), 'setText'):
                        getattr(self, input_field).setText(value)

            # 填充输出数据
            if 'outputs' in result_data:
                for output_field, value in result_data['outputs'].items():
                    if hasattr(self, output_field) and hasattr(getattr(self, output_field), 'setText'):
                        getattr(self, output_field).setText(value)

        self.statusBar().showMessage("已加载历史记录")

    def on_tab_changed(self, index):
        """标签页切换时的处理"""
        self.statusBar().showMessage(f"已切换到 {self.tab_widget.tabText(index)}")

    def validate_ip(self, ip):
        """验证IP地址格式"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None

    def validate_cidr(self, cidr):
        """验证CIDR格式"""
        try:
            cidr_int = int(cidr.lstrip('/'))
            return 0 <= cidr_int <= 32
        except:
            return False

    def highlight_input(self, widget, is_valid):
        """高亮显示输入框状态"""
        if is_valid:
            widget.setProperty("error", False)
            widget.setProperty("success", True)
        else:
            widget.setProperty("error", True)
            widget.setProperty("success", False)
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    def create_network_ip_tab(self):
        """创建网络和IP地址计算器标签页"""
        layout = self.create_scrollable_tab("🌐 网络和IP地址计算器")

        # 输入区域 - 优化分组显示
        input_group = QGroupBox("输入参数")
        input_layout = QVBoxLayout(input_group)
        # input_layout.setSpacing(12)
        # input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_ip_cidr = QLabel("IP/掩码（如 192.168.0.1/29）:")
        self.txt_ip_cidr = QLineEdit()
        self.txt_ip_cidr.setPlaceholderText("例如: 192.168.1.1/24 或 10.0.0.5")
        # self.txt_ip_cidr.setMinimumWidth(250)
        self.txt_ip_cidr.textChanged.connect(self.validate_ip_cidr_input)

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_calc_network = QPushButton("计算")
        btn_calc_network.clicked.connect(self.calc_network_ip)
        # btn_calc_network.setMinimumHeight(30)

        self.btn_clear_network = self.create_clear_button()
        self.btn_clear_network.clicked.connect(lambda: self.reset_fields([
            self.txt_ip_cidr, self.txt_usable, self.txt_mask, self.txt_network,
            self.txt_first, self.txt_last, self.txt_broadcast
        ]))

        btn_layout.addWidget(btn_calc_network)
        btn_layout.addWidget(self.btn_clear_network)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # btn_layout.setSpacing(10)

        # input_layout.addWidget(lbl_ip_cidr, 0, 0, Qt.AlignVCenter)
        # input_layout.addWidget(self.txt_ip_cidr, 0, 1)
        # input_layout.addLayout(btn_layout, 0, 2)
        # input_layout.setColumnStretch(1, 1)

        input_layout.addWidget(lbl_ip_cidr)
        input_layout.addWidget(self.txt_ip_cidr)
        input_layout.addLayout(btn_layout)
        # input_layout.setColumnStretch(1, 1)

        # 输出区域 - 优化分组显示
        output_group = QGroupBox("计算结果")
        output_layout = QGridLayout(output_group)
        # output_layout.setSpacing(12)
        # output_layout.setContentsMargins(5, 5, 5, 5)

        lbl_usable = QLabel("可用地址数量:")
        self.txt_usable = QLineEdit(readOnly=True)
        self.txt_usable.setMinimumWidth(150)

        lbl_mask = QLabel("子网掩码:")
        self.txt_mask = QLineEdit(readOnly=True)
        self.txt_mask.setMinimumWidth(150)

        lbl_network = QLabel("网络地址:")
        self.txt_network = QLineEdit(readOnly=True)
        self.txt_network.setMinimumWidth(150)

        lbl_first = QLabel("第一个可用地址:")
        self.txt_first = QLineEdit(readOnly=True)
        self.txt_first.setMinimumWidth(150)

        lbl_last = QLabel("最后可用地址:")
        self.txt_last = QLineEdit(readOnly=True)
        self.txt_last.setMinimumWidth(150)

        lbl_broadcast = QLabel("广播地址:")
        self.txt_broadcast = QLineEdit(readOnly=True)
        self.txt_broadcast.setMinimumWidth(150)

        # 复制按钮
        copy_widgets = [
            (lbl_usable, self.txt_usable),
            (lbl_mask, self.txt_mask),
            (lbl_network, self.txt_network),
            (lbl_first, self.txt_first),
            (lbl_last, self.txt_last),
            (lbl_broadcast, self.txt_broadcast)
        ]
        self.btn_copy_network = self.create_copy_button(copy_widgets)

        output_layout.addWidget(lbl_usable, 0, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_usable, 0, 1)
        output_layout.addWidget(lbl_mask, 0, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_mask, 0, 3)
        output_layout.addWidget(lbl_network, 1, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_network, 1, 1)
        output_layout.addWidget(lbl_first, 1, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_first, 1, 3)
        output_layout.addWidget(lbl_last, 2, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_last, 2, 1)
        output_layout.addWidget(lbl_broadcast, 2, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_broadcast, 2, 3)
        output_layout.addWidget(self.btn_copy_network, 3, 3, Qt.AlignRight)

        # 设置列拉伸，确保内容不被截断
        # output_layout.setColumnStretch(1, 1)
        # output_layout.setColumnStretch(3, 1)

        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def validate_ip_cidr_input(self):
        """验证IP/CIDR输入"""
        text = self.txt_ip_cidr.text()
        if '/' in text:
            ip_part, cidr_part = text.split('/', 1)
            ip_valid = self.validate_ip(ip_part)
            cidr_valid = self.validate_cidr(cidr_part)
            self.highlight_input(self.txt_ip_cidr, ip_valid and cidr_valid)
        else:
            # 单独的IP地址
            self.highlight_input(self.txt_ip_cidr, self.validate_ip(text))

    def calc_network_ip(self):
        """计算网络和IP地址信息"""
        try:
            ip_cidr = self.txt_ip_cidr.text()
            # 处理只输入IP的情况，默认添加/32
            if '/' not in ip_cidr:
                ip_cidr += '/32'

            network = ipaddress.IPv4Network(ip_cidr, strict=False)
            self.txt_usable.setText(str(network.num_addresses - 2))  # 减去网络和广播
            self.txt_mask.setText(str(network.netmask))
            self.txt_network.setText(str(network.network_address))

            # 处理主机地址情况（/32）
            if network.num_addresses > 1:
                self.txt_first.setText(str(network.network_address + 1))
                self.txt_last.setText(str(network.broadcast_address - 1))
                self.txt_broadcast.setText(str(network.broadcast_address))
            else:
                self.txt_first.setText("无")
                self.txt_last.setText("无")
                self.txt_broadcast.setText("无")

            self.statusBar().showMessage("计算成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 0,
                'inputs': {'txt_ip_cidr': ip_cidr},
                'outputs': {
                    'txt_usable': self.txt_usable.text(),
                    'txt_mask': self.txt_mask.text(),
                    'txt_network': self.txt_network.text(),
                    'txt_first': self.txt_first.text(),
                    'txt_last': self.txt_last.text(),
                    'txt_broadcast': self.txt_broadcast.text()
                }
            }
            self.add_to_history(f"网络计算: {ip_cidr}", history_data)

        except Exception as e:
            self.reset_fields([
                self.txt_usable, self.txt_mask, self.txt_network,
                self.txt_first, self.txt_last, self.txt_broadcast
            ])
            self.txt_usable.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_ip_cidr, False)
            self.statusBar().showMessage(f"计算错误: {str(e)}")

    def create_cidr_to_subnet_tab(self):
        """创建通过掩码位元数计算子网掩码标签页"""
        layout = self.create_scrollable_tab("🔢 掩码位元数计算子网掩码")

        # 输入区域
        input_group = QGroupBox("输入参数")
        input_layout = QVBoxLayout(input_group)
        input_layout.setSpacing(12)
        input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_cidr = QLabel("掩码位元数（如 27 或 /27）:")
        self.txt_cidr = QLineEdit()
        self.txt_cidr.setPlaceholderText("例如: 24 或 /24")
        self.txt_cidr.setMinimumWidth(200)
        self.txt_cidr.textChanged.connect(lambda: self.highlight_input(
            self.txt_cidr, self.validate_cidr(self.txt_cidr.text())))

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_calc_cidr = QPushButton("计算")
        btn_calc_cidr.clicked.connect(self.calc_cidr_subnet)
        btn_calc_cidr.setMinimumHeight(30)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn_clear_cidr = self.create_clear_button()
        self.btn_clear_cidr.clicked.connect(lambda: self.reset_fields([
            self.txt_cidr, self.txt_cidr_usable, self.txt_cidr_total,
            self.txt_cidr_subnet, self.txt_cidr_wildcard
        ]))

        btn_layout.addWidget(btn_calc_cidr)
        btn_layout.addWidget(self.btn_clear_cidr)
        btn_layout.setSpacing(10)

        input_layout.addWidget(lbl_cidr)
        input_layout.addWidget(self.txt_cidr)
        input_layout.addLayout(btn_layout)
        # input_layout.setColumnStretch(1, 1)

        # 输出区域
        output_group = QGroupBox("计算结果")
        output_layout = QGridLayout(output_group)
        output_layout.setSpacing(12)
        output_layout.setContentsMargins(5, 5, 5, 5)

        lbl_usable = QLabel("可用地址数量:")
        self.txt_cidr_usable = QLineEdit(readOnly=True)
        self.txt_cidr_usable.setMinimumWidth(150)

        lbl_total = QLabel("地址总数:")
        self.txt_cidr_total = QLineEdit(readOnly=True)
        self.txt_cidr_total.setMinimumWidth(150)

        lbl_subnet = QLabel("子网掩码:")
        self.txt_cidr_subnet = QLineEdit(readOnly=True)
        self.txt_cidr_subnet.setMinimumWidth(150)

        lbl_wildcard = QLabel("通配符掩码:")
        self.txt_cidr_wildcard = QLineEdit(readOnly=True)
        self.txt_cidr_wildcard.setMinimumWidth(150)

        # 复制按钮
        copy_widgets = [
            (lbl_usable, self.txt_cidr_usable),
            (lbl_total, self.txt_cidr_total),
            (lbl_subnet, self.txt_cidr_subnet),
            (lbl_wildcard, self.txt_cidr_wildcard)
        ]
        self.btn_copy_cidr = self.create_copy_button(copy_widgets)

        output_layout.addWidget(lbl_usable, 0, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_cidr_usable, 0, 1)
        output_layout.addWidget(lbl_total, 0, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_cidr_total, 0, 3)
        output_layout.addWidget(lbl_subnet, 1, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_cidr_subnet, 1, 1)
        output_layout.addWidget(lbl_wildcard, 1, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_cidr_wildcard, 1, 3)
        output_layout.addWidget(self.btn_copy_cidr, 2, 3, Qt.AlignRight)

        # 设置列拉伸
        output_layout.setColumnStretch(1, 1)
        output_layout.setColumnStretch(3, 1)

        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def calc_cidr_subnet(self):
        """通过CIDR计算子网掩码"""
        try:
            cidr = self.txt_cidr.text().lstrip("/")
            prefix = int(cidr)

            if prefix < 0 or prefix > 32:
                raise ValueError("掩码位元数必须在0-32之间")

            netmask = ipaddress.IPv4Address(0xFFFFFFFF ^ (1 << (32 - prefix)) - 1)
            wildcard = ipaddress.IPv4Address(0xFFFFFFFF ^ int(netmask))
            network = ipaddress.IPv4Network(f"0.0.0.0/{prefix}", strict=False)

            self.txt_cidr_usable.setText(str(network.num_addresses - 2 if network.num_addresses > 1 else 0))
            self.txt_cidr_total.setText(str(network.num_addresses))
            self.txt_cidr_subnet.setText(str(netmask))
            self.txt_cidr_wildcard.setText(str(wildcard))
            self.highlight_input(self.txt_cidr, True)
            self.statusBar().showMessage("计算成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 1,
                'inputs': {'txt_cidr': cidr},
                'outputs': {
                    'txt_cidr_usable': self.txt_cidr_usable.text(),
                    'txt_cidr_total': self.txt_cidr_total.text(),
                    'txt_cidr_subnet': self.txt_cidr_subnet.text(),
                    'txt_cidr_wildcard': self.txt_cidr_wildcard.text()
                }
            }
            self.add_to_history(f"掩码计算: /{cidr}", history_data)

        except Exception as e:
            self.reset_fields([
                self.txt_cidr_usable, self.txt_cidr_total, self.txt_cidr_subnet,
                self.txt_cidr_wildcard
            ])
            self.txt_cidr_usable.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_cidr, False)
            self.statusBar().showMessage(f"计算错误: {str(e)}")

    def create_cidr_convert_tab(self):
        """创建通过掩码位元数转换子网掩码标签页"""
        layout = self.create_scrollable_tab("🔄 掩码位元数转换")

        # 输入区域
        input_group = QGroupBox("输入参数")
        input_layout = QVBoxLayout(input_group)
        input_layout.setSpacing(12)
        input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_cidr_conv = QLabel("掩码位元数（如 24 或 /24）:")
        self.txt_cidr_conv = QLineEdit()
        self.txt_cidr_conv.setPlaceholderText("例如: 24 或 /24")
        self.txt_cidr_conv.setMinimumWidth(200)
        self.txt_cidr_conv.textChanged.connect(lambda: self.highlight_input(
            self.txt_cidr_conv, self.validate_cidr(self.txt_cidr_conv.text())))

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_calc_conv = QPushButton("转换")
        btn_calc_conv.clicked.connect(self.calc_cidr_convert)
        btn_calc_conv.setMinimumHeight(30)

        self.btn_clear_conv = self.create_clear_button()
        self.btn_clear_conv.clicked.connect(lambda: self.reset_fields([
            self.txt_cidr_conv, self.txt_dec_subnet, self.txt_hex_subnet,
            self.txt_binary_subnet
        ]))

        btn_layout.addWidget(btn_calc_conv)
        btn_layout.addWidget(self.btn_clear_conv)
        btn_layout.setSpacing(10)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        input_layout.addWidget(lbl_cidr_conv)
        input_layout.addWidget(self.txt_cidr_conv)
        input_layout.addLayout(btn_layout)
        # input_layout.setColumnStretch(1, 1)

        # 输出区域
        output_group = QGroupBox("转换结果")
        output_layout = QGridLayout(output_group)
        output_layout.setSpacing(12)
        output_layout.setContentsMargins(5, 5, 5, 5)

        lbl_dec = QLabel("十进制子网掩码:")
        self.txt_dec_subnet = QLineEdit(readOnly=True)
        self.txt_dec_subnet.setMinimumWidth(200)

        lbl_hex = QLabel("十六进制子网掩码:")
        self.txt_hex_subnet = QLineEdit(readOnly=True)
        self.txt_hex_subnet.setMinimumWidth(200)

        lbl_binary = QLabel("二进制子网掩码:")
        self.txt_binary_subnet = QLineEdit(readOnly=True)
        self.txt_binary_subnet.setMinimumWidth(200)

        # 复制按钮
        copy_widgets = [
            (lbl_dec, self.txt_dec_subnet),
            (lbl_hex, self.txt_hex_subnet),
            (lbl_binary, self.txt_binary_subnet)
        ]
        self.btn_copy_conv = self.create_copy_button(copy_widgets)

        output_layout.addWidget(lbl_dec, 0, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_dec_subnet, 0, 1)
        output_layout.addWidget(lbl_hex, 1, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_hex_subnet, 1, 1)
        output_layout.addWidget(lbl_binary, 2, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_binary_subnet, 2, 1)
        output_layout.addWidget(self.btn_copy_conv, 3, 1, Qt.AlignRight)
        output_layout.setColumnStretch(1, 1)

        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def calc_cidr_convert(self):
        """转换CIDR到十进制、十六进制和二进制"""
        try:
            cidr = self.txt_cidr_conv.text().lstrip("/")
            prefix = int(cidr)

            if prefix < 0 or prefix > 32:
                raise ValueError("掩码位元数必须在0-32之间")

            netmask = ipaddress.IPv4Address(0xFFFFFFFF ^ (1 << (32 - prefix)) - 1)

            # 十进制
            dec_str = str(netmask)

            # 十六进制
            hex_str = "0x" + "".join(f"{int(octet):02X}" for octet in dec_str.split("."))

            # 二进制
            binary_str = ".".join(f"{int(octet):08b}" for octet in dec_str.split("."))

            self.txt_dec_subnet.setText(dec_str)
            self.txt_hex_subnet.setText(hex_str)
            self.txt_binary_subnet.setText(binary_str)
            self.highlight_input(self.txt_cidr_conv, True)
            self.statusBar().showMessage("转换成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 2,
                'inputs': {'txt_cidr_conv': cidr},
                'outputs': {
                    'txt_dec_subnet': self.txt_dec_subnet.text(),
                    'txt_hex_subnet': self.txt_hex_subnet.text(),
                    'txt_binary_subnet': self.txt_binary_subnet.text()
                }
            }
            self.add_to_history(f"掩码转换: /{cidr}", history_data)

        except Exception as e:
            self.reset_fields([self.txt_dec_subnet, self.txt_hex_subnet, self.txt_binary_subnet])
            self.txt_dec_subnet.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_cidr_conv, False)
            self.statusBar().showMessage(f"转换错误: {str(e)}")

    def create_host_count_tab(self):
        """创建通过主机数量计算子网掩码标签页"""
        layout = self.create_scrollable_tab("👥 主机数量计算子网掩码")

        # 输入区域
        input_group = QGroupBox("输入参数")
        input_layout = QVBoxLayout(input_group)
        input_layout.setSpacing(12)
        input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_host_count = QLabel("需要的主机数量:")
        self.txt_host_count = QLineEdit()
        self.txt_host_count.setPlaceholderText("例如: 50")
        self.txt_host_count.setMinimumWidth(200)
        self.txt_host_count.setValidator(QIntValidator(0, 2 ** 30))
        self.txt_host_count.textChanged.connect(lambda: self.highlight_input(
            self.txt_host_count, len(self.txt_host_count.text()) > 0 and
                                 int(self.txt_host_count.text() or 0) >= 0))

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_calc_host = QPushButton("计算")
        btn_calc_host.clicked.connect(self.calc_host_subnet)
        btn_calc_host.setMinimumHeight(30)

        self.btn_clear_host = self.create_clear_button()
        self.btn_clear_host.clicked.connect(lambda: self.reset_fields([
            self.txt_host_count, self.txt_cidr_host, self.txt_subnet_host,
            self.txt_usable_host, self.txt_total_host
        ]))

        btn_layout.addWidget(btn_calc_host)
        btn_layout.addWidget(self.btn_clear_host)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # btn_layout.setSpacing(10)

        input_layout.addWidget(lbl_host_count)
        input_layout.addWidget(self.txt_host_count)
        input_layout.addLayout(btn_layout)


        # 输出区域
        output_group = QGroupBox("计算结果")
        output_layout = QGridLayout(output_group)
        output_layout.setSpacing(12)
        output_layout.setContentsMargins(5, 5, 5, 5)

        lbl_cidr_host = QLabel("掩码位元数:")
        self.txt_cidr_host = QLineEdit(readOnly=True)
        self.txt_cidr_host.setMinimumWidth(150)

        lbl_subnet_host = QLabel("子网掩码:")
        self.txt_subnet_host = QLineEdit(readOnly=True)
        self.txt_subnet_host.setMinimumWidth(150)

        lbl_usable_host = QLabel("可用地址数量:")
        self.txt_usable_host = QLineEdit(readOnly=True)
        self.txt_usable_host.setMinimumWidth(150)

        lbl_total_host = QLabel("地址总数:")
        self.txt_total_host = QLineEdit(readOnly=True)
        self.txt_total_host.setMinimumWidth(150)

        # 复制按钮
        copy_widgets = [
            (lbl_cidr_host, self.txt_cidr_host),
            (lbl_subnet_host, self.txt_subnet_host),
            (lbl_usable_host, self.txt_usable_host),
            (lbl_total_host, self.txt_total_host)
        ]
        self.btn_copy_host = self.create_copy_button(copy_widgets)

        output_layout.addWidget(lbl_cidr_host, 0, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_cidr_host, 0, 1)
        output_layout.addWidget(lbl_subnet_host, 0, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_subnet_host, 0, 3)
        output_layout.addWidget(lbl_usable_host, 1, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_usable_host, 1, 1)
        output_layout.addWidget(lbl_total_host, 1, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_total_host, 1, 3)
        output_layout.addWidget(self.btn_copy_host, 2, 3, Qt.AlignRight)

        # 设置列拉伸
        output_layout.setColumnStretch(1, 1)
        output_layout.setColumnStretch(3, 1)

        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def calc_host_subnet(self):
        """通过主机数量计算子网掩码"""
        try:
            host_count = int(self.txt_host_count.text())

            if host_count < 0:
                raise ValueError("主机数量不能为负数")

            # 处理0台主机的特殊情况
            if host_count == 0:
                prefix = 32
            else:
                # 需要至少容纳 host_count + 网络地址 + 广播地址
                required = host_count + 2
                host_bits = 0
                while (1 << host_bits) < required:
                    host_bits += 1
                    if host_bits > 32:
                        raise ValueError("主机数量过大，超出IPv4地址范围")
                prefix = 32 - host_bits

            netmask = ipaddress.IPv4Address(0xFFFFFFFF ^ (1 << (32 - prefix)) - 1)
            total_addresses = 1 << (32 - prefix)
            usable_addresses = total_addresses - 2 if total_addresses > 1 else 0

            self.txt_cidr_host.setText(f"/{prefix}")
            self.txt_subnet_host.setText(str(netmask))
            self.txt_usable_host.setText(str(usable_addresses))
            self.txt_total_host.setText(str(total_addresses))
            self.highlight_input(self.txt_host_count, True)
            self.statusBar().showMessage("计算成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 3,
                'inputs': {'txt_host_count': str(host_count)},
                'outputs': {
                    'txt_cidr_host': self.txt_cidr_host.text(),
                    'txt_subnet_host': self.txt_subnet_host.text(),
                    'txt_usable_host': self.txt_usable_host.text(),
                    'txt_total_host': self.txt_total_host.text()
                }
            }
            self.add_to_history(f"主机计算: {host_count}台主机", history_data)

        except Exception as e:
            self.reset_fields([
                self.txt_cidr_host, self.txt_subnet_host, self.txt_usable_host,
                self.txt_total_host
            ])
            self.txt_cidr_host.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_host_count, False)
            self.statusBar().showMessage(f"计算错误: {str(e)}")

    def create_ip_subnet_tab(self):
        """创建IP地址子网掩码计算器标签页"""
        layout = self.create_scrollable_tab("📋 IP地址子网掩码计算器")

        # 输入区域
        input_group = QGroupBox("输入参数")
        input_layout = QVBoxLayout(input_group)
        input_layout.setSpacing(12)
        input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_ip = QLabel("IP地址:")
        self.txt_ip = QLineEdit()
        self.txt_ip.setPlaceholderText("例如: 192.168.1.1")
        self.txt_ip.setMinimumWidth(180)
        self.txt_ip.textChanged.connect(lambda: self.highlight_input(
            self.txt_ip, self.validate_ip(self.txt_ip.text())))

        lbl_net_type = QLabel("选择网络类型:")
        self.cmb_net_type = QComboBox()
        self.cmb_net_type.addItems(["默认", "A类网", "B类网", "C类网"])
        self.cmb_net_type.setMinimumWidth(150)

        lbl_calc_type = QLabel("计算方式:")
        self.cmb_calc_type = QComboBox()
        self.cmb_calc_type.addItems(["按子网数量", "按主机数量"])
        self.cmb_calc_type.setMinimumWidth(150)

        lbl_count = QLabel("数量:")
        self.txt_count = QLineEdit()
        self.txt_count.setPlaceholderText("例如: 10")
        self.txt_count.setMinimumWidth(100)
        self.txt_count.setValidator(QIntValidator(1, 1000000))
        self.txt_count.textChanged.connect(lambda: self.highlight_input(
            self.txt_count, len(self.txt_count.text()) > 0 and
                            int(self.txt_count.text() or 0) > 0))

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_calc_ip_subnet = QPushButton("计算")
        btn_calc_ip_subnet.clicked.connect(self.calc_ip_subnet)
        btn_calc_ip_subnet.setMinimumHeight(30)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn_clear_ip_subnet = self.create_clear_button()
        self.btn_clear_ip_subnet.clicked.connect(lambda: [
            self.txt_ip.clear(),
            self.cmb_net_type.setCurrentIndex(0),
            self.cmb_calc_type.setCurrentIndex(0),
            self.txt_count.clear(),
            self.txt_result_ip_subnet.clear()
        ])

        btn_layout.addWidget(btn_calc_ip_subnet)
        btn_layout.addWidget(self.btn_clear_ip_subnet)
        btn_layout.setSpacing(10)

        input_layout.addWidget(lbl_ip)
        input_layout.addWidget(self.txt_ip)
        input_layout.addWidget(lbl_net_type)
        input_layout.addWidget(self.cmb_net_type)
        input_layout.addWidget(lbl_calc_type)
        input_layout.addWidget(self.cmb_calc_type)
        input_layout.addWidget(lbl_count)
        input_layout.addWidget(self.txt_count)
        input_layout.addLayout(btn_layout)

        # 设置列拉伸
        # input_layout.setColumnStretch(1, 1)
        # input_layout.setColumnStretch(3, 1)

        # 输出区域
        output_group = QGroupBox("计算结果")
        output_layout = QVBoxLayout(output_group)
        output_layout.setContentsMargins(5, 5, 5, 5)


        self.txt_result_ip_subnet = QTextEdit(readOnly=True)
        self.txt_result_ip_subnet.setMinimumHeight(180)
        self.txt_result_ip_subnet.setMinimumWidth(400)

        # 复制按钮
        self.btn_copy_ip_subnet = self.create_copy_button([self.txt_result_ip_subnet])

        btn_container = QHBoxLayout()
        btn_container.addStretch()
        btn_container.addWidget(self.btn_copy_ip_subnet)

        output_layout.addWidget(self.txt_result_ip_subnet)
        output_layout.addLayout(btn_container)

        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def calc_ip_subnet(self):
        """根据网络类型和IP计算子网信息"""
        try:
            ip_str = self.txt_ip.text()
            net_type = self.cmb_net_type.currentText()
            calc_type = self.cmb_calc_type.currentText()
            count = int(self.txt_count.text())

            if count <= 0:
                raise ValueError("数量必须为正数")

            # 验证IP地址
            if not self.validate_ip(ip_str):
                raise ValueError("无效的IP地址格式")

            # 解析IP地址
            ip = ipaddress.IPv4Address(ip_str)
            ip_int = int(ip)

            # 确定默认网络类型
            first_octet = ip_int >> 24
            if net_type == "默认":
                if 1 <= first_octet <= 126:
                    net_type = "A类网"
                elif 128 <= first_octet <= 191:
                    net_type = "B类网"
                elif 192 <= first_octet <= 223:
                    net_type = "C类网"
                else:
                    raise ValueError("IP地址不属于A、B、C类网络")

            # 确定默认前缀
            if net_type == "A类网":
                default_prefix = 8
            elif net_type == "B类网":
                default_prefix = 16
            else:  # C类网
                default_prefix = 24

            # 计算所需的额外位
            if calc_type == "按子网数量":
                # 计算子网所需位数
                subnet_bits = 0
                while (1 << subnet_bits) < count:
                    subnet_bits += 1
                    if default_prefix + subnet_bits > 32:
                        raise ValueError("子网数量过多，无法在当前网络类型中分配")

                new_prefix = default_prefix + subnet_bits
                total_subnets = 1 << subnet_bits
                host_bits = 32 - new_prefix
                hosts_per_subnet = (1 << host_bits) - 2 if host_bits > 0 else 0

                result = f"网络类型: {net_type}\n"
                result += f"默认前缀: /{default_prefix}\n"
                result += f"子网数量: {count}\n"
                result += f"所需子网位: {subnet_bits}\n"
                result += f"新前缀: /{new_prefix}\n"
                result += f"可用子网总数: {total_subnets}\n"
                result += f"每个子网可用主机数: {hosts_per_subnet}\n"
                result += f"子网掩码: {ipaddress.IPv4Address(0xFFFFFFFF ^ (1 << (32 - new_prefix)) - 1)}\n"

            else:  # 按主机数量
                # 计算主机所需位数
                required = count + 2  # 加网络地址和广播地址
                host_bits = 0
                while (1 << host_bits) < required:
                    host_bits += 1
                    if host_bits > (32 - default_prefix):
                        raise ValueError("主机数量过多，无法在当前网络类型中分配")

                new_prefix = 32 - host_bits
                if new_prefix < default_prefix:
                    raise ValueError("主机数量过多，超出当前网络类型的最大容量")

                subnet_bits = new_prefix - default_prefix
                total_subnets = 1 << subnet_bits if subnet_bits > 0 else 1
                hosts_per_subnet = (1 << host_bits) - 2

                result = f"网络类型: {net_type}\n"
                result += f"默认前缀: /{default_prefix}\n"
                result += f"主机数量: {count}\n"
                result += f"所需主机位: {host_bits}\n"
                result += f"新前缀: /{new_prefix}\n"
                result += f"可用子网总数: {total_subnets}\n"
                result += f"每个子网可用主机数: {hosts_per_subnet}\n"
                result += f"子网掩码: {ipaddress.IPv4Address(0xFFFFFFFF ^ (1 << (32 - new_prefix)) - 1)}\n"

            self.txt_result_ip_subnet.setText(result)
            self.highlight_input(self.txt_ip, True)
            self.highlight_input(self.txt_count, True)
            self.statusBar().showMessage("计算成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 4,
                'inputs': {
                    'txt_ip': ip_str,
                    'cmb_net_type': net_type,
                    'cmb_calc_type': calc_type,
                    'txt_count': str(count)
                },
                'outputs': {'txt_result_ip_subnet': self.txt_result_ip_subnet.toPlainText()}
            }
            self.add_to_history(f"子网计算: {ip_str}, {calc_type} {count}", history_data)

        except Exception as e:
            self.txt_result_ip_subnet.setText(f"错误: {str(e)}")
            if not self.validate_ip(self.txt_ip.text()):
                self.highlight_input(self.txt_ip, False)
            if len(self.txt_count.text()) == 0 or int(self.txt_count.text() or 0) <= 0:
                self.highlight_input(self.txt_count, False)
            self.statusBar().showMessage(f"计算错误: {str(e)}")

    def create_network_node_tab(self):
        """创建网络/节点计算器标签页"""
        layout = self.create_scrollable_tab("🔌 网络/节点计算器")

        # 输入区域
        input_group = QGroupBox("输入参数")
        input_layout = QGridLayout(input_group)
        input_layout.setSpacing(12)
        input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_subnet_mask = QLabel("子网掩码:")
        self.txt_subnet_mask = QLineEdit()
        self.txt_subnet_mask.setPlaceholderText("例如: 255.255.255.0 或 24")
        self.txt_subnet_mask.setMinimumWidth(200)
        self.txt_subnet_mask.textChanged.connect(self.validate_subnet_mask)

        lbl_tcp_ip = QLabel("IP地址:")
        self.txt_tcp_ip = QLineEdit()
        self.txt_tcp_ip.setPlaceholderText("例如: 192.168.1.1")
        self.txt_tcp_ip.setMinimumWidth(200)
        self.txt_tcp_ip.textChanged.connect(lambda: self.highlight_input(
            self.txt_tcp_ip, self.validate_ip(self.txt_tcp_ip.text())))

        # 按钮区域
        btn_layout = QHBoxLayout()
        btn_calc_node = QPushButton("计算")
        btn_calc_node.clicked.connect(self.calc_network_node)
        btn_calc_node.setMinimumHeight(30)

        self.btn_clear_node = self.create_clear_button()
        self.btn_clear_node.clicked.connect(lambda: self.reset_fields([
            self.txt_subnet_mask, self.txt_tcp_ip, self.txt_net, self.txt_net_cidr,
            self.txt_host_id, self.txt_broadcast_node, self.txt_first_node,
            self.txt_last_node
        ]))

        btn_layout.addWidget(btn_calc_node)
        btn_layout.addWidget(self.btn_clear_node)
        btn_layout.setSpacing(10)

        input_layout.addWidget(lbl_subnet_mask, 0, 0, Qt.AlignVCenter)
        input_layout.addWidget(self.txt_subnet_mask, 0, 1)
        input_layout.addWidget(lbl_tcp_ip, 0, 2, Qt.AlignVCenter)
        input_layout.addWidget(self.txt_tcp_ip, 0, 3)
        input_layout.addLayout(btn_layout, 0, 4)

        # 设置列拉伸
        input_layout.setColumnStretch(1, 1)
        input_layout.setColumnStretch(3, 1)

        # 输出区域
        output_group = QGroupBox("计算结果")
        output_layout = QGridLayout(output_group)
        output_layout.setSpacing(12)
        output_layout.setContentsMargins(5, 5, 5, 5)

        lbl_net = QLabel("网络地址:")
        self.txt_net = QLineEdit(readOnly=True)
        self.txt_net.setMinimumWidth(150)

        lbl_net_cidr = QLabel("网络地址(CIDR):")
        self.txt_net_cidr = QLineEdit(readOnly=True)
        self.txt_net_cidr.setMinimumWidth(150)

        lbl_host_id = QLabel("主机ID:")
        self.txt_host_id = QLineEdit(readOnly=True)
        self.txt_host_id.setMinimumWidth(150)

        lbl_broadcast = QLabel("广播地址:")
        self.txt_broadcast_node = QLineEdit(readOnly=True)
        self.txt_broadcast_node.setMinimumWidth(150)

        lbl_first = QLabel("第一个可用地址:")
        self.txt_first_node = QLineEdit(readOnly=True)
        self.txt_first_node.setMinimumWidth(150)

        lbl_last = QLabel("最后可用地址:")
        self.txt_last_node = QLineEdit(readOnly=True)
        self.txt_last_node.setMinimumWidth(150)

        # 复制按钮
        copy_widgets = [
            (lbl_net, self.txt_net),
            (lbl_net_cidr, self.txt_net_cidr),
            (lbl_host_id, self.txt_host_id),
            (lbl_broadcast, self.txt_broadcast_node),
            (lbl_first, self.txt_first_node),
            (lbl_last, self.txt_last_node)
        ]
        self.btn_copy_node = self.create_copy_button(copy_widgets)

        output_layout.addWidget(lbl_net, 0, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_net, 0, 1)
        output_layout.addWidget(lbl_net_cidr, 0, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_net_cidr, 0, 3)
        output_layout.addWidget(lbl_host_id, 1, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_host_id, 1, 1)
        output_layout.addWidget(lbl_broadcast, 1, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_broadcast_node, 1, 3)
        output_layout.addWidget(lbl_first, 2, 0, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_first_node, 2, 1)
        output_layout.addWidget(lbl_last, 2, 2, Qt.AlignVCenter)
        output_layout.addWidget(self.txt_last_node, 2, 3)
        output_layout.addWidget(self.btn_copy_node, 3, 3, Qt.AlignRight)

        # 设置列拉伸
        output_layout.setColumnStretch(1, 1)
        output_layout.setColumnStretch(3, 1)

        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def validate_subnet_mask(self):
        """验证子网掩码"""
        mask = self.txt_subnet_mask.text()
        try:
            # 尝试作为CIDR验证
            if self.validate_cidr(mask):
                self.highlight_input(self.txt_subnet_mask, True)
                return True

            # 尝试作为子网掩码验证
            ipaddress.IPv4Address(mask)
            # 检查是否是有效的子网掩码
            mask_int = int(ipaddress.IPv4Address(mask))
            if self.is_valid_subnet_mask(mask_int):
                self.highlight_input(self.txt_subnet_mask, True)
                return True

        except:
            pass

        self.highlight_input(self.txt_subnet_mask, False)
        return False

    def calc_network_node(self):
        """计算网络/节点信息"""
        try:
            subnet_mask = self.txt_subnet_mask.text()
            tcp_ip = self.txt_tcp_ip.text()

            # 验证输入
            if not self.validate_ip(tcp_ip):
                raise ValueError("无效的IP地址")

            if not self.validate_subnet_mask():
                raise ValueError("无效的子网掩码")

            # 解析子网掩码为前缀长度
            try:
                # 尝试直接解析为前缀
                prefix = int(subnet_mask.lstrip("/"))
                network = ipaddress.IPv4Network(f"{tcp_ip}/{prefix}", strict=False)
            except:
                # 解析为子网掩码
                network = ipaddress.IPv4Network(f"{tcp_ip}/{subnet_mask}", strict=False)
                prefix = network.prefixlen

            # 计算主机ID
            ip_int = int(ipaddress.IPv4Address(tcp_ip))
            netmask_int = int(network.netmask)
            host_id_int = ip_int & ~netmask_int
            host_id = str(ipaddress.IPv4Address(host_id_int))

            self.txt_net.setText(str(network.network_address))
            self.txt_net_cidr.setText(f"{network.network_address}/{prefix}")
            self.txt_host_id.setText(host_id)
            self.txt_broadcast_node.setText(str(network.broadcast_address))

            # 处理主机地址情况
            if network.num_addresses > 1:
                self.txt_first_node.setText(str(network.network_address + 1))
                self.txt_last_node.setText(str(network.broadcast_address - 1))
            else:
                self.txt_first_node.setText("无")
                self.txt_last_node.setText("无")

            self.highlight_input(self.txt_subnet_mask, True)
            self.highlight_input(self.txt_tcp_ip, True)
            self.statusBar().showMessage("计算成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 5,
                'inputs': {
                    'txt_subnet_mask': subnet_mask,
                    'txt_tcp_ip': tcp_ip
                },
                'outputs': {
                    'txt_net': self.txt_net.text(),
                    'txt_net_cidr': self.txt_net_cidr.text(),
                    'txt_host_id': self.txt_host_id.text(),
                    'txt_broadcast_node': self.txt_broadcast_node.text(),
                    'txt_first_node': self.txt_first_node.text(),
                    'txt_last_node': self.txt_last_node.text()
                }
            }
            self.add_to_history(f"网络节点计算: {tcp_ip} {subnet_mask}", history_data)

        except Exception as e:
            self.reset_fields([
                self.txt_net, self.txt_net_cidr, self.txt_host_id,
                self.txt_broadcast_node, self.txt_first_node, self.txt_last_node
            ])
            self.txt_net.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_subnet_mask, False)
            self.highlight_input(self.txt_tcp_ip, False)
            self.statusBar().showMessage(f"计算错误: {str(e)}")

    def create_subnet_converter_tab(self):
        """创建子网掩码换算器标签页"""
        layout = self.create_scrollable_tab("🔀 子网掩码换算器")

        # 输入区域
        input_group = QGroupBox("输入参数")
        input_layout = QGridLayout(input_group)
        input_layout.setSpacing(15)
        input_layout.setContentsMargins(5, 5, 5, 5)

        lbl_subnet = QLabel("子网掩码（如 255.255.255.0）:")
        self.txt_subnet = QLineEdit()
        self.txt_subnet.setPlaceholderText("例如: 255.255.255.0")
        self.txt_subnet.setMinimumWidth(200)
        self.txt_subnet.textChanged.connect(self.validate_subnet_mask_field)

        lbl_cidr = QLabel("掩码位元数（如 24 或 /24）:")
        self.txt_cidr_conv_full = QLineEdit()
        self.txt_cidr_conv_full.setPlaceholderText("例如: 24 或 /24")
        self.txt_cidr_conv_full.setMinimumWidth(200)
        self.txt_cidr_conv_full.textChanged.connect(lambda: self.highlight_input(
            self.txt_cidr_conv_full, self.validate_cidr(self.txt_cidr_conv_full.text())))

        # 按钮区域
        btn_layout1 = QHBoxLayout()
        btn_subnet_to_cidr = QPushButton("子网掩码 → 位元数")
        btn_subnet_to_cidr.clicked.connect(self.subnet_to_cidr)
        btn_subnet_to_cidr.setMinimumHeight(30)

        btn_layout2 = QHBoxLayout()
        btn_cidr_to_subnet = QPushButton("位元数 → 子网掩码")
        btn_cidr_to_subnet.clicked.connect(self.cidr_to_subnet)
        btn_cidr_to_subnet.setMinimumHeight(30)

        self.btn_clear_converter = self.create_clear_button()
        self.btn_clear_converter.clicked.connect(lambda: self.reset_fields([
            self.txt_subnet, self.txt_cidr_conv_full
        ]))

        btn_layout1.addWidget(btn_subnet_to_cidr)
        btn_layout1.addWidget(self.btn_clear_converter)
        btn_layout2.addWidget(btn_cidr_to_subnet)
        btn_layout1.setSpacing(10)

        input_layout.addWidget(lbl_subnet, 0, 0, Qt.AlignVCenter)
        input_layout.addWidget(self.txt_subnet, 0, 1)
        input_layout.addLayout(btn_layout1, 0, 2)
        input_layout.addWidget(lbl_cidr, 1, 0, Qt.AlignVCenter)
        input_layout.addWidget(self.txt_cidr_conv_full, 1, 1)
        input_layout.addLayout(btn_layout2, 1, 2)
        input_layout.setColumnStretch(1, 1)

        layout.addWidget(input_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def validate_subnet_mask_field(self):
        """验证子网掩码输入框"""
        try:
            mask = self.txt_subnet.text()
            ipaddress.IPv4Address(mask)
            mask_int = int(ipaddress.IPv4Address(mask))
            if self.is_valid_subnet_mask(mask_int):
                self.highlight_input(self.txt_subnet, True)
                return True
        except:
            pass
        self.highlight_input(self.txt_subnet, False)
        return False

    def subnet_to_cidr(self):
        """子网掩码转换为掩码位元数"""
        try:
            subnet_mask = self.txt_subnet.text()
            mask = ipaddress.IPv4Address(subnet_mask)
            mask_int = int(mask)

            # 检查是否是有效的子网掩码
            if not self.is_valid_subnet_mask(mask_int):
                raise ValueError("无效的子网掩码")

            # 计算前缀长度
            prefix = 32
            while prefix > 0 and not (mask_int & (1 << (32 - prefix))):
                prefix -= 1

            self.txt_cidr_conv_full.setText(f"/{prefix}")
            self.highlight_input(self.txt_subnet, True)
            self.statusBar().showMessage("转换成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 6,
                'inputs': {'txt_subnet': subnet_mask},
                'outputs': {'txt_cidr_conv_full': self.txt_cidr_conv_full.text()}
            }
            self.add_to_history(f"子网转CIDR: {subnet_mask}", history_data)

        except Exception as e:
            self.txt_cidr_conv_full.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_subnet, False)
            self.statusBar().showMessage(f"转换错误: {str(e)}")

    def cidr_to_subnet(self):
        """掩码位元数转换为子网掩码"""
        try:
            cidr = self.txt_cidr_conv_full.text().lstrip("/")
            prefix = int(cidr)

            if prefix < 0 or prefix > 32:
                raise ValueError("掩码位元数必须在0-32之间")

            netmask = ipaddress.IPv4Address(0xFFFFFFFF ^ (1 << (32 - prefix)) - 1)
            self.txt_subnet.setText(str(netmask))
            self.highlight_input(self.txt_cidr_conv_full, True)
            self.statusBar().showMessage("转换成功")

            # 添加到历史记录
            history_data = {
                'tab_index': 6,
                'inputs': {'txt_cidr_conv_full': cidr},
                'outputs': {'txt_subnet': self.txt_subnet.text()}
            }
            self.add_to_history(f"CIDR转子网: /{cidr}", history_data)

        except Exception as e:
            self.txt_subnet.setText(f"错误: {str(e)}")
            self.highlight_input(self.txt_cidr_conv_full, False)
            self.statusBar().showMessage(f"转换错误: {str(e)}")

    def create_help_tab(self):
        """创建帮助说明标签页"""
        layout = self.create_scrollable_tab("❓ 帮助说明")

        help_group = QGroupBox("工具使用说明")
        help_layout = QVBoxLayout(help_group)
        help_layout.setContentsMargins(10, 10, 10, 10)

        help_text = """
        本工具提供多种网络与IP地址计算功能，以下是各功能的使用说明：

        1. 🌐 网络和IP地址计算器
           - 输入格式：IP地址/掩码（如 192.168.0.1/24）
           - 功能：计算可用地址数量、子网掩码、网络地址、第一个可用地址、最后可用地址和广播地址

        2. 🔢 掩码位元数计算子网掩码
           - 输入格式：掩码位元数（如 24 或 /24）
           - 功能：计算可用地址数量、地址总数、子网掩码和通配符掩码

        3. 🔄 掩码位元数转换
           - 输入格式：掩码位元数（如 24 或 /24）
           - 功能：将掩码位元数转换为十进制、十六进制和二进制子网掩码

        4. 👥 主机数量计算子网掩码
           - 输入格式：需要的主机数量（如 50）
           - 功能：根据主机数量计算合适的掩码位元数、子网掩码、可用地址数量和地址总数

        5. 📋 IP地址子网掩码计算器
           - 输入格式：IP地址、网络类型和数量
           - 功能：按A/B/C类网络类型计算子网信息

        6. 🔌 网络/节点计算器
           - 输入格式：子网掩码和IP地址
           - 功能：计算网络地址、网络地址(CIDR)、主机ID、广播地址、第一个和最后一个可用地址

        7. 🔀 子网掩码换算器
           - 输入格式：子网掩码或掩码位元数
           - 功能：在子网掩码和掩码位元数之间进行相互转换

        所有计算基于IPv4地址，输入错误时会显示相应的错误信息。
        """

        help_label = QLabel(help_text)
        help_label.setWordWrap(True)
        help_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        # 添加一些常用的子网掩码参考表
        table_group = QGroupBox("常用子网掩码参考表")
        table_layout = QVBoxLayout(table_group)
        table_layout.setContentsMargins(10, 10, 10, 10)

        table_text = """
        掩码位元数 | 子网掩码      | 可用主机数 | 地址总数
        ----------|---------------|------------|---------
        /32       | 255.255.255.255 | 0          | 1
        /31       | 255.255.255.254 | 0          | 2
        /30       | 255.255.255.252 | 2          | 4
        /29       | 255.255.255.248 | 6          | 8
        /28       | 255.255.255.240 | 14         | 16
        /27       | 255.255.255.224 | 30         | 32
        /26       | 255.255.255.192 | 62         | 64
        /25       | 255.255.255.128 | 126        | 128
        /24       | 255.255.255.0   | 254        | 256
        /23       | 255.255.254.0   | 510        | 512
        /22       | 255.255.252.0   | 1022       | 1024
        /21       | 255.255.248.0   | 2046       | 2048
        /20       | 255.255.240.0   | 4094       | 4096
        /19       | 255.255.224.0   | 8190       | 8192
        /18       | 255.255.192.0   | 16382      | 16384
        /17       | 255.255.128.0   | 32766      | 32768
        /16       | 255.255.0.0     | 65534      | 65536
        """

        table_label = QLabel(f"<pre>{table_text}</pre>")
        table_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        table_layout.addWidget(table_label)
        help_layout.addWidget(help_label)
        help_layout.addWidget(table_group)

        layout.addWidget(help_group)
        layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def is_valid_subnet_mask(self, mask_int):
        """检查是否是有效的子网掩码"""
        if mask_int == 0:
            return True
        # 子网掩码应该是连续的1后面跟连续的0
        # 翻转所有位并加1，如果是2的幂则有效
        inverted = ~mask_int & 0xFFFFFFFF
        return (inverted + 1) & inverted == 0

    def reset_fields(self, fields):
        """重置输入字段"""
        for field in fields:
            field.clear()
            # 重置输入状态样式
            if hasattr(field, 'setProperty'):
                field.setProperty("error", False)
                field.setProperty("success", False)
                field.style().unpolish(field)
                field.style().polish(field)
                field.update()
        self.statusBar().showMessage("已清除输入和结果")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 确保中文显示正常
    window = IPAddressCalculator()
    window.show()
    sys.exit(app.exec())
