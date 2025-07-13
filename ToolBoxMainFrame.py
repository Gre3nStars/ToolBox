import os
import sys
import time

from PySide6 import QtGui, QtWidgets
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTreeWidget, QTreeWidgetItem, QSplitter,
    QToolButton, QTabWidget, QFrame, QGridLayout, QTreeWidgetItemIterator, QFileDialog, QMessageBox, QTextEdit,
    QFontDialog
)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QPoint, QTimer, QObject, Signal
from PySide6.QtGui import QIcon, QFont, QPalette, QColor, QAction

from system_status_bar import SystemStatusBar


def resource_path(relative_path):
    """ 获取资源绝对路径，适用于 PyInstaller 打包 """
    try:
        # PyInstaller 创建的临时文件夹中的路径
        base_path = sys._MEIPASS
    except Exception:
        # 正常运行时的路径
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(600, 320)

class Dialog(QtWidgets.QMainWindow):
    def closeEvent(self, event):
        reply = QtWidgets.QMessageBox.question(self,
                                               '本程序',
                                               "是否要退出程序？",
                                               QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                                               QtWidgets.QMessageBox.No)
        if reply == QtWidgets.QMessageBox.Yes:
            event.accept()
        else:
            event.ignore()

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PySide6.QtCore import QTimer, QTime, Qt, Property, QPropertyAnimation
from PySide6.QtGui import QFont, QColor, QPainter, QPen, QBrush


class FlipClock(QWidget):
    """翻页时钟组件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

        # 设置定时器更新时间
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)  # 每秒更新一次

        # 初始更新时间
        self.update_time()

    def init_ui(self):
        # 主布局
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(10)

        # 日期显示
        self.date_label = QLabel()
        self.date_label.setAlignment(Qt.AlignCenter)
        self.date_label.setFont(QFont("Microsoft YaHei", 14))
        self.date_label.setStyleSheet("""
                    color: #333; 
                    font-weight: bold;
                    font-family: "Microsoft YaHei", sans-serif !important;
                    font-size: 40px !important;
                """)

        # 时间显示（网格布局）
        time_layout = QGridLayout()
        time_layout.setSpacing(5)

        # 时、分、秒标签
        self.hour_label = QLabel("00")
        self.minute_label = QLabel("00")
        self.second_label = QLabel("00")

        # 分隔符
        self.colon1 = QLabel(":")
        self.colon2 = QLabel(":")

        # 设置时间标签样式
        for label in [self.hour_label, self.minute_label, self.second_label]:
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setFont(QFont("Microsoft YaHei", 48, QFont.Bold))
            label.setStyleSheet("""
                background-color: white;
                color: #1a1a1a;
                border-radius: 6px;
                padding: 10px;
                box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                font-family: "Microsoft YaHei", sans-serif !important;
                font-size: 120px !important;
                font-weight: bold !important;
            """)
            label.setMinimumSize(160, 120)

        # 设置分隔符样式
        for colon in [self.colon1, self.colon2]:
            colon.setAlignment(Qt.AlignmentFlag.AlignCenter)
            colon.setFont(QFont("Microsoft YaHei", 48, QFont.Bold))
            colon.setStyleSheet("""
            color: #666;
            font-family: "Microsoft YaHei", sans-serif !important;
            font-size: 48px !important;
            font-weight: bold !important;
        """)

        # 添加到网格布局
        time_layout.addWidget(self.hour_label, 0, 0)
        time_layout.addWidget(self.colon1, 0, 1)
        time_layout.addWidget(self.minute_label, 0, 2)
        time_layout.addWidget(self.colon2, 0, 3)
        time_layout.addWidget(self.second_label, 0, 4)

        # 添加
        time_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # 添加到主布局
        main_layout.addWidget(self.date_label)
        main_layout.addLayout(time_layout)
        main_layout.addStretch()

        # 设置组件背景
        self.setStyleSheet("background-color: transparent;image: none")

    def update_time(self):
        """更新时间和日期显示"""
        # 获取当前时间
        current_time = time.localtime()

        # 格式化时间
        hour = f"{current_time.tm_hour:02d}"
        minute = f"{current_time.tm_min:02d}"
        second = f"{current_time.tm_sec:02d}"

        # 格式化日期
        date_str = f"{current_time.tm_year}年{current_time.tm_mon}月{current_time.tm_mday}日 "
        weekday = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"][current_time.tm_wday]
        date_str += weekday

        # 更新显示（添加翻页动画效果）
        if self.hour_label.text() != hour:
            self.animate_label(self.hour_label, hour)
        if self.minute_label.text() != minute:
            self.animate_label(self.minute_label, minute)
        if self.second_label.text() != second:
            self.second_label.setText(second)

        # 更新日期
        self.date_label.setText(date_str)

    def animate_label(self, label, new_text):
        """为数字变化添加简单的翻转动画效果"""
        # 先缩小
        animation = QPropertyAnimation(label, b"minimumHeight")
        animation.setDuration(100)
        animation.setStartValue(label.height())
        animation.setEndValue(0)
        animation.start()

        # 动画结束后更新文本并恢复大小
        def update_text():
            label.setText(new_text)
            # 恢复大小
            animation = QPropertyAnimation(label, b"minimumHeight")
            animation.setDuration(100)
            animation.setStartValue(0)
            animation.setEndValue(80)
            animation.start()

        QTimer.singleShot(100, update_text)


class NotepadWidget(QWidget):
    """记事本组件"""

    def __init__(self, parent=None, file_path=None):
        super().__init__(parent)
        self.file_path = file_path  # 保存当前文件路径
        self.init_ui()

        # 如果有文件路径，打开文件
        if self.file_path and os.path.exists(self.file_path):
            self.load_file()
        else:
            self.setWindowTitle("新建记事本")

    def init_ui(self):
        # 主布局
        layout = QVBoxLayout(self)

        # 文本编辑区域
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("YaHei", 12))
        layout.addWidget(self.text_edit)

        # 底部按钮区域
        btn_layout = QHBoxLayout()
        save_btn = QPushButton("保存")
        save_btn.clicked.connect(self.save_file)
        btn_layout.addWidget(save_btn)
        layout.addLayout(btn_layout)

        self.setMinimumSize(600, 400)

    def load_file(self):
        """加载文件内容"""
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.text_edit.setText(content)
                self.setWindowTitle(f"记事本 - {os.path.basename(self.file_path)}")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"无法打开文件: {str(e)}")

    def save_file(self):
        """保存文件内容"""
        if self.file_path:
            try:
                with open(self.file_path, 'w', encoding='utf-8') as f:
                    f.write(self.text_edit.toPlainText())
                QMessageBox.information(self, "成功", "文件已保存")
            except Exception as e:
                QMessageBox.warning(self, "错误", f"保存文件失败: {str(e)}")
        else:
            # 新建文件，使用另存为
            self.save_file_as()

    def save_file_as(self):
        """另存为新文件"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            self.file_path = file_path
            self.save_file()

class CollapsibleSidebar(QWidget):
    """可折叠、隐藏的侧边导航栏"""
    menu_toggled = Signal(bool)
    menu_clicked = Signal(str)  # 用于传递点击的菜单项文本

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.is_collapsed = False
        self.is_hidden = False

    def init_ui(self):
        # 主布局（垂直）
        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # 顶部控制区域（水平）
        self.control_frame = QWidget()
        self.control_frame.setStyleSheet("background-color: #1E88E5;")
        control_layout = QHBoxLayout(self.control_frame)
        control_layout.setContentsMargins(5, 5, 5, 5)

        # 折叠按钮
        self.collapse_btn = QPushButton("≡")
        # self.collapse_btn.setToolTip("折叠/展开菜单")
        self.collapse_btn.setFixedSize(28, 28)
        self.collapse_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: white;
                border: none;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.2);
            }
        """)
        self.collapse_btn.clicked.connect(self.toggle_hide)

        # 标题
        self.title_label = QLabel("工具导航")
        self.title_label.setStyleSheet("""
            color: white; 
            font-weight: bold;
            padding-left: 5px;
        """)

        # 隐藏按钮
        self.hide_btn = QPushButton("⟨")
        self.hide_btn.setToolTip("隐藏/显示侧边栏")
        self.hide_btn.setFixedSize(28, 28)
        self.hide_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: white;
                border: none;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.5);
            }
        """)
        self.hide_btn.clicked.connect(self.toggle_hide)

        control_layout.addWidget(self.collapse_btn)
        control_layout.addWidget(self.title_label, 1)
        control_layout.addWidget(self.hide_btn)

        self.main_layout.addWidget(self.control_frame)

        # 菜单树（卡片式）
        self.menu_tree = QTreeWidget()
        self.menu_tree.setHeaderHidden(True)
        self.menu_tree.setStyleSheet("""
            QTreeWidget {
                background-color: #f5f7fa;
                border: none;
                padding: 2px;
            }
            QTreeWidget::item {
                height: 28px;
                border-radius: 3px;
                margin: 1px 2px;
                padding: 2px 5px;
                background-color: white;
                border: 1px solid #e0e0e0;
                box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            }
             QTreeWidget::item:selected {
                 background-color: #e3f2fd;
                 border: 1px solid #1E88E5;
                 color: #1E88E5;
             }
            QTreeWidget::item:hover {
                background-color: #F1F8E9;
                border: 1px solid #81c784;
            }
            QTreeWidget::branch {
                background-color: transparent;
                image: none;        /* 移除默认图标 */
                border-image: none; /* 移除边框图像 */
                width: 0px;         /* 宽度设为0 */
                
            }
            QTreeWidget::branch:has-children:!has-siblings:closed,
            QTreeWidget::branch:closed:has-children:has-siblings {
                background-color: transparent;
            }
            QTreeWidget::branch:open:has-children:!has-siblings,
            QTreeWidget::branch:open:has-children:has-siblings {
                background-color: transparent;
            } 
            /* 第1级分支的缩进 */
            QTreeWidget::item:!has-children {
                padding-left: 10px;
            }
        """)

        self.menu_tree.setAnimated(True)
        self.menu_tree.setIndentation(1)

        # 绑定树控件的点击事件
        self.menu_tree.itemClicked.connect(self.on_item_clicked)

        # 添加菜单数据
        self.add_menu_items()

        self.main_layout.addWidget(self.menu_tree, 1)

        # 宽度配置
        self.expanded_width = 200  # 展开状态宽度
        self.collapsed_width = 100  # 折叠状态宽度
        self.setFixedWidth(self.expanded_width)

    def add_menu_items(self):
        # 密码学工具（主菜单）
        crypto_item = QTreeWidgetItem(self.menu_tree)
        crypto_item.setText(0, "密码学工具")
        # crypto_item.setIcon(0, QIcon("resource/Setting.ico"))

        normal_icon_path = resource_path(os.path.join('resource','menu.png'))
        icon_path = resource_path(os.path.join('resource', 'encrypted.png'))
        crypto_item.setIcon(0, QIcon(icon_path))

        # 子菜单
        codec_item = QTreeWidgetItem(crypto_item)
        codec_item.setText(0, "编码解码工具")
        codec_item.setIcon(0,QIcon(normal_icon_path))

        # 子菜单
        aes_item = QTreeWidgetItem(crypto_item)
        aes_item.setText(0, "加密解密工具")
        aes_item.setIcon(0,QIcon(normal_icon_path))

        rsa_item = QTreeWidgetItem(crypto_item)
        rsa_item.setText(0, "RSA加解密工具")
        rsa_item.setIcon(0,QIcon(normal_icon_path))

        # 子菜单
        md5_item = QTreeWidgetItem(crypto_item)
        md5_item.setText(0, "MD5工具")
        md5_item.setIcon(0, QIcon(normal_icon_path))

        # 开发调试工具（主菜单）
        dev_item = QTreeWidgetItem(self.menu_tree)
        dev_item.setText(0, "开发调试工具")
        # dev_item.setIcon(0, QIcon("resource/devenv.ico"))
        icon_path2 = resource_path(os.path.join('resource', 'devenv.ico'))
        dev_item.setIcon(0, QIcon(icon_path2))
        # 子菜单
        # 子菜单
        json_item = QTreeWidgetItem(dev_item)
        json_item.setText(0, "Json处理工具")
        json_item.setIcon(0, QIcon(normal_icon_path))

        regex_item = QTreeWidgetItem(dev_item)
        regex_item.setText(0, "正则表达式工具")
        regex_item.setIcon(0, QIcon(normal_icon_path))

        jwt_item = QTreeWidgetItem(dev_item)
        jwt_item.setText(0, "JWT处理工具")
        jwt_item.setIcon(0, QIcon(normal_icon_path))

        switch_hosts = QTreeWidgetItem(dev_item)
        switch_hosts.setText(0, "Hosts修改工具")
        switch_hosts.setIcon(0, QIcon(normal_icon_path))


        # 渗透辅助工具（主菜单）
        penetration_item = QTreeWidgetItem(self.menu_tree)
        penetration_item.setText(0, "渗透辅助工具")
        # penetration_item.setIcon(0, QIcon("resource/Threat.ico"))
        icon_path3 = resource_path(os.path.join('resource', 'Threat.ico'))
        penetration_item.setIcon(0, QIcon(icon_path3))

        command_item = QTreeWidgetItem(penetration_item)
        command_item.setText(0,"常用命令工具")
        command_item.setIcon(0, QIcon(normal_icon_path))

        # 其它小工具（主菜单）
        others_item = QTreeWidgetItem(self.menu_tree)
        others_item.setText(0, "其它小工具")
        # others_item.setIcon(0, QIcon("resource/other.ico"))
        icon_path4 = resource_path(os.path.join('resource', 'other.ico'))
        others_item.setIcon(0, QIcon(icon_path4))

        qrcode_item = QTreeWidgetItem(others_item)
        qrcode_item.setText(0, "二维码工具")
        qrcode_item.setIcon(0, QIcon(normal_icon_path))

        timestamp_item = QTreeWidgetItem(others_item)
        timestamp_item.setText(0, "Unix时间戳工具")
        timestamp_item.setIcon(0, QIcon(normal_icon_path))

    def on_item_clicked(self, item, column):
        """处理菜单项点击事件，通过信号传递出去"""
        # 获取菜单项文本（考虑折叠状态）
        item_text = item.text(column)
        if not item_text:
            item_text = item.data(0, Qt.UserRole)

        # 只处理叶子节点（子菜单）的点击
        if item.childCount() == 0 and item_text:
            self.menu_clicked.emit(item_text)

    def toggle_collapse(self):
        if self.is_collapsed:
            # 展开逻辑
            self.title_label.show()
            self.menu_tree.setColumnWidth(0, self.expanded_width)
            self.collapse_btn.setText("≡")
            # 恢复文本
            iterator = QTreeWidgetItemIterator(self.menu_tree)
            while iterator.value():
                item = iterator.value()
                original_text = item.data(0, Qt.UserRole)
                if original_text:
                    item.setText(0, original_text)
                iterator += 1
            self.is_collapsed = False
        else:
            # 折叠逻辑
            self.title_label.hide()
            self.menu_tree.setColumnWidth(0, self.collapsed_width)
            # 暂存文本
            iterator = QTreeWidgetItemIterator(self.menu_tree)
            while iterator.value():
                item = iterator.value()
                item.setData(0, Qt.UserRole, item.text(0))
                item.setText(0, "")
                iterator += 1
            self.collapse_btn.setText("⟩")
            self.is_collapsed = True
        # 执行宽度动画
        self.animate_width(self.expanded_width if not self.is_collapsed else self.collapsed_width)
        self.menu_toggled.emit(self.is_collapsed)

    def toggle_hide(self):
        if self.is_hidden:
            # 显示逻辑
            self.show()
            self.hide_btn.setText("⟨")
            target_width = self.expanded_width if not self.is_collapsed else self.collapsed_width
            self.control_frame.show()
            if not self.is_collapsed:
                self.menu_tree.show()
                self.title_label.show()
            self.animate_width(target_width)
            self.is_hidden = False
        else:
            # 隐藏逻辑
            self.animate_width(0)
            self.hide_btn.setText("⟩")
            self.is_hidden = True
        self.menu_toggled.emit(self.is_hidden)

    def animate_width(self, target_width):
        self.setMinimumWidth(self.width())
        animation = QPropertyAnimation(self, b"minimumWidth")
        animation.setDuration(300)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.setStartValue(self.width())
        animation.setEndValue(target_width)
        if target_width == 0:
            animation.finished.connect(self.hide)
        else:
            if self.isHidden():
                self.show()
        animation.start()


class FloatingButton(QToolButton):
    """侧边栏隐藏时的显示按钮"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()

    def init_ui(self):
        self.setText("⟩")
        self.setToolTip("显示侧边栏")
        # self.setStyleSheet("""
        #     QToolButton {
        #         background-color: #1E88E5;
        #         color: white;
        #         border: none;
        #         font-size: 16px;
        #         border-radius: 0 3px 3px 0;
        #         padding: 5px 2px;
        #         z-index: 100;
        #     }
        #     QToolButton:hover {
        #         background-color: #0D47A1;
        #     }
        # """)
        self.setStyleSheet("""
                    QToolButton {
                        background-color: #1E88E5;
                        color: white;
                        border: 2px;
                        border-radius: 6x 6px 6px 6x;
                        padding: 5px 2px;
                        z-index: 100;
                    }
                    QToolButton:hover {
                        background-color: #325EA1;
                    }
                """)
        self.setFixedSize(16, 32)
        self.hide()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.create_menu_bar()

    def init_ui(self):

        self.setWindowTitle("")
        self.setGeometry(300, 300, 1000, 600)

        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局（垂直）
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 分割器（管理侧边栏与内容区）
        self.splitter = QSplitter(Qt.Horizontal)

        # 侧边栏
        self.sidebar = CollapsibleSidebar(self)
        # 连接菜单点击信号
        self.sidebar.menu_clicked.connect(self.open_new_tab)
        self.splitter.addWidget(self.sidebar)

        # 右侧内容区 - 使用 QTabWidget 作为容器
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)  # 允许关闭 Tab
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.splitter.addWidget(self.tab_widget)

        # 初始化时，自动添加一个默认 Tab 作为主页面（包含翻页时钟）
        self.add_default_tab()

        # 将分割器加入主布局
        main_layout.addWidget(self.splitter)

        # 设置图标
        # icon = QtGui.QIcon("resource/App.ico")  # 支持.ico, .png, .jpg等格式
        icon_path = resource_path(os.path.join('resource', 'App.ico'))
        icon = QtGui.QIcon(icon_path)
        self.setWindowIcon(icon)
        # 设置窗口程序字体
        # font = QtGui.QFont()
        # font.setFamily("微软雅黑")

        # 浮动按钮
        self.floating_button = FloatingButton(self)
        self.floating_button.clicked.connect(self.show_sidebar)

        # 设置分割器初始尺寸
        self.splitter.setSizes([160, 840])

        # 信号连接（侧边栏状态变化）
        self.sidebar.menu_toggled.connect(self.on_sidebar_toggled)

        # 状态栏
        self.status_bar = SystemStatusBar(
            self,
            update_interval=1.0,  # 更新间隔1秒
            show_system_info=False  # 只显示进程信息
        )
        self.setStatusBar(self.status_bar)

    def create_menu_bar(self):
        """创建顶部菜单栏"""
        menubar = self.menuBar()

        # 1. 设置菜单
        settings_menu = menubar.addMenu("设置")

        # 退出动作
        font_action = QAction("设置字体", self)
        exit_action = QAction("退出", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("退出应用程序")
        font_action.triggered.connect(self.set_font)
        exit_action.triggered.connect(self.close)
        settings_menu.addAction(font_action)
        settings_menu.addAction(exit_action)

        # 2. 记事本菜单
        notepad_menu = menubar.addMenu("临时记事本")

        # 新建临时记事本
        new_note_action = QAction("新建临时记事本", self)
        new_note_action.setShortcut("Ctrl+N")
        new_note_action.setStatusTip("创建新的临时记事本")
        new_note_action.triggered.connect(self.new_notepad)
        notepad_menu.addAction(new_note_action)

        # 打开记事本
        open_note_action = QAction("打开记事本", self)
        open_note_action.setShortcut("Ctrl+O")
        open_note_action.setStatusTip("打开已存在的文本文件")
        # open_note_action.triggered.connect(self.open_notepad)
        # notepad_menu.addAction(open_note_action)

        # 3. 关于菜单
        about_menu = menubar.addMenu("帮助")

        # 关于应用
        about_action = QAction("关于", self)
        # about_action.setStatusTip("显示应用程序信息")
        about_action.triggered.connect(self.show_about_dialog)
        about_menu.addAction(about_action)

    def set_font(self):
        ok, font = QFontDialog.getFont()

        # 如果用户点击了确定按钮
        if ok:
            # 应用字体到整个应用程序
            QApplication.setFont(font)
            # 可以选择性地更新状态栏消息
            self.statusBar().showMessage(f"字体已设置为: {font.family()}, {font.pointSize()}pt")

    def show_about_dialog(self):
        """处理"About"菜单项"""
        # 创建并显示关于对话框
        QMessageBox.about(self,
            "关于本程序",
            "这是一个PyQt5开发的工具箱\n版本: 1.0.0\n© 2025 hqq"
        )

    def new_notepad(self):
        text_page = QWidget()
        layout = QVBoxLayout(text_page)
        text_edit = QTextEdit()
        text_edit.setStyleSheet("font-size: 18px;")
        layout.addWidget(text_edit)
        # self.tabWidget.addTab(text_page,"asdlfjals")
        self.tab_widget.addTab(text_page, f"临时记事本 {self.tab_widget.count() + 1}")
        self.tab_widget.setCurrentIndex(self.tab_widget.count() - 1)

    def open_notepad(self):
        """打开已存在的记事本文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "打开文件", "", "文本文件 (*.txt);;所有文件 (*)"
        )
        if file_path:
            notepad = NotepadWidget(self, file_path)
            self.notepad_windows.append(notepad)
            notepad.show()

    def add_default_tab(self):
        """添加默认 Tab 页（程序启动时的主页面），包含翻页时钟"""
        default_page = QFrame()
        default_layout = QVBoxLayout(default_page)
        default_layout.setContentsMargins(20, 20, 20, 20)

        # 页面标题
        title_label = QLabel("")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # title_label.setFont(QFont("Microsoft YaHei", 18, QFont.Bold))
        title_label.setStyleSheet("color: #333; margin-bottom: 20px;")

        # 添加翻页时钟组件
        self.flip_clock = FlipClock()
        # self.flip_clock = FlipDigit()

        # 说明文本
        info_label = QLabel("")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # info_label.setFont(QFont("Microsoft YaHei", 12))
        # info_label.setStyleSheet("color: #666; margin-top: 20px;")

        # 添加到布局
        default_layout.addWidget(title_label)
        default_layout.addWidget(self.flip_clock)
        default_layout.addWidget(info_label)
        default_layout.addStretch()

        # 设置页面背景
        default_page.setStyleSheet("background-color: #f0f2f5;")

        self.tab_widget.addTab(default_page, "主页")

    def open_new_tab(self, tab_title):
        """新增 Tab 页的通用方法"""
        # 避免重复创建相同标题的 Tab
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == tab_title:
                self.tab_widget.setCurrentIndex(i)
                return


        if tab_title == "加密解密工具":
            # 动态导入 encrypt_widget.py 中的 AESEncryptWidget
            from encrypt_widget import EncryptToolWindow
            new_page = EncryptToolWindow(self)  # 实例化外部窗口
        elif tab_title == "编码解码工具":
            from codec_widget import CodecWidget
            new_page = CodecWidget()
        elif tab_title == "RSA加解密工具":
            from rsa_widget import RSAtool
            new_page = RSAtool()
        elif tab_title == "MD5工具":
            from md5_widget import EncryptionTool
            new_page = EncryptionTool()
        elif tab_title == "Json处理工具":
            from json_widget import JsonProcessor
            new_page = JsonProcessor()
        elif tab_title == "JWT处理工具":
            from jwt_widget import JWTUtility
            new_page = JWTUtility()
        elif tab_title == "Hosts修改工具":
            from hosts_widget import HostsTool
            new_page = HostsTool()
        elif tab_title == "二维码工具":
            from qrcode_widget import QRCodeTool
            new_page = QRCodeTool()
        elif tab_title == "常用命令工具":
            from command_widget import CommandTool
            new_page = CommandTool()
        elif tab_title == "正则表达式工具":
            from regex_widget import RegexTool
            new_page = RegexTool()
        elif tab_title == "Unix时间戳工具":
            from timestamp_widget import TimestampTool
            new_page = TimestampTool()

        else:
            # 其他菜单默认显示空页面
            QMessageBox.warning(self,"友情提示","功能暂未实现~~\n敬请期待！")

            return
            # new_page = QFrame()
            # new_layout = QVBoxLayout(new_page)
            # new_label = QLabel(f"这是 {tab_title} 功能页面\n可在此填充具体逻辑")
            # new_label.setAlignment(Qt.AlignCenter)
            # new_label.setFont(QFont("Microsoft YaHei", 12))
            # new_layout.addWidget(new_label)
            # new_page.setStyleSheet("background-color: #f0f2f5;")


        # 添加到 TabWidget
        self.tab_widget.addTab(new_page, tab_title)
        # 切换到新创建的 Tab
        self.tab_widget.setCurrentIndex(self.tab_widget.count() - 1)

    def close_tab(self, index):
        """关闭 Tab 页"""
        # 保护默认页面不被关闭
        if self.tab_widget.tabText(index) == "主页":
            # self.statusBar().showMessage("默认页面不能关闭")
            return

        self.tab_widget.removeTab(index)

    def show_sidebar(self):
        """显示侧边栏"""
        self.sidebar.is_hidden = False
        self.sidebar.hide_btn.setText("⟨")
        target_width = self.sidebar.expanded_width if not self.sidebar.is_collapsed else self.sidebar.collapsed_width

        self.sidebar.show()
        self.sidebar.control_frame.show()
        if not self.sidebar.is_collapsed:
            self.sidebar.menu_tree.show()
            self.sidebar.title_label.show()

        self.sidebar.animate_width(target_width)
        self.sidebar.menu_toggled.emit(False)

    def on_sidebar_toggled(self, state):
        """响应侧边栏状态变化"""
        if self.sidebar.is_hidden:
            self.statusBar().showMessage("侧边栏已隐藏")
            self.splitter.setSizes([0, self.splitter.width()])
            self.floating_button.show()
            self.position_floating_button()
        else:
            status_text = "侧边栏已展开" if not self.sidebar.is_collapsed else "侧边栏已折叠"
            self.statusBar().showMessage(status_text)

            self.splitter.setSizes([
                self.sidebar.expanded_width if not self.sidebar.is_collapsed else self.sidebar.collapsed_width,
                self.splitter.width() - (
                    self.sidebar.expanded_width if not self.sidebar.is_collapsed else self.sidebar.collapsed_width)
            ])
            self.floating_button.hide()

    def position_floating_button(self):
        """定位浮动按钮"""
        y_pos = (self.height() - self.floating_button.height()) // 2
        self.floating_button.move(0, y_pos)

    def resizeEvent(self, event):
        """窗口大小改变时重新定位浮动按钮"""
        super().resizeEvent(event)
        if self.sidebar.is_hidden:
            self.position_floating_button()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    # 设置全局样式
    # app.setStyleSheet("""
    #         /* 全局字体设置 */
    #         * {
    #             font-family: "Microsoft YaHei", "SimHei", sans-serif;  /* 优先使用微软雅黑，其次黑体 */
    #             font-size: 14px;  /* 全局默认字体大小 */
    #         }
    #         /* 可针对特定控件单独调整（可选） */
    #         QLabel#titleLabel {
    #             font-size: 14px;
    #             font-weight: bold;
    #         }
    #         QPushButton {
    #             font-size: 14px;
    #         }
    #     """)
    #
    # app.setStyleSheet("""
    #         * {
    #             font-family: "SimHei", sans-serif;  /* 全局字体 */
    #             font-size: 14px;  /* 全局字体大小 */
    #         }
    #         QMainWindow, QWidget {
    #             background-color: #f9f9f9;
    #         }
    #         QLabel {
    #             color: #333;
    #         }
    #         QStatusBar {
    #             background-color: #e0e0e0;
    #             color: #555;
    #             border-top: 1px solid #ccc;
    #         }
    #         QMenuBar {
    #             background-color: #f0f0f0;
    #             padding: 2px;
    #         }
    #         QMenuBar::item {
    #             padding: 4px 10px;
    #             background-color: transparent;
    #         }
    #         QMenuBar::item:selected {
    #             background-color: #e0e0e0;
    #             border-radius: 3px;
    #         }
    #         QMenu {
    #             background-color: white;
    #             border: 1px solid #ccc;
    #             padding: 2px;
    #         }
    #         QMenu::item {
    #             padding: 4px 20px;
    #         }
    #         QMenu::item:selected {
    #             background-color: #1E88E5;
    #             color: white;
    #         }
    #     """)

    app_style = """
    QTextEdit {
        border: 1px solid #d0d0d0;
        border-radius: 4px;
        padding: 6px;
        background-color: white;
        selection-background-color: #accef7;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) inset;
    }
    QTextEdit:focus {
        border-color: #66afe9;
        outline: 0;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) inset, 0 0 8px rgba(102, 175, 233, 0.6);
    }
    QLineEdit {
        border: 1px solid #d0d0d0;
        border-radius: 4px;
        padding: 6px;
        background-color: white;
        selection-background-color: #accef7;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) inset;
    }
    QLineEdit:focus {
        border-color: #66afe9;
        outline: 0;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05) inset, 0 0 8px rgba(102, 175, 233, 0.6);
    }
    QLabel {
    color: #333333;
    background-color: transparent;
    }

    /* 按钮样式 */
    QPushButton {
        background-color: #f0f0f0;
        border: 1px solid #cccccc;
        border-radius: 4px;
        padding: 6px 12px;
        color: #333333;
    }

    QPushButton:hover {
        background-color: #e8e8e8;
        border-color: #b3b3b3;
    }

    QPushButton:pressed {
        background-color: #d0d0d0;
        border-color: #999999;
    }

    QPushButton:disabled {
        background-color: #f5f5f5;
        border-color: #dddddd;
        color: #aaaaaa;
    }
    /* 单选和复选框 */
    QRadioButton::indicator, QCheckBox::indicator {
        width: 16px;
        height: 16px;
        border: 1px solid #cccccc;
        border-radius: 8px; /* 圆形用于RadioButton */
        background-color: white;
    }
    QCheckBox::indicator {
        border-radius: 2px; /* 方形用于CheckBox */
    }
    QRadioButton::indicator:checked {
        background-color: #4a86e8;
        border-color: #4a86e8;
    }
    QRadioButton::indicator:checked::before {
        content: '';
        width: 8px;
        height: 8px;
        border-radius: 4px;
        background-color: white;
        position: absolute;
        top: 4px;
        left: 4px;
    }

    QCheckBox::indicator:checked {
        background-color: #4a86e8;
        border-color: #4a86e8;
    }

    QCheckBox::indicator:checked::before {
        content: '✓';
        color: white;
        position: absolute;
        top: -1px;
        left: 2px;
    }

    /* 下拉框 - 增强版 */
    QComboBox {
        combobox-popup: 0; /* 使用非原生下拉框 */
        border: 1px solid #b0b0b0; /* 更明显的边框 */
        border-radius: 4px;
        padding: 6px 25px 6px 6px; /* 右侧留出空间给下拉按钮 */
        background-color: white;
    }

    QComboBox:hover {
        border-color: #909090; /* 悬停时边框颜色加深 */
    }

    QComboBox:focus {
        border-color: #4a86e8;
        box-shadow: 0 0 5px rgba(74, 134, 232, 0.5);
    }

    QComboBox::drop-down {
        subcontrol-origin: padding;
        subcontrol-position: top right;
        width: 20px;
        border-left-width: 1px;
        border-left-color: #d0d0d0;
        border-left-style: solid;
        border-top-right-radius: 4px;
        border-bottom-right-radius: 4px;
        background-color: #f0f0f0;
    }

    QComboBox::drop-down:hover {
        background-color: #e8e8e8; /* 下拉按钮悬停效果 */
    }

    QComboBox::down-arrow {
        image: url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAGCAYAAAD68A/GAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEgAACxIB0t1+/AAAABx0RVh0U29mdHdhcmUAQWRvYmUgRmlyZXdvcmtzIENTNXG14zYAAABPSURBVAiZfc0xDkAAFIPhd2Kr1WRjcAExuIgzGUTIZ/AkImjSofnbNBAfHvzAHjOKNzhiQ42IDFXCDivaaxAJd0xYshT3QqBxqnxeHvhunpu23xnmAAAAAElFTkSuQmCC);
        width: 10px;
        height: 10px;
    }

    QComboBox QAbstractItemView {
        border: 1px solid #b0b0b0;
        border-radius: 4px;
        background-color: white;
        selection-background-color: #4a86e8;
        selection-color: white;
        padding: 4px;
        min-height: 80px; /* 设置最小高度 */
    }

    /* 滑块 */
    QSlider::groove:horizontal {
        border: 1px solid #bbb;
        background: white;
        height: 8px;
        border-radius: 4px;
    }

    QSlider::handle:horizontal {
        background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #eeeeee, stop:1 #cccccc);
        border: 1px solid #aaa;
        width: 16px;
        margin: -4px 0;
        border-radius: 8px;
    }

    /* 进度条 */
    QProgressBar {
        border: 1px solid #d0d0d0;
        border-radius: 4px;
        text-align: center;
        background-color: #f5f5f5;
    }

    QProgressBar::chunk {
        background-color: #4a86e8;
        border-radius: 3px;
    }

    /* 选项卡 */
    QTabWidget::pane {
        border: 1px solid #d0d0d0;
        border-radius: 4px;
        padding: 6px;
        top: -1px;
    }

    QTabBar::tab {
        background-color: #f0f0f0;
        border: 1px solid #d0d0d0;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        padding: 6px 12px;
        margin-right: -1px;
    }

    QTabBar::tab:selected, QTabBar::tab:hover {
        background-color: white;
    }

    QTabBar::tab:selected {
        border-color: #66afe9;
        z-index: 10;
    }

    /* 分组框 */
    QGroupBox {
        border: 1px solid #d0d0d0;
        border-radius: 4px;
        margin-top: 10px;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top center;
        padding: 0 5px;
        background-color: white;
    }
    """
    
    # /* 列表、树和表格 */
    # QListWidget, QTableWidget {
    #     border: 1px solid #d0d0d0;
    #     border-radius: 4px;
    #     background-color: white;
    # }
    #
    # QListWidget::item, QTreeWidget::item, QTableWidget::item {
    #     padding: 4px;
    #     border-bottom: 1px solid #f0f0f0;
    # }
    #
    # QListWidget::item:selected, QTreeWidget::item:selected, QTableWidget::item:selected {
    #     background-color: #4a86e8;
    #     color: white;
    # }
    #
    # QHeaderView::section {
    #     background-color: #f0f0f0;
    #     border: 1px solid #d0d0d0;
    #     padding: 6px;
    #     font-weight: bold;
    # }


    app.setStyleSheet(app_style)
    default_font = QFont("微软雅黑", 10)
    app.setFont(default_font)


    window = MainWindow()
    window.show()
    window.setWindowTitle("ToolBox")
    sys.exit(app.exec_())
