"""
Author: Gre3nStars
Date: 2025-07-21 17:11:32
LastEditors: Author
LastEditTime: 2025-08-07 11:32:57
Description: 
Copyright: Copyright (c) 2025 by Gre3nStars, All Rights Reserved. 
"""
import psutil
import threading
import time
from PySide6.QtWidgets import QStatusBar, QLabel, QProgressBar, QHBoxLayout, QWidget
from PySide6.QtCore import QTimer, Signal, QObject, Qt
from PySide6.QtGui import QFont


class SystemMonitor(QObject):
    """系统监控器，用于获取系统信息"""
    data_updated = Signal(dict)

    def __init__(self, update_interval=2.0):
        super().__init__()
        self.update_interval = update_interval
        self.is_running = False
        self.monitor_thread = None

    def start_monitoring(self):
        """开始监控"""
        if not self.is_running:
            self.is_running = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)

    def _monitor_loop(self):
        """监控循环"""
        while self.is_running:
            try:
                # 获取当前进程信息
                current_process = psutil.Process()

                # 获取系统信息
                system_data = {
                    'pid': current_process.pid,
                    'cpu_percent': current_process.cpu_percent(),
                    'memory_percent': current_process.memory_percent(),
                    'memory_mb': current_process.memory_info().rss / 1024 / 1024,
                    'system_cpu_percent': psutil.cpu_percent(interval=0.1),
                    'system_memory_percent': psutil.virtual_memory().percent,
                    'system_memory_used_gb': psutil.virtual_memory().used / 1024 / 1024 / 1024,
                    'system_memory_total_gb': psutil.virtual_memory().total / 1024 / 1024 / 1024
                }

                # 发送数据更新信号
                self.data_updated.emit(system_data)

                # 等待下次更新
                time.sleep(self.update_interval)

            except Exception as e:
                print(f"系统监控错误: {e}")
                time.sleep(self.update_interval)


class SystemStatusBar(QStatusBar):
    """系统状态栏组件"""

    def __init__(self, parent=None, update_interval=2.0, show_system_info=True, auto_restore=True, restore_delay=5.0):
        super().__init__(parent)

        self.update_interval = update_interval
        self.show_system_info = show_system_info
        self.auto_restore = auto_restore
        self.restore_delay = restore_delay

        # 颜色阈值配置
        self.cpu_thresholds = {
            'normal': 30,  # 正常阈值（绿色）
            'warning': 70  # 警告阈值（橙色）
        }
        self.memory_thresholds = {
            'normal': 50,  # 正常阈值（绿色）
            'warning': 80  # 警告阈值（橙色）
        }

        # 创建系统监控器
        self.system_monitor = SystemMonitor(update_interval)
        self.system_monitor.data_updated.connect(self.update_status)

        # 恢复定时器
        self.restore_timer = QTimer()
        self.restore_timer.setSingleShot(True)
        self.restore_timer.timeout.connect(self.restore_system_status)

        # 保存原始状态信息
        self.original_status_widget = None
        self.is_custom_message = False

        # 初始化UI
        self.init_ui()

        # 启动监控
        self.system_monitor.start_monitoring()

    def init_ui(self):
        """初始化UI"""
        # 设置状态栏样式
        self.setStyleSheet("""
            QStatusBar {
                background-color: #f0f0f0;
                border-top: 1px solid #ccc;
                padding: 2px;
            }
            QStatusBar QLabel {
                padding: 2px 6px;
                border-radius: 3px;
                background-color: #e0e0e0;
                border: 1px solid #ccc;
                font-size: 11px;
                font-family: 'Consolas', 'Monaco', monospace;
            }
            QStatusBar QProgressBar {
                border: 1px solid #ccc;
                border-radius: 3px;
                text-align: center;
                font-size: 10px;
                font-weight: bold;
            }
            QStatusBar QProgressBar::chunk {
                border-radius: 2px;
            }
        """)

        # 创建状态信息容器
        self.status_widget = QWidget()
        self.status_layout = QHBoxLayout(self.status_widget)
        self.status_layout.setContentsMargins(0, 0, 0, 0)
        self.status_layout.setSpacing(8)

        # 进程ID标签
        self.pid_label = QLabel("PID: --")
        self.pid_label.setToolTip("当前进程ID")
        self.status_layout.addWidget(self.pid_label)

        # 进程CPU使用率
        self.process_cpu_label = QLabel("进程CPU: --%")
        self.process_cpu_label.setToolTip("当前进程CPU使用率")
        self.status_layout.addWidget(self.process_cpu_label)

        # 进程内存使用率
        self.process_memory_label = QLabel("进程内存: --%")
        self.process_memory_label.setToolTip("当前进程内存使用率")
        self.status_layout.addWidget(self.process_memory_label)

        # 进程内存使用量
        self.process_memory_mb_label = QLabel("进程内存: --MB")
        self.process_memory_mb_label.setToolTip("当前进程内存使用量(MB)")
        self.status_layout.addWidget(self.process_memory_mb_label)

        if self.show_system_info:
            # 分隔符
            separator1 = QLabel("|")
            separator1.setStyleSheet("background: transparent; border: none; color: #666;")
            self.status_layout.addWidget(separator1)

            # 系统CPU使用率
            self.system_cpu_label = QLabel("系统CPU: --%")
            self.system_cpu_label.setToolTip("系统整体CPU使用率")
            self.status_layout.addWidget(self.system_cpu_label)

            # 系统内存使用率进度条
            self.system_memory_progress = QProgressBar()
            self.system_memory_progress.setFixedSize(80, 16)
            self.system_memory_progress.setToolTip("系统内存使用率")
            self.system_memory_progress.setFormat("内存: %p%")
            self.status_layout.addWidget(self.system_memory_progress)

            # 系统内存使用量
            self.system_memory_label = QLabel("系统内存: --/--GB")
            self.system_memory_label.setToolTip("系统内存使用量/总内存")
            self.status_layout.addWidget(self.system_memory_label)

        # 添加弹性空间
        self.status_layout.addStretch()

        # 将状态信息容器添加到状态栏
        self.addWidget(self.status_widget)

        # 保存原始状态组件引用
        self.original_status_widget = self.status_widget

        # 设置初始状态
        self.update_status({
            'pid': '--',
            'cpu_percent': 0,
            'memory_percent': 0,
            'memory_mb': 0,
            'system_cpu_percent': 0,
            'system_memory_percent': 0,
            'system_memory_used_gb': 0,
            'system_memory_total_gb': 0
        })

    def update_status(self, data):
        """更新状态显示"""
        try:
            # 更新进程信息
            self.pid_label.setText(f"PID: {data['pid']}")

            # 更新进程CPU使用率（带颜色）
            cpu_percent = data['cpu_percent']
            self.process_cpu_label.setText(f"进程CPU: {cpu_percent:.1f}%")
            self.update_label_color(self.process_cpu_label, cpu_percent, 'cpu')

            # 更新进程内存使用率（带颜色）
            memory_percent = data['memory_percent']
            self.process_memory_label.setText(f"进程内存: {memory_percent:.1f}%")
            self.update_label_color(self.process_memory_label, memory_percent, 'memory')

            # 更新进程内存使用量
            self.process_memory_mb_label.setText(f"进程内存: {data['memory_mb']:.1f}MB")

            # 更新系统信息
            if self.show_system_info:
                # 更新系统CPU使用率（带颜色）
                system_cpu_percent = data['system_cpu_percent']
                self.system_cpu_label.setText(f"系统CPU: {system_cpu_percent:.1f}%")
                self.update_label_color(self.system_cpu_label, system_cpu_percent, 'cpu')

                # 更新系统内存进度条
                system_memory_percent = data['system_memory_percent']
                self.system_memory_progress.setValue(int(system_memory_percent))
                self.system_memory_label.setText(
                    f"系统内存: {data['system_memory_used_gb']:.1f}/{data['system_memory_total_gb']:.1f}GB"
                )

                # 根据内存使用率设置进度条颜色
                self.update_progress_color(system_memory_percent)

        except Exception as e:
            print(f"更新状态栏错误: {e}")

    def update_label_color(self, label, percent, type_name):
        """更新标签颜色"""
        if type_name == 'cpu':
            # CPU使用率颜色阈值
            if percent < self.cpu_thresholds['normal']:
                color = "#4CAF50"  # 绿色 - 正常
            elif percent < self.cpu_thresholds['warning']:
                color = "#FF9800"  # 橙色 - 警告
            else:
                color = "#F44336"  # 红色 - 危险
        else:  # memory
            # 内存使用率颜色阈值
            if percent < self.memory_thresholds['normal']:
                color = "#4CAF50"  # 绿色 - 正常
            elif percent < self.memory_thresholds['warning']:
                color = "#FF9800"  # 橙色 - 警告
            else:
                color = "#F44336"  # 红色 - 危险

        # 更新标签样式
        label.setStyleSheet(f"""
            QLabel {{
                padding: 2px 6px;
                border-radius: 3px;
                background-color: #e0e0e0;
                border: 1px solid #ccc;
                font-size: 11px;
                font-family: 'Consolas', 'Monaco', monospace;
                color: {color};
                font-weight: bold;
            }}
        """)

    def update_progress_color(self, memory_percent):
        """更新进度条颜色"""
        if memory_percent < self.memory_thresholds['normal']:
            self.system_memory_progress.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #ccc;
                    border-radius: 3px;
                    text-align: center;
                    font-size: 10px;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #4CAF50;
                    border-radius: 2px;
                }
            """)
        elif memory_percent < self.memory_thresholds['warning']:
            self.system_memory_progress.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #ccc;
                    border-radius: 3px;
                    text-align: center;
                    font-size: 10px;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #FF9800;
                    border-radius: 2px;
                }
            """)
        else:
            self.system_memory_progress.setStyleSheet("""
                QProgressBar {
                    border: 1px solid #ccc;
                    border-radius: 3px;
                    text-align: center;
                    font-size: 10px;
                    font-weight: bold;
                }
                QProgressBar::chunk {
                    background-color: #F44336;
                    border-radius: 2px;
                }
            """)

    def set_update_interval(self, interval):
        """设置更新间隔"""
        self.update_interval = interval
        self.system_monitor.stop_monitoring()
        self.system_monitor = SystemMonitor(interval)
        self.system_monitor.data_updated.connect(self.update_status)
        self.system_monitor.start_monitoring()

    def show_system_info(self, show=True):
        """显示/隐藏系统信息"""
        self.show_system_info = show
        # 重新初始化UI
        self.clearMessage()
        self.removeWidget(self.status_widget)
        self.status_widget.deleteLater()
        self.init_ui()

    def showMessage(self, message, timeout=0):
        """重写showMessage方法，拦截所有状态栏消息显示"""
        if self.auto_restore:
            self.is_custom_message = True
            # 隐藏系统状态组件
            if self.original_status_widget:
                self.original_status_widget.setVisible(False)
            # 启动恢复定时器
            if timeout > 0:
                self.restore_timer.start(timeout * 1000)
            else:
                self.restore_timer.start(self.restore_delay * 1000)

        super().showMessage(message, timeout)

    def show_message(self, message, timeout=0):
        """显示消息，支持自动恢复（兼容方法）"""
        self.showMessage(message, timeout)

    def clearMessage(self):
        """重写clearMessage方法，拦截所有状态栏消息清除"""
        super().clearMessage()
        if self.auto_restore:
            self.restore_system_status()

    def clear_message(self):
        """清除消息，立即恢复系统状态（兼容方法）"""
        self.clearMessage()

    def restore_system_status(self):
        """恢复系统状态显示"""
        if self.auto_restore and self.original_status_widget:
            self.is_custom_message = False
            self.original_status_widget.setVisible(True)
            self.restore_timer.stop()
            # 清除可能残留的消息
            super().clearMessage()

    def set_auto_restore(self, enabled=True, delay=None):
        """设置自动恢复功能"""
        self.auto_restore = enabled
        if delay is not None:
            self.restore_delay = delay

    def set_restore_delay(self, delay):
        """设置恢复延迟时间"""
        self.restore_delay = delay

    def set_cpu_thresholds(self, normal=30, warning=70):
        """设置CPU使用率颜色阈值"""
        self.cpu_thresholds['normal'] = normal
        self.cpu_thresholds['warning'] = warning

    def set_memory_thresholds(self, normal=50, warning=80):
        """设置内存使用率颜色阈值"""
        self.memory_thresholds['normal'] = normal
        self.memory_thresholds['warning'] = warning

    def get_cpu_thresholds(self):
        """获取CPU使用率颜色阈值"""
        return self.cpu_thresholds.copy()

    def get_memory_thresholds(self):
        """获取内存使用率颜色阈值"""
        return self.memory_thresholds.copy()

    def is_showing_custom_message(self):
        """检查是否正在显示自定义消息"""
        return self.is_custom_message

    def closeEvent(self, event):
        """关闭事件"""
        self.system_monitor.stop_monitoring()
        self.restore_timer.stop()
        super().closeEvent(event)


# 便捷函数，用于快速添加到现有窗口
def add_system_status_bar(window, update_interval=2.0, show_system_info=True, auto_restore=True, restore_delay=5.0):
    """
    为现有窗口添加系统状态栏

    Args:
        window: QMainWindow实例
        update_interval: 更新间隔（秒）
        show_system_info: 是否显示系统信息
        auto_restore: 是否启用自动恢复功能
        restore_delay: 自动恢复延迟时间（秒）

    Returns:
        SystemStatusBar实例
    """
    status_bar = SystemStatusBar(window, update_interval, show_system_info, auto_restore, restore_delay)
    window.setStatusBar(status_bar)
    return status_bar

