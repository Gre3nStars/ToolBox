"""
Author: Gre3nStars
Date: 2025-08-13 15:43:29
LastEditTime: 2025-08-15 15:05:20
Description: 
FilePath: ToolBox_public_v1.0.15/widgets/subdomain_query_widget.py
Copyright: Copyright (c) 2025 by Gre3nStars, All Rights Reserved. 
"""
import sys
import re
import requests
from abc import ABC, abstractmethod
from bs4 import BeautifulSoup
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QTextEdit, QPushButton,
                               QTableWidget, QTableWidgetItem, QFileDialog,
                               QGroupBox, QMessageBox, QSplitter,
                               QProgressBar, QLineEdit, QComboBox)
from PySide6.QtCore import Qt, Signal, QThread, QObject, QTimer, QSettings
from PySide6.QtGui import QFont, QColor, QCursor


# ********** 接口抽象层 **********
class QueryProvider(ABC):
    """查询服务提供者抽象基类，所有查询接口需实现此类"""

    @abstractmethod
    def get_name(self):
        """返回接口名称"""
        pass

    @abstractmethod
    def get_description(self):
        """返回接口描述"""
        pass

    @abstractmethod
    def supports_type(self, query_type):
        """判断是否支持指定查询类型（subdomain/ip）"""
        pass

    @abstractmethod
    def query(self, target, query_type, page, progress_callback):
        """执行查询
        参数:
            target: 查询目标
            query_type: 查询类型 (subdomain/ip)
            page: 页码
            progress_callback: 进度回调函数 (0-100)
        返回:
            包含以下键的字典:
                success: 布尔值
                records: 记录列表
                total_count: 总记录数
                has_more: 是否有更多页
                message: 错误信息（如果success为False）
        """
        pass

    def get_config_options(self):
        """返回配置选项（如有需要）"""
        return {}

    def save_config(self, config):
        """保存配置（如有需要）"""
        pass


# ********** 具体实现 - RapidDNS **********
class RapidDNSProvider(QueryProvider):
    """RapidDNS查询接口实现"""

    def get_name(self):
        return "RapidDNS"

    def get_description(self):
        return "提供子域名和IP关联域名查询服务"

    def supports_type(self, query_type):
        return query_type in ["subdomain", "ip"]

    def query(self, target, query_type, page, progress_callback):
        try:
            BASE_URL = "https://rapiddns.io"
            HEADERS = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate, br",
                "Referer": f"{BASE_URL}/",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            }

            if query_type == "subdomain":
                url = f"{BASE_URL}/s/{target}?page={page}"
            else:
                url = f"{BASE_URL}/ip/{target}?page={page}"

            progress_callback(30)

            response = requests.get(
                url,
                headers=HEADERS,
                timeout=60,
                allow_redirects=True
            )

  
            progress_callback(70)

            if response.status_code != 200:
                return {
                    "success": False,
                    "message": f"请求失败，状态码: {response.status_code}",
                    "records": [],
                    "total_count": 0,
                    "has_more": False
                }

            return self.parse_response(response.text, page)

        except Exception as e:
            return {
                "success": False,
                "message": f"查询错误: {str(e)}",
                "records": [],
                "total_count": 0,
                "has_more": False
            }

    def parse_response(self, html, page):
        """解析RapidDNS响应"""
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # 提取总记录数
            total_count = 0
            total_div = soup.find('div', style=re.compile(r'margin: 0 8px;'))

            if total_div and 'total:' in total_div.get_text().lower():
                total_span = total_div.find('span', style=re.compile(r'color: #39cfca;'))
                if total_span:
                    total_text = total_span.get_text(strip=True)
                    num_match = re.search(r'(\d+)', total_text)
                    if num_match:
                        total_count = int(num_match.group(1))

            # 备选方案提取总记录数
            if total_count == 0:
                total_elements = soup.find_all(text=re.compile(r'Total:', re.IGNORECASE))
                for elem in total_elements:
                    parent = elem.parent
                    if parent:
                        total_text = parent.get_text()
                        num_match = re.search(r'(\d+)', total_text)
                        if num_match:
                            total_count = int(num_match.group(1))
                            break

            # 查找结果表格
            table = soup.find('table', id='table')
            if not table:
                table = soup.find('table', class_=re.compile(r'result', re.IGNORECASE))
            if not table:
                tables = soup.find_all('table')
                if tables:
                    table = tables[0]

            if not table:
                return {
                    "success": False,
                    "message": "未找到结果表格",
                    "records": [],
                    "total_count": total_count,
                    "has_more": False
                }

            # 提取记录
            tbody = table.find('tbody')
            if tbody:
                rows = tbody.find_all('tr')
            else:
                all_rows = table.find_all('tr')
                rows = all_rows[1:] if len(all_rows) > 1 else []

            records = []
            row_number = (page - 1) * 100 + 1  # 计算全局序号

            for row in rows:
                cols = row.find_all('td')
                if 4 <= len(cols) <= 5:
                    domain = cols[0].get_text(strip=True)
                    address = cols[1].get_text(strip=True)
                    if cols[1].find('a'):
                        address = cols[1].find('a').get_text(strip=True)

                    record_type = cols[2].get_text(strip=True) if len(cols) > 2 else ""
                    date = cols[3].get_text(strip=True) if len(cols) > 3 else ""

                    if domain and address:
                        records.append({
                            "序号": str(row_number),
                            "域名": domain,
                            "地址": address,
                            "类型": record_type,
                            "日期": date
                        })
                        row_number += 1

            # 判断是否有更多页
            items_per_page = 100
            has_more = (page * items_per_page) < total_count if total_count > 0 else len(records) == items_per_page

            return {
                "success": True,
                "records": records,
                "total_count": total_count,
                "has_more": has_more,
                "message": ""
            }

        except Exception as e:
            return {
                "success": False,
                "message": f"解析错误: {str(e)}",
                "records": [],
                "total_count": 0,
                "has_more": False
            }


# ********** 演示查询接口 **********
class DemoDNSProvider(QueryProvider):
    """演示用的查询接口实现"""

    def get_name(self):
        return "DemoDNS"

    def get_description(self):
        return "演示用的查询接口，返回模拟数据"

    def supports_type(self, query_type):
        return True  # 支持所有查询类型

    def query(self, target, query_type, page, progress_callback):
        # 模拟网络延迟
        import time
        for i in range(5):
            time.sleep(0.2)
            progress_callback(20 + i * 16)  # 模拟进度更新

        # 生成模拟数据
        records = []
        for i in range(10):
            records.append({
                "序号": str((page - 1) * 10 + i + 1),
                "域名": f"demo{i}.example.com",
                "地址": "192.168.1." + str(i + 1),
                "类型": "A",
                "日期": "2023-01-01"
            })

        progress_callback(100)

        return {
            "success": True,
            "records": records,
            "total_count": 50,  # 模拟总共有50条记录
            "has_more": page < 5,  # 模拟有5页数据
            "message": ""
        }


# ********** 接口管理 **********
class ProviderManager:
    """查询接口管理器"""

    def __init__(self):
        self.providers = []
        self.load_providers()

    def load_providers(self):
        """加载所有可用的查询接口"""
        # 注册内置接口
        self.register_provider(RapidDNSProvider())
        # self.register_provider(DemoDNSProvider())

        # 可以在这里添加更多接口加载逻辑，例如从插件目录加载

    def register_provider(self, provider):
        """注册一个查询接口"""
        if isinstance(provider, QueryProvider) and provider not in self.providers:
            self.providers.append(provider)

    def get_providers(self, query_type=None):
        """获取所有可用接口，可选按查询类型过滤"""
        if query_type:
            return [p for p in self.providers if p.supports_type(query_type)]
        return self.providers

    def get_provider_by_name(self, name):
        """通过名称获取接口实例"""
        for provider in self.providers:
            if provider.get_name() == name:
                return provider
        return None


# ********** 支持文件拖拽的文本编辑框 **********
class DragDropTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setPlaceholderText("请输入域名或IP地址（每行一个，支持批量查询）\n或直接拖拽文本文件到此处")

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()

            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        self.insertPlainText(content + "\n")
                    except UnicodeDecodeError:
                        try:
                            with open(file_path, 'r', encoding='gbk') as f:
                                content = f.read()
                            self.insertPlainText(content + "\n")
                        except Exception as e:
                            QMessageBox.warning(self, "文件读取失败", f"无法读取文件 {file_path}：{str(e)}")
                    except Exception as e:
                        QMessageBox.warning(self, "文件读取失败", f"处理文件 {file_path} 时出错：{str(e)}")
        else:
            super().dropEvent(event)


# ********** 查询信号类 **********
class QuerySignals(QObject):
    page_result = Signal(dict)
    total_count_updated = Signal(int)
    progress_updated = Signal(int)
    finished = Signal()
    error = Signal(str)


# ********** 分页查询工作线程 **********
class QueryWorker(QThread):
    def __init__(self, provider, target, query_type, page):
        super().__init__()
        self.provider = provider
        self.target = target
        self.query_type = query_type
        self.page = page
        self.signals = QuerySignals()
        self.is_running = True  # 用于优雅停止线程

    def run(self):
        try:
            # 执行查询，通过回调更新进度
            result = self.provider.query(
                self.target,
                self.query_type,
                self.page,
                self.signals.progress_updated.emit
            )

            if not self.is_running:  # 检查线程是否已被要求停止
                return

            if result:
                result["target"] = self.target
                result["query_type"] = self.query_type
                result["page"] = self.page
                result["provider"] = self.provider.get_name()
                self.signals.page_result.emit(result)

                if "total_count" in result:
                    self.signals.total_count_updated.emit(result["total_count"])

            self.signals.finished.emit()

        except Exception as e:
            if self.is_running:  # 只有在线程正常运行时才发送错误信号
                self.signals.error.emit(f"查询错误: {str(e)}")
            self.signals.finished.emit()

    def stop(self):
        """优雅地停止线程"""
        self.is_running = False
        self.wait(1000)  # 等待1秒，给线程时间处理停止请求


# ********** 主窗口类 **********
class MultiDNSQueryTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.provider_manager = ProviderManager()
        self.settings = QSettings("DNSQueryTool", "Config")

        self.setWindowTitle("多接口DNS查询工具")
        self.setGeometry(100, 100, 800, 600)

        # 初始化状态变量
        self.current_target = None
        self.current_query_type = None
        self.current_provider = None
        self.all_records = []
        self.loaded_pages = set()
        self.total_count = 0
        self.items_per_page = 100
        self.current_display_page = 1
        self.query_worker = None  # 当前查询线程

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        splitter = QSplitter(Qt.Vertical)

        # 输入区域
        input_group = QGroupBox("查询输入")
        input_layout = QVBoxLayout()

        # input_note = QLabel("自动识别域名或IP地址（一次查询一个目标）:\n"
        #                     "- 域名（如: vpclub.cn）→ 查询子域名\n"
        #                     "- IP地址（如: 8.8.8.8 或 2409:8080::1）→ 查询同IP域名")
        # input_layout.addWidget(input_note)

        # 接口选择
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("查询接口:"))

        self.provider_combo = QComboBox()
        # self.provider_combo.setMinimumWidth(200)
        for provider in self.provider_manager.get_providers():
            self.provider_combo.addItem(provider.get_name(), provider)

        # 加载上次使用的接口
        last_provider = self.settings.value("last_provider")
        if last_provider:
            index = self.provider_combo.findText(last_provider)
            if index >= 0:
                self.provider_combo.setCurrentIndex(index)

        self.provider_combo.currentIndexChanged.connect(self.on_provider_changed)
        provider_layout.addWidget(self.provider_combo)
        provider_layout.addStretch()
        input_layout.addLayout(provider_layout)

        # 接口描述
        # self.provider_desc = QLabel("接口描述将显示在这里")
        # self.provider_desc.setStyleSheet("color: #666; font-style: italic;")
        # self.provider_desc.setWordWrap(True)
        # input_layout.addWidget(self.provider_desc)
        # self.update_provider_description()

        # 查询输入框
        self.query_input = DragDropTextEdit()
        input_layout.addWidget(self.query_input)

        # 按钮布局
        btn_layout = QHBoxLayout()
        self.btn_clear = QPushButton("\U0001F5D1 清空输入")
        self.btn_clear.clicked.connect(self.clear_input)

        self.btn_start = QPushButton("\U0001F50E 开始查询")
        self.btn_start.clicked.connect(self.start_new_query)

        # self.query_progress = QProgressBar()
        # self.query_progress.setMinimumWidth(200)
        # self.query_progress.setMaximumHeight(35)
        # self.query_progress.setValue(0)
        # self.query_progress.setHidden(True)

        btn_layout.addWidget(self.btn_start)
        btn_layout.addWidget(self.btn_clear)
        # btn_layout.addWidget(self.query_progress)
        
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        input_layout.addLayout(btn_layout)

        input_group.setLayout(input_layout)
        splitter.addWidget(input_group)

        # 结果区域
        result_group = QGroupBox("查询结果")
        result_layout = QVBoxLayout()

        self.result_table = QTableWidget()
        self.result_table.setColumnCount(7)  # 增加一列显示数据来源
        self.result_table.setHorizontalHeaderLabels([
            "数据来源", "查询目标", "序号", "域名", "地址", "类型", "日期"
        ])
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.setEditTriggers(QTableWidget.DoubleClicked)
        self.result_table.setSelectionBehavior(QTableWidget.SelectItems)
        self.result_table.setTextElideMode(Qt.ElideNone)
        result_layout.addWidget(self.result_table)

        # 分页布局
        pagination_layout = QHBoxLayout()

        self.total_count_label = QLabel("总记录数: 0 \U0001F4C8")
        # self.total_count_label.setStyleSheet("margin-right: 20px; font-weight: bold;")

        self.page_info_label = QLabel("当前页: 0/0")
        # self.page_info_label.setStyleSheet("margin-right: 20px;")

        self.btn_first = QPushButton("首页 \U000023EE")
        self.btn_prev = QPushButton("上一页 \U00002B05")
        self.btn_next = QPushButton("下一页 \U000027A1")
        self.btn_last = QPushButton("末页 \U0001F501")

        jump_layout = QHBoxLayout()
        jump_layout.addWidget(QLabel("跳转到页:"))
        self.page_jump_input = QLineEdit()
        # self.page_jump_input.setMaximumWidth(60)
        self.btn_jump = QPushButton("确定 \U00002713")
        self.btn_jump.clicked.connect(self.jump_to_page)
        jump_layout.addWidget(self.page_jump_input)
        jump_layout.addWidget(self.btn_jump)
        jump_layout.setSpacing(5)

        self.btn_first.clicked.connect(self.go_first_page)
        self.btn_prev.clicked.connect(self.go_prev_page)
        self.btn_next.clicked.connect(self.go_next_page)
        self.btn_last.clicked.connect(self.go_last_page)

        pagination_layout.addWidget(self.total_count_label)
        pagination_layout.addWidget(self.page_info_label)
        pagination_layout.addWidget(self.btn_first)
        pagination_layout.addWidget(self.btn_prev)
        pagination_layout.addLayout(jump_layout)
        pagination_layout.addWidget(self.btn_next)
        pagination_layout.addWidget(self.btn_last)
        pagination_layout.addStretch()
        pagination_layout.addStretch()

        # for btn in [self.btn_first, self.btn_prev, self.btn_next, self.btn_last, self.btn_jump]:
        #     btn.setStyleSheet("padding: 5px 10px;")

        result_layout.addLayout(pagination_layout)

        # 导出布局
        export_layout = QHBoxLayout()
        self.btn_export = QPushButton("\U0001F4BE 导出结果")
        self.btn_export.clicked.connect(self.export_results)
    

        self.btn_clear_results = QPushButton("\U0001F5D1 清空结果")
        self.btn_clear_results.clicked.connect(self.clear_results)


        export_layout.addStretch()
        export_layout.addWidget(self.btn_clear_results)
        export_layout.addWidget(self.btn_export)
        export_layout.setSpacing(10)
        result_layout.addLayout(export_layout)

        result_group.setLayout(result_layout)
        splitter.addWidget(result_group)

        splitter.setSizes([250, 650])
        main_layout.addWidget(splitter)

        self.statusBar().showMessage("\U00002705 就绪")
        self.update_pagination_controls()

    def on_provider_changed(self):
        """当选择的查询接口改变时触发"""
        self.update_provider_description()
        # 保存当前选择的接口
        current_provider = self.get_current_provider()
        if current_provider:
            self.settings.setValue("last_provider", current_provider.get_name())

    # def update_provider_description(self):
    #     """更新接口描述信息"""
    #     current_provider = self.get_current_provider()
    #     if current_provider:
    #         self.provider_desc.setText(f"接口描述: {current_provider.get_description()}")

    def get_current_provider(self):
        """获取当前选中的查询接口"""
        return self.provider_combo.currentData()

    def handle_page_result(self, result):
        """处理查询结果，在主线程中更新UI"""
        if not result or not result["success"]:
            QMessageBox.warning(self, "查询失败", result.get("message", "未知错误"))
            return

        print(f"接收到第 {result['page']} 页结果，记录数: {len(result['records'])}")

        if len(result["records"]) > 0:
            page = result["page"]
            if page not in self.loaded_pages:
                self.loaded_pages.add(page)
                start_index = (page - 1) * self.items_per_page

                for i, record in enumerate(result["records"]):
                    position = start_index + i
                    while len(self.all_records) <= position:
                        self.all_records.append(None)
                    # 添加数据来源信息
                    record["provider"] = result["provider"]
                    self.all_records[position] = record

            self.current_display_page = result["page"]
            self.show_current_page()
            self.update_pagination_info()
        else:
            QMessageBox.information(self, "提示", f"第 {result['page']} 页未找到记录")

    def show_current_page(self):
        """在主线程中显示当前页内容"""
        self.result_table.setRowCount(0)

        start = (self.current_display_page - 1) * self.items_per_page
        end = start + self.items_per_page

        displayed_count = 0
        for i in range(start, end):
            if i < len(self.all_records) and self.all_records[i] is not None:
                record = self.all_records[i]
                row = self.result_table.rowCount()
                self.result_table.insertRow(row)

                self.result_table.setItem(row, 0, QTableWidgetItem(record["provider"]))
                self.result_table.setItem(row, 1, QTableWidgetItem(self.current_target))
                self.result_table.setItem(row, 2, QTableWidgetItem(record["序号"]))
                self.result_table.setItem(row, 3, QTableWidgetItem(record["域名"]))
                self.result_table.setItem(row, 4, QTableWidgetItem(record["地址"]))
                self.result_table.setItem(row, 5, QTableWidgetItem(record["类型"]))
                self.result_table.setItem(row, 6, QTableWidgetItem(record["日期"]))

                displayed_count += 1

        print(f"添加到表格的记录数: {displayed_count}")

        if displayed_count == 0:
            QMessageBox.information(self, "提示", f"第 {self.current_display_page} 页未找到任何记录")

        self.result_table.resizeColumnsToContents()

    def detect_query_type(self, target):
        """检测查询目标类型（域名或IP）"""
        target = target.strip().lower()
        target = re.sub(r'^https?://', '', target)
        target = re.sub(r'[/:].*$', '', target)

        ipv4_pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        if re.match(ipv4_pattern, target):
            parts = target.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return "ip"

        ipv6_pattern = r'^([0-9a-fA-F:]+)$'
        if re.match(ipv6_pattern, target) and ':' in target and ':::' not in target:
            return "ip"

        return "subdomain"

    def start_new_query(self):
        """开始新的查询，首先清空原有数据"""
        # 检查是否已有查询在进行
        if self.query_worker and self.query_worker.isRunning():
            reply = QMessageBox.question(
                self, "查询进行中",
                "已有查询在进行中，是否要取消当前查询并开始新查询？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return
            self.query_worker.stop()

        input_text = self.query_input.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, "输入错误", "请输入一个域名或IP地址")
            return

        # 获取当前选择的查询接口
        self.current_provider = self.get_current_provider()
        if not self.current_provider:
            QMessageBox.warning(self, "选择错误", "请选择一个查询接口")
            return

        target = input_text.splitlines()[0].strip()
        self.current_query_type = self.detect_query_type(target)

        # 检查当前接口是否支持该查询类型
        if not self.current_provider.supports_type(self.current_query_type):
            QMessageBox.warning(
                self, "不支持的查询类型",
                f"{self.current_provider.get_name()} 不支持 {self.current_query_type} 类型的查询"
            )
            return

        # 清空原有数据
        self.clear_existing_data()

        self.current_target = target
        # self.query_progress.setHidden(False)
        # self.query_progress.setValue(0)
        self.load_page(1)

    def clear_existing_data(self):
        """清空现有查询数据"""
        self.all_records = []
        self.loaded_pages = set()
        self.total_count = 0
        self.current_display_page = 1
        self.result_table.setRowCount(0)  # 清空表格
        self.total_count_label.setText("总记录数: 0 \U0001F4C8")
        self.page_info_label.setText("当前页: 0/0")
        self.update_pagination_controls()

    def load_page(self, page):
        """加载指定页的数据，在后台线程中执行"""
        if page in self.loaded_pages or (self.query_worker and self.query_worker.isRunning()):
            return

        if self.total_count > 0:
            total_pages = self.calculate_total_pages()
            if page > total_pages:
                QMessageBox.information(self, "提示", f"已超出最大页数（共 {total_pages} 页）")
                # self.query_progress.setHidden(True)
                return

        self.statusBar().showMessage(f"正在使用 {self.current_provider.get_name()} 加载第 {page} 页... \U0001F551")
        self.btn_start.setEnabled(False)
        self.disable_pagination_buttons()
        QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))

        # 创建并启动新的查询线程
        self.query_worker = QueryWorker(
            self.current_provider,
            self.current_target,
            self.current_query_type,
            page
        )
        self.query_worker.signals.page_result.connect(self.handle_page_result)
        self.query_worker.signals.total_count_updated.connect(self.update_total_count)
        # self.query_worker.signals.progress_updated.connect(self.update_query_progress)
        self.query_worker.signals.error.connect(self.handle_query_error)
        self.query_worker.signals.finished.connect(self.on_query_finished)
        self.query_worker.start()

    # def update_query_progress(self, value):
    #     """更新查询进度条，在主线程中执行"""
    #     self.query_progress.setValue(value)
    #     if value == 100:
    #         QTimer.singleShot(500, lambda: self.query_progress.setHidden(True))

    def calculate_total_pages(self):
        """计算总页数"""
        if self.total_count == 0:
            return 0
        return (self.total_count + self.items_per_page - 1) // self.items_per_page

    def update_total_count(self, total):
        """更新总记录数，在主线程中执行"""
        self.total_count = total
        self.total_count_label.setText(f"总记录数: {self.total_count:,} \U0001F4C8")
        self.update_pagination_info()
        print(f"更新总记录数: {self.total_count}")

    def update_pagination_info(self):
        """更新分页信息，在主线程中执行"""
        total_pages = self.calculate_total_pages()
        self.page_info_label.setText(f"当前页: {self.current_display_page}/{total_pages}")
        self.page_jump_input.setText(str(self.current_display_page))
        self.update_pagination_controls()
        self.statusBar().showMessage(f"已加载第 {self.current_display_page} 页 \U00002705")

    def update_pagination_controls(self):
        """更新分页控件状态"""
        total_pages = self.calculate_total_pages()
        has_data = self.total_count > 0 or len([r for r in self.all_records if r is not None]) > 0

        self.btn_first.setEnabled(has_data and self.current_display_page > 1)
        self.btn_prev.setEnabled(has_data and self.current_display_page > 1)
        self.btn_next.setEnabled(has_data and (self.current_display_page < total_pages or total_pages == 0))
        self.btn_last.setEnabled(has_data and (self.current_display_page < total_pages or total_pages == 0))

    def disable_pagination_buttons(self):
        """禁用所有分页按钮"""
        self.btn_first.setEnabled(False)
        self.btn_prev.setEnabled(False)
        self.btn_next.setEnabled(False)
        self.btn_last.setEnabled(False)
        self.btn_jump.setEnabled(False)

    def enable_pagination_buttons(self):
        """启用分页按钮"""
        self.btn_jump.setEnabled(True)
        self.update_pagination_controls()

    def go_first_page(self):
        """跳转到第一页"""
        if self.current_display_page == 1:
            return

        # self.query_progress.setHidden(False)
        # self.query_progress.setValue(0)
        self.load_page(1)

    def go_prev_page(self):
        """跳转到上一页"""
        if self.current_display_page <= 1:
            return

        # self.query_progress.setHidden(False)
        # self.query_progress.setValue(0)
        prev_page = self.current_display_page - 1
        self.load_page(prev_page)

    def go_next_page(self):
        """跳转到下一页"""
        next_page = self.current_display_page + 1
        # self.query_progress.setHidden(False)
        # self.query_progress.setValue(0)
        self.load_page(next_page)

    def go_last_page(self):
        """跳转到最后一页"""
        total_pages = self.calculate_total_pages() if self.total_count > 0 else 10
        # self.query_progress.setHidden(False)
        # self.query_progress.setValue(0)
        self.load_page(total_pages)

    def jump_to_page(self):
        """跳转到指定页"""
        try:
            page = int(self.page_jump_input.text().strip())
            if page < 1:
                raise ValueError

            # self.query_progress.setHidden(False)
            # self.query_progress.setValue(0)
            self.load_page(page)
        except ValueError:
            QMessageBox.warning(self, "输入错误", "请输入有效的页码")
            self.page_jump_input.setText(str(self.current_display_page))

    def handle_query_error(self, error_msg):
        """处理查询错误，在主线程中执行"""
        self.statusBar().showMessage(f"查询错误: {error_msg} \U0000274C")
        QMessageBox.warning(self, "查询错误", error_msg)
        # self.query_progress.setHidden(True)
        QApplication.restoreOverrideCursor()

    def on_query_finished(self):
        """查询完成后清理，在主线程中执行"""
        self.query_worker = None
        self.btn_start.setEnabled(True)
        self.enable_pagination_buttons()
        QApplication.restoreOverrideCursor()

    def clear_input(self):
        """清空输入框"""
        self.query_input.clear()
        self.statusBar().showMessage("已清空输入 \U00002705")

    def clear_results(self):
        """清空查询结果"""
        if self.query_worker and self.query_worker.isRunning():
            self.query_worker.stop()

        self.clear_existing_data()
        # self.query_progress.setHidden(True)
        self.statusBar().showMessage("已清空结果 \U00002705")
        self.btn_start.setEnabled(True)
        QApplication.restoreOverrideCursor()

    def export_results(self):
        """导出查询结果"""
        valid_records = [r for r in self.all_records if r is not None]
        if not valid_records:
            QMessageBox.information(self, "提示", "没有可导出的记录")
            return

        from datetime import datetime
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"dns_results_{self.current_target}_{current_time}"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "导出结果", default_filename,
            "CSV文件 (*.csv);;文本文件 (*.txt);;Excel文件 (*.xlsx);;所有文件 (*)"
        )

        if not file_path:
            return

        try:
            export_data = []
            for record in valid_records:
                export_data.append({
                    "数据来源": record["provider"],
                    "查询目标": self.current_target,
                    "序号": record["序号"],
                    "域名": record["域名"],
                    "地址": record["地址"],
                    "类型": record["类型"],
                    "日期": record["日期"]
                })

            if file_path.endswith(".csv"):
                import csv
                with open(file_path, 'w', encoding='utf-8', newline='') as f:
                    fieldnames = ["数据来源", "查询目标", "序号", "域名", "地址", "类型", "日期"]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(export_data)

            elif file_path.endswith(".txt"):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"DNS查询结果 - 目标: {self.current_target}\n")
                    f.write(f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"总记录数: {len(export_data)}\n")
                    f.write("=" * 150 + "\n")
                    for i, item in enumerate(export_data, 1):
                        f.write(f"[{i}] 来源: {item['数据来源']}, 序号: {item['序号']}, 域名: {item['域名']}, "
                                f"地址: {item['地址']}, 类型: {item['类型']}, 日期: {item['日期']}\n")

            elif file_path.endswith(".xlsx"):
                import pandas as pd
                df = pd.DataFrame(export_data)
                df.to_excel(file_path, index=False)

            else:
                QMessageBox.warning(self, "格式错误", "不支持的文件格式")
                return

            QMessageBox.information(self, "成功", f"已导出 {len(export_data)} 条记录到 {file_path}")
            self.statusBar().showMessage(f"已导出结果到 {file_path} \U00002705")

        except ImportError as e:
            if "pandas" in str(e) or "openpyxl" in str(e):
                QMessageBox.warning(self, "依赖缺失",
                                    "导出Excel需要安装pandas和openpyxl\n命令: pip install pandas openpyxl")
            else:
                QMessageBox.warning(self, "依赖缺失", f"缺少必要组件: {str(e)}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出时发生错误: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("SimHei"))
    window = MultiDNSQueryTool()
    window.show()
    sys.exit(app.exec())
