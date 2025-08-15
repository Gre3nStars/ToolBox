"""
Author: Gre3nStars
Date: 2025-08-08 14:20:53
LastEditTime: 2025-08-12 10:42:56
Description: 
FilePath: ToolBox_internal/widgets/icp_query_widget.py
Copyright: Copyright (c) 2025 by Gre3nStars, All Rights Reserved. 
"""
import sys
import csv
import re
import time
import socket
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QTextEdit,
                               QPushButton, QTableWidget, QTableWidgetItem,
                               QFileDialog, QComboBox, QGroupBox,
                               QMessageBox, QSplitter, QProgressDialog, QLineEdit)
from PySide6.QtCore import Qt, Signal, QThread, QMimeData
from PySide6.QtGui import QFont, QColor, QDragEnterEvent, QDropEvent

# 尝试导入IP地址归属地查询工具
try:
    from widgets.ip_location_widget import QQWryReader

    ip_reader = QQWryReader()
    ip_location_support = True
except ImportError:
    ip_location_support = False
    print("警告: 未找到IP地址归属地查询模块，相关功能将不可用")


# 备案查询接口 - 使用GET请求
class ICPQueryAPI:
    # 基础URL和请求头
    BASE_URL = "https://www.beianx.cn"
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
        "Cookie": "__51vcke__JfvlrnUmvss1wiTZ=66a2f7c8-8504-527c-a067-96a42105b059; __51vuft__JfvlrnUmvss1wiTZ=1744169577253; acw_tc=1a0c39d217546215849011317ef2a5047c375c841d79bbcf9cb435f172bc9e; machine_str=76a12589-2433-4511-ae0c-05e9d2525ba3; .AspNetCore.Antiforgery.OGq99nrNx5I=CfDJ8MqL6GlHKUtPvbcvLdLdwqlTrdT2FoaW4OGMLpux4RjuzB9bNpuiIaQCs4ByXStGyN7i9poGDXX37G7O5-EtU1lFt1qmsiB4kciT5GX2lx3LvkgzCoIUZte9n4OZDZChWJNgShZlcg4kV-mNs652ht8; __51uvsct__JfvlrnUmvss1wiTZ=21;",
        "Referer": "https://www.beianx.cn/search/",
        "Upgrade-Insecure-Requests": "1"
    }

    @staticmethod
    def query_by_keyword(keyword, service_type="1"):
        """
        通过关键词查询备案信息（支持域名、公司名称等）
        使用GET请求，直接拼接URL
        service_type: 1-网站, 6-APP, 7-小程序, 8-快应用
        """
        try:
            # 对关键词进行URL编码
            encoded_keyword = quote(keyword, encoding='utf-8')

            # 构建GET请求URL
            url = f"{ICPQueryAPI.BASE_URL}/search/{encoded_keyword}?service_type={service_type}"

            # 发送GET查询请求
            response = requests.get(
                url,
                headers=ICPQueryAPI.HEADERS,
                timeout=10
            )

            # 检查请求是否成功
            if response.status_code != 200:
                return {"success": False, "message": f"请求失败，状态码: {response.status_code}"}

            # 解析HTML结果
            return ICPQueryAPI.parse_html_result(response.text, keyword)

        except requests.exceptions.Timeout:
            return {"success": False, "message": "查询超时，请稍后重试"}
        except Exception as e:
            return {"success": False, "message": f"查询失败: {str(e)}"}

    @staticmethod
    def parse_html_result(html, keyword):
        """解析HTML结果，提取备案信息"""
        try:
            soup = BeautifulSoup(html, 'html.parser')

            # 检查是否有结果表格，添加空值检查
            result_table = soup.find('table', class_='table table-sm table-bordered table-hover')
            if not result_table:
                return {"success": False, "message": f"未查询到 {keyword} 的备案信息"}

            # 提取更新时间，添加空值检查
            right_span = soup.find('span', class_='right-span')
            if right_span:
                update_time_text = right_span.get_text(strip=True)
                update_time_match = re.search(r'更新时间：(.*?)\s', update_time_text)
                update_time = update_time_match.group(1) if update_time_match else ""
            else:
                update_time = ""  # 如果没有找到更新时间，使用空值

            # 解析表格数据，修复find_all错误
            results = []

            # 先查找tbody，确保它存在
            tbody = result_table.find('tbody')
            if not tbody:
                # 如果没有tbody，尝试直接从table中找tr（有些网站可能不使用tbody）
                rows = result_table.find_all('tr')
                # 跳过表头行
                if rows and len(rows) > 0:
                    rows = rows[1:]  # 假设第一行是表头
            else:
                # 正常从tbody中获取行
                rows = tbody.find_all('tr')

            # 检查是否有行数据
            if not rows:
                return {"success": False, "message": f"未查询到 {keyword} 的备案信息"}

            # 处理每一行数据
            for row in rows:
                try:
                    cols = row.find_all('td')
                    # 确保有足够的列
                    if len(cols) >= 7:
                        # 提取每行数据，添加空值处理
                        company_name = cols[1].get_text(strip=True) if cols[1] else ""
                        company_type = cols[2].get_text(strip=True) if cols[2] else ""
                        icp_number = cols[3].get_text(strip=True) if cols[3] else ""
                        website_name = cols[4].get_text(strip=True) if cols[4] else ""
                        website_url = cols[5].get_text(strip=True) if cols[5] else ""
                        audit_date = cols[6].get_text(strip=True) if cols[6] else ""

                        # 解析IP和归属地
                        ip_address = ""
                        ip_location = ""

                        if website_url:
                            # 从URL中提取域名
                            domain_match = re.search(r'https?://([^/]+)', website_url)
                            if domain_match:
                                domain = domain_match.group(1)
                            else:
                                domain = website_url

                            # 解析IP地址
                            try:
                                ip_address = socket.gethostbyname(domain)

                                # 查询IP归属地
                                if ip_location_support:
                                    ip_location = ip_reader.get_addr_by_ip(ip_address)
                                else:
                                    ip_location = "IP归属地查询模块未安装"
                            except Exception as e:
                                ip_address = f"解析失败"
                                # ip_address = f"解析失败: {str(e)}"
                                ip_location = ""

                        results.append({
                            "序号": cols[0].get_text(strip=True) if cols[0] else "",
                            "主办单位名称": company_name,
                            "主办单位性质": company_type,
                            "网站备案号": icp_number,
                            "网站名称": website_name,
                            "网站首页地址": website_url,
                            "审核日期": audit_date,
                            "IP地址": ip_address,
                            "IP归属地": ip_location
                        })
                except Exception as e:
                    # 处理单行解析错误，不影响其他行
                    print(f"解析表格行时出错: {str(e)}")
                    continue

            if not results:
                return {"success": False, "message": f"未查询到 {keyword} 的备案信息"}

            return {
                "success": True,
                "data": {
                    "total": len(results),
                    "update_time": update_time,
                    "records": results
                }
            }

        except Exception as e:
            return {"success": False, "message": f"解析结果失败: {str(e)}"}


# 支持文件拖拽的文本编辑框
class DragDropTextEdit(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setPlaceholderText("请输入域名、公司名称或备案号（每行一个，支持批量查询）\n或直接拖拽文本文件到此处")

    def dragEnterEvent(self, event: QDragEnterEvent):
        # 检查拖入的是否是文件
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dropEvent(self, event: QDropEvent):
        # 处理拖入的文件
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()

            # 读取所有拖入的文件内容
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    try:
                        # 尝试以UTF-8编码读取文件
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        self.insertPlainText(content + "\n")
                    except UnicodeDecodeError:
                        # 尝试其他编码
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


# 多线程查询处理
class QueryWorker(QThread):
    update_signal = Signal(dict)
    finished_signal = Signal()

    def __init__(self, targets_with_type, api_selector, service_type="1"):
        super().__init__()
        self.targets_with_type = targets_with_type  # 包含类型的目标列表 [(target, type), ...]
        self.api_selector = api_selector  # 选择的API
        self.service_type = service_type  # 服务类型：网站、APP等
        self.running = True

    def run(self):
        for target, query_type in self.targets_with_type:
            if not self.running:
                break

            # 无论类型如何，都使用关键词查询
            result = ICPQueryAPI.query_by_keyword(target, self.service_type)

            # 添加查询目标和类型到结果中
            if result:
                result["target"] = target
                result["query_type"] = query_type
                self.update_signal.emit(result)

            # 避免请求过于频繁
            time.sleep(1)

        self.finished_signal.emit()

    def stop(self):
        self.running = False
        self.wait()


# 主窗口类
class ICPInquiryTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ICP备案信息查询工具")
        self.setGeometry(100, 100, 800, 600)
        self.results = []  # 存储查询结果

        self.init_ui()

    def init_ui(self):
        # 创建主部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 创建分割器
        splitter = QSplitter(Qt.Vertical)

        # 创建输入区域
        input_group = QGroupBox("查询输入")
        input_layout = QVBoxLayout()

        # 服务类型选择
        service_layout = QHBoxLayout()
        service_label = QLabel("查询类型:")
        self.service_selector = QComboBox()
        self.service_selector.addItems(["网站", "APP", "小程序", "快应用"])
        self.service_selector.setCurrentIndex(0)  # 默认选择网站

        service_layout.addWidget(service_label)
        service_layout.addWidget(self.service_selector)
        service_layout.addStretch()
        input_layout.addLayout(service_layout)


        # 输入区域（支持拖拽）
        self.query_input = DragDropTextEdit()
        self.query_input.setMinimumHeight(100)
        input_layout.addWidget(self.query_input)

        # 控制区域
        control_layout = QHBoxLayout()

        # API选择
        api_label = QLabel("查询接口:")
        self.api_selector = QComboBox()
        self.api_selector.addItems(["beianx接口"])

        # 按钮区域
        button_layout = QHBoxLayout()

        # 清空输入按钮
        self.btn_clear_input = QPushButton("\U0001F5D1 清空输入")
        self.btn_clear_input.clicked.connect(self.clear_input)
        # self.btn_clear_input.setStyleSheet("background-color: #f39c12; color: white; font-weight: bold;")

        # 清空所有按钮
        self.btn_clear_all = QPushButton("\U0001F5D1 清空所有")
        self.btn_clear_all.clicked.connect(self.clear_all)
        # self.btn_clear_all.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold;")

        # 查询按钮
        self.btn_query = QPushButton("🔍 开始查询")
        self.btn_query.clicked.connect(self.start_query)
        # self.btn_query.setStyleSheet("background-color: #3498db; color: white; font-weight: bold;")

        button_layout.addWidget(self.btn_query)
        button_layout.addWidget(self.btn_clear_input)
        button_layout.addWidget(self.btn_clear_all)
        button_layout.setSpacing(10)

        control_layout.addWidget(api_label)
        control_layout.addWidget(self.api_selector)
        control_layout.addStretch()
        control_layout.addLayout(button_layout)

        input_layout.addLayout(control_layout)

        input_group.setLayout(input_layout)
        splitter.addWidget(input_group)

        # 创建结果展示区域
        result_group = QGroupBox("查询结果")
        result_layout = QVBoxLayout()

        # 结果标签和清除按钮
        result_ctrl_layout = QHBoxLayout()
        self.result_count = QLabel("查询结果: 0 条")
        self.btn_clear_results = QPushButton("\U0001F5D1 清空结果")
        self.btn_clear_results.clicked.connect(self.clear_results)
        self.btn_export_excel = QPushButton("\U0001F4C1 导出为Excel")
        self.btn_export_excel.clicked.connect(lambda: self.export_results("excel"))
        self.btn_export_text = QPushButton("\U0001F4C4 导出为文本文件")
        self.btn_export_text.clicked.connect(lambda: self.export_results("text"))

        result_ctrl_layout.addWidget(self.result_count)
        result_ctrl_layout.addStretch()
        result_ctrl_layout.addWidget(self.btn_export_excel)
        result_ctrl_layout.addWidget(self.btn_export_text)
        result_ctrl_layout.addWidget(self.btn_clear_results)

        # 结果表格（增加IP相关列）
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(11)
        self.result_table.setHorizontalHeaderLabels([
            "查询类型", "查询目标", "序号", "主办单位名称",
            "主办单位性质", "网站备案号", "网站名称",
            "网站首页地址", "审核日期", "IP地址", "IP归属地"
        ])
        self.result_table.horizontalHeader().setStretchLastSection(True)
        # self.result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.result_table.setEditTriggers(QTableWidget.DoubleClicked)

        self.result_table.setSelectionBehavior(QTableWidget.SelectItems)
        self.result_table.setSelectionMode(QTableWidget.SingleSelection)
        self.result_table.setTextElideMode(Qt.ElideNone)

        # 添加分页控制器
        self.pagination_layout = QHBoxLayout()
        
        # 每页显示数量选择
        self.page_size_label = QLabel("每页显示:")
        self.page_size_combo = QComboBox()
        self.page_size_combo.addItems(["20", "50", "100","500"])
        self.page_size_combo.setCurrentText("20")
        self.page_size_combo.currentTextChanged.connect(self.on_page_size_changed)

        # 分页按钮
        self.first_page_btn = QPushButton("⏪ 首页")
        self.prev_page_btn = QPushButton("️◀️上一页")
        self.page_info_label = QLabel("第 0 页 / 共 0 页")
        self.next_page_btn = QPushButton("▶️下一页")
        self.last_page_btn = QPushButton("⏩ 末页")

        # 跳转控制
        self.jump_label = QLabel("跳转到:")
        self.jump_input = QLineEdit()
        self.jump_input.setMinimumWidth(120)
        self.jump_input.setMaximumWidth(120)
        self.jump_input.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.jump_btn = QPushButton("确定")
        self.jump_btn.clicked.connect(self.on_jump_clicked)

        # 添加到分页布局
        self.pagination_layout.addWidget(self.page_size_label)
        self.pagination_layout.addWidget(self.page_size_combo)
        # self.pagination_layout.addSpacing(20)
        self.pagination_layout.addWidget(self.first_page_btn)
        self.pagination_layout.addWidget(self.prev_page_btn)
        self.pagination_layout.addWidget(self.page_info_label)
        self.pagination_layout.addWidget(self.next_page_btn)
        self.pagination_layout.addWidget(self.last_page_btn)
        # self.pagination_layout.addSpacing(20)
        self.pagination_layout.addWidget(self.jump_label)
        self.pagination_layout.addWidget(self.jump_input)
        self.pagination_layout.addWidget(self.jump_btn)
        
        self.pagination_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pagination_layout.addStretch()

        # 绑定分页按钮事件
        self.first_page_btn.clicked.connect(self.first_page)
        self.prev_page_btn.clicked.connect(self.prev_page)
        self.next_page_btn.clicked.connect(self.next_page)
        self.last_page_btn.clicked.connect(self.last_page)

        # 导出按钮
        # export_layout = QHBoxLayout()
        # self.btn_export_excel = QPushButton("\U0001F4C1 导出为Excel")
        # self.btn_export_excel.clicked.connect(lambda: self.export_results("excel"))
        # self.btn_export_text = QPushButton("\U0001F4C4 导出为文本文件")
        # self.btn_export_text.clicked.connect(lambda: self.export_results("text"))
        # 
        # export_layout.addStretch()
        # export_layout.addWidget(self.btn_export_excel)
        # export_layout.addWidget(self.btn_export_text)
        # export_layout.setSpacing(10)

        # 添加到结果区域布局
        result_layout.addLayout(result_ctrl_layout)
        result_layout.addWidget(self.result_table)
        result_layout.addLayout(self.pagination_layout)
        # result_layout.addLayout(export_layout)
        
        result_group.setLayout(result_layout)
        splitter.addWidget(result_group)

        # 设置分割器初始大小
        splitter.setSizes([280, 520])

        main_layout.addWidget(splitter)

        # 状态条
        self.statusBar().showMessage("就绪")

        # 分页相关变量初始化
        self.current_page = 1
        self.page_size = 20
        self.total_pages = 0
        self.all_results = []  # 存储所有结果，用于分页显示

        # 初始化查询线程
        self.query_worker = None

    def detect_content_type(self, content):
        """
        自动识别内容类型
        返回 "domain" 表示域名，"company" 表示公司名称，"icp" 表示备案号
        """
        # 域名正则表达式（简化版）
        domain_pattern = re.compile(
            r'^(?=.{1,253}$)((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$'
        )

        # 备案号正则表达式
        icp_pattern = re.compile(r'^[^\u4e00-\u9fff]{2,5}ICP备\d{8,10}号(-\d+)?$')

        # 先检查是否符合备案号格式
        if icp_pattern.match(content):
            return "icp"

        # 检查是否符合域名格式
        if domain_pattern.match(content):
            return "domain"

        # 公司名称通常包含的关键词或主要是中文字符
        company_keywords = ["公司", "有限公司", "企业", "集团", "股份", "合伙"]
        if any(keyword in content for keyword in company_keywords) or \
                len([c for c in content if '\u4e00' <= c <= '\u9fff']) > len(content) * 0.5:
            return "company"

        # 无法确定时，作为通用关键词处理
        return "keyword"

    def extract_second_level_domain(self, domain):
        """提取二级域名（修复国内域名识别逻辑，如news.qq.com.cn -> qq.com.cn）"""
        try:
            # 移除可能的协议头（http://、https://）和端口号
            domain = re.sub(r'^https?://', '', domain)
            domain = re.sub(r':\d+$', '', domain)
            # 按点分割域名
            parts = domain.split('.')
            # 过滤空字符串（处理极端情况）
            parts = [p for p in parts if p]

            if len(parts) <= 2:
                # 本身已是二级或顶级域名（如qq.com、cn）
                return domain

            # 中国国内域名特殊处理：优先识别 "主体.行业.cn" 结构
            # 国内常见行业/机构后缀（不含.cn）
            china_industry_suffixes = {'com', 'net', 'org', 'gov', 'edu', 'ac', 'mil', 'int'}

            # 如果域名以.cn结尾，且倒数第二部分是国内行业后缀
            if parts[-1] == 'cn' and parts[-2] in china_industry_suffixes:
                # 取 主体.行业.cn（至少需要3个部分：主体+行业+cn）
                if len(parts) >= 3:
                    return '.'.join(parts[-3:])  # 如 [news, qq, com, cn] -> qq.com.cn

            # 处理其他特殊后缀（如.co.uk等国际特殊后缀）
            special_suffixes = {'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
                                'com.hk', 'net.hk', 'org.hk'}

            # 检查更长的特殊后缀（3部分）
            if len(parts) >= 3:
                last_three = '.'.join(parts[-3:])
                if last_three in special_suffixes:
                    return last_three

            # 检查2部分的特殊后缀
            last_two = '.'.join(parts[-2:])
            if last_two in special_suffixes:
                return last_two

            # 普通情况：取最后两部分
            return last_two

        except Exception as e:
            print(f"提取二级域名失败: {str(e)}")
            return domain

    def get_selected_api(self):
        """获取选中的API"""
        return "api1" if self.api_selector.currentIndex() == 0 else "api2"

    def get_service_type(self):
        """获取选中的服务类型对应的编码"""
        # 服务类型对应关系：网站-1, APP-6, 小程序-7, 快应用-8
        return str(self.service_selector.currentIndex() + 1) if self.service_selector.currentIndex() == 0 else \
            str(self.service_selector.currentIndex() + 5)

    def start_query(self):
        """开始查询过程，先清除原有结果"""
        # 清除之前的查询结果
        self.clear_results(confirm=False)

        # 获取输入内容
        input_text = self.query_input.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, "输入错误", "请输入至少一个域名、公司名称或备案号")
            return

        # 处理输入，获取目标列表
        targets = [line.strip() for line in input_text.splitlines() if line.strip()]
        if not targets:
            QMessageBox.warning(self, "输入错误", "请输入有效的域名、公司名称或备案号")
            return

        # 自动识别每个目标的类型，并处理域名（提取二级域名）
        targets_with_type = []
        for target in targets:
            content_type = self.detect_content_type(target)
            # 如果是域名，提取二级域名
            if content_type == "domain":
                processed_target = self.extract_second_level_domain(target)
                # 记录原始目标和处理后的目标（方便显示）
                targets_with_type.append((processed_target, content_type, target))
            else:
                # 非域名类型直接使用原目标
                targets_with_type.append((target, content_type, target))

        # 停止当前可能正在运行的查询
        if self.query_worker and self.query_worker.isRunning():
            self.query_worker.stop()

        api_selector = self.get_selected_api()
        service_type = self.get_service_type()

        # 创建并启动查询线程（注意传递处理后的目标）
        self.query_worker = QueryWorker(
            [(t[0], t[1]) for t in targets_with_type],  # 传递处理后的目标和类型
            api_selector,
            service_type
        )
        # 存储原始目标，用于显示
        self.original_targets = {t[0]: t[2] for t in targets_with_type}

        self.query_worker.update_signal.connect(self.handle_query_result)
        self.query_worker.finished_signal.connect(self.query_finished)

        # 显示进度对话框
        self.progress = QProgressDialog("正在查询...", "取消", 0, len(targets), self)
        self.progress.setWindowTitle("查询中")
        self.progress.setWindowModality(Qt.WindowModal)
        self.progress.canceled.connect(self.query_worker.stop)
        self.progress_value = 0

        self.statusBar().showMessage(f"正在查询 {len(targets)} 个目标...")
        self.btn_query.setEnabled(False)

        self.query_worker.start()

    def handle_query_result(self, result):
        """处理单个查询结果"""
        self.progress_value += 1
        self.progress.setValue(self.progress_value)

        if result["success"]:
            # 对于有多个记录的结果，每条记录都添加到表格
            if "records" in result["data"] and len(result["data"]["records"]) > 0:
                for record in result["data"]["records"]:
                    item = result.copy()
                    item["current_record"] = record
                    self.results.append(item)
                    self.add_result_to_table(item)
                    self.all_results.append(item)
            else:
                self.results.append(result)
                self.add_result_to_table(result)
                self.all_results.append(result)
        else:
            # 处理查询失败的情况
            self.results.append(result)
            self.add_result_to_table(result)
            self.all_results.append(result)
        # 更新当前页显示
        self.update_pagination()

    def update_pagination(self):
        """更新分页显示"""
        # 计算总页数
        self.total_pages = max(1, (len(self.all_results) + self.page_size - 1) // self.page_size)
        # 确保当前页不超过总页数
        self.current_page = min(self.current_page, self.total_pages)
        # 更新表格显示
        self.show_current_page()
        # 更新分页信息
        self.update_pagination_controls()

    def show_current_page(self):
        """显示当前页的内容"""
        # 清空当前表格
        self.result_table.setRowCount(0)

        # 计算当前页的记录范围
        start = (self.current_page - 1) * self.page_size
        end = min(start + self.page_size, len(self.all_results))

        # 添加当前页的记录
        for i in range(start, end):
            result = self.all_results[i]
            row = self.result_table.rowCount()
            self.result_table.insertRow(row)

            # 处理查询类型
            type_mapping = {
                "domain": "域名",
                "company": "公司名称",
                "icp": "备案号",
                "keyword": "关键词"
            }
            query_type = type_mapping.get(result["query_type"], "未知")
            self.result_table.setItem(row, 0, QTableWidgetItem(query_type))

            # 处理查询目标（显示原始输入）
            original_target = self.original_targets.get(result["target"], result["target"])
            self.result_table.setItem(row, 1, QTableWidgetItem(original_target))

            # 处理其他字段
            if result["success"] and "current_record" in result:
                record = result["current_record"]
                self.result_table.setItem(row, 2, QTableWidgetItem(record.get("序号", "")))
                self.result_table.setItem(row, 3, QTableWidgetItem(record.get("主办单位名称", "")))
                self.result_table.setItem(row, 4, QTableWidgetItem(record.get("主办单位性质", "")))
                self.result_table.setItem(row, 5, QTableWidgetItem(record.get("网站备案号", "")))
                self.result_table.setItem(row, 6, QTableWidgetItem(record.get("网站名称", "")))
                self.result_table.setItem(row, 7, QTableWidgetItem(record.get("网站首页地址", "")))
                self.result_table.setItem(row, 8, QTableWidgetItem(record.get("审核日期", "")))
                self.result_table.setItem(row, 9, QTableWidgetItem(record.get("IP地址", "")))
                self.result_table.setItem(row, 10, QTableWidgetItem(record.get("IP归属地", "")))
            else:
                for col in range(2, 11):
                    self.result_table.setItem(row, col, QTableWidgetItem(""))
                error_item = QTableWidgetItem(result.get("message", "查询失败"))
                error_item.setForeground(QColor("red"))
                self.result_table.setItem(row, 5, error_item)

        # 自动调整列宽
        self.result_table.resizeColumnsToContents()
        # 更新结果计数
        self.result_count.setText(f"查询结果: {len(self.all_results)} 条")

    def update_pagination_controls(self):
        """更新分页控制器状态"""
        # 更新页码信息
        self.page_info_label.setText(f"第 {self.current_page} 页 / 共 {self.total_pages} 页")

        # 更新按钮状态（是否可用）
        self.first_page_btn.setEnabled(self.current_page > 1)
        self.prev_page_btn.setEnabled(self.current_page > 1)
        self.next_page_btn.setEnabled(self.current_page < self.total_pages)
        self.last_page_btn.setEnabled(self.current_page < self.total_pages)

        # 更新跳转输入框
        self.jump_input.setText(str(self.current_page))

    # 分页控制方法
    def first_page(self):
        """跳转到首页"""
        if self.current_page != 1:
            self.current_page = 1
            self.show_current_page()
            self.update_pagination_controls()

    def prev_page(self):
        """跳转到上一页"""
        if self.current_page > 1:
            self.current_page -= 1
            self.show_current_page()
            self.update_pagination_controls()

    def next_page(self):
        """跳转到下一页"""
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.show_current_page()
            self.update_pagination_controls()

    def last_page(self):
        """跳转到末页"""
        if self.current_page != self.total_pages:
            self.current_page = self.total_pages
            self.show_current_page()
            self.update_pagination_controls()

    def on_page_size_changed(self, text):
        """处理每页显示数量变更"""
        try:
            new_size = int(text)
            if new_size != self.page_size:
                self.page_size = new_size
                self.current_page = 1  # 重置到第一页
                self.update_pagination()
        except ValueError:
            pass

    def on_jump_clicked(self):
        """处理跳转到指定页"""
        try:
            page = int(self.jump_input.text())
            if 1 <= page <= self.total_pages:
                self.current_page = page
                self.show_current_page()
                self.update_pagination_controls()
            else:
                QMessageBox.warning(self, "输入错误", f"请输入1到{self.total_pages}之间的页码")
                self.jump_input.setText(str(self.current_page))
        except ValueError:
            QMessageBox.warning(self, "输入错误", "请输入有效的页码")
            self.jump_input.setText(str(self.current_page))
    
    def add_result_to_table(self, result):
        """将结果添加到表格，包含IP解析信息"""
        row = self.result_table.rowCount()
        self.result_table.insertRow(row)

        # 查询类型
        type_mapping = {
            "domain": "域名",
            "company": "公司名称",
            "icp": "备案号",
            "keyword": "关键词"
        }
        query_type = type_mapping.get(result["query_type"], "未知")
        self.result_table.setItem(row, 0, QTableWidgetItem(query_type))

        # 查询目标：如果是域名，显示原始输入；否则显示处理后的目标
        original_target = self.original_targets.get(result["target"], result["target"])
        self.result_table.setItem(row, 1, QTableWidgetItem(original_target))

        if result["success"] and "current_record" in result:
            record = result["current_record"]
            # 序号
            self.result_table.setItem(row, 2, QTableWidgetItem(record.get("序号", "")))

            # 主办单位名称
            self.result_table.setItem(row, 3, QTableWidgetItem(record.get("主办单位名称", "")))

            # 主办单位性质
            self.result_table.setItem(row, 4, QTableWidgetItem(record.get("主办单位性质", "")))

            # 网站备案号
            self.result_table.setItem(row, 5, QTableWidgetItem(record.get("网站备案号", "")))

            # 网站名称
            self.result_table.setItem(row, 6, QTableWidgetItem(record.get("网站名称", "")))

            # 网站首页地址
            self.result_table.setItem(row, 7, QTableWidgetItem(record.get("网站首页地址", "")))

            # 审核日期
            self.result_table.setItem(row, 8, QTableWidgetItem(record.get("审核日期", "")))

            # IP地址
            self.result_table.setItem(row, 9, QTableWidgetItem(record.get("IP地址", "")))

            # IP归属地
            self.result_table.setItem(row, 10, QTableWidgetItem(record.get("IP归属地", "")))
        else:
            # 失败的结果
            for col in range(2, 11):
                self.result_table.setItem(row, col, QTableWidgetItem(""))

            # 在备案号列显示错误信息
            error_item = QTableWidgetItem(result.get("message", "查询失败"))
            error_item.setForeground(QColor("red"))
            self.result_table.setItem(row, 5, error_item)

        # 更新结果计数
        self.result_count.setText(f"查询结果: {len(self.results)} 条")

        # 自动调整列宽
        self.result_table.resizeColumnsToContents()

    def query_finished(self):
        """查询完成后的处理"""
        self.statusBar().showMessage(f"查询完成，共 {len(self.results)} 条结果")
        self.btn_query.setEnabled(True)
        self.update_pagination()  # 确保分页信息正确更新

        if hasattr(self, 'progress'):
            self.progress.close()

    def clear_results(self, confirm=True):
        """清空查询结果，confirm参数控制是否需要确认"""
        if confirm and not self.results:
            return  # 如果没有结果，直接返回

        if not confirm or (confirm and self.results):
            # 如果不需要确认，或者需要确认且有结果
            if not confirm or QMessageBox.question(
                    self, "确认", "确定要清空所有查询结果吗？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            ) == QMessageBox.Yes:
                self.result_table.setRowCount(0)
                self.all_results = []
                self.results = []  # 保持与原有代码兼容
                self.result_count.setText("查询结果: 0 条")
                self.statusBar().showMessage("已清空查询结果")

    def clear_input(self):
        """清空输入区域"""
        if self.query_input.toPlainText().strip():
            if QMessageBox.question(
                    self, "确认", "确定要清空输入内容吗？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            ) == QMessageBox.Yes:
                self.query_input.clear()
                self.statusBar().showMessage("已清空输入内容")

    def clear_all(self):
        """清空所有数据（输入和结果）"""
        if self.query_input.toPlainText().strip() or self.results:
            if QMessageBox.question(
                    self, "确认", "确定要清空所有输入和查询结果吗？",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            ) == QMessageBox.Yes:
                self.query_input.clear()
                self.result_table.setRowCount(0)
                self.results = []
                self.result_count.setText("查询结果: 0 条")
                self.statusBar().showMessage("已清空所有数据")

    def export_results(self, export_type):
        """导出查询结果，包含IP解析信息"""
        if not self.results:
            QMessageBox.information(self, "提示", "没有可导出的查询结果")
            return

        # 获取保存路径
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"备案查询结果_{current_time}"

        if export_type == "excel":
            file_path, _ = QFileDialog.getSaveFileName(
                self, "导出为Excel", default_filename, "Excel文件 (*.xlsx);;所有文件 (*)"
            )
            if file_path:
                if not file_path.endswith(".xlsx"):
                    file_path += ".xlsx"
                self.export_to_excel(file_path)
        else:  # text
            file_path, _ = QFileDialog.getSaveFileName(
                self, "导出为文本文件", default_filename, "文本文件 (*.txt);;CSV文件 (*.csv);;所有文件 (*)"
            )
            if file_path:
                if file_path.endswith(".csv"):
                    self.export_to_csv(file_path)
                else:
                    if not file_path.endswith(".txt"):
                        file_path += ".txt"
                    self.export_to_text(file_path)

    def export_to_excel(self, file_path):
        """导出结果到Excel文件，包含IP解析信息"""
        try:
            # 尝试导入pandas，如果没有安装则提示
            import pandas as pd

            data = []
            for result in self.results:
                type_mapping = {
                    "domain": "域名",
                    "company": "公司名称",
                    "icp": "备案号",
                    "keyword": "关键词"
                }
                query_type = type_mapping.get(result["query_type"], "未知")

                if result["success"] and "current_record" in result:
                    record = result["current_record"]
                    data.append({
                        # "查询类型": query_type,
                        "序号": record.get("序号", ""),
                        "查询目标": result["target"],
                        "主办单位名称": record.get("主办单位名称", ""),
                        "主办单位性质": record.get("主办单位性质", ""),
                        "网站备案号": record.get("网站备案号", ""),
                        "网站名称": record.get("网站名称", ""),
                        "网站首页地址": record.get("网站首页地址", ""),
                        "审核日期": record.get("审核日期", ""),
                        "IP地址": record.get("IP地址", ""),
                        "IP归属地": record.get("IP归属地", "")
                    })
                else:
                    data.append({
                        # "查询类型": query_type,
                        "序号": "",
                        "查询目标": result["target"],
                        "主办单位名称": "",
                        "主办单位性质": "",
                        "网站备案号": result.get("message", "查询失败"),
                        "网站名称": "",
                        "网站首页地址": "",
                        "审核日期": "",
                        "IP地址": "",
                        "IP归属地": ""
                    })

            df = pd.DataFrame(data)
            df.to_excel(file_path, index=False)
            QMessageBox.information(self, "成功", f"已成功导出 {len(data)} 条结果到 {file_path}")
            self.statusBar().showMessage(f"已导出结果到 {file_path}")

        except ImportError:
            QMessageBox.warning(self, "依赖缺失",
                                "导出Excel需要安装pandas和openpyxl库\n请使用命令: pip install pandas openpyxl")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出Excel时发生错误: {str(e)}")

    def export_to_text(self, file_path):
        """导出结果到文本文件，包含IP解析信息"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(f"备案信息查询结果 - 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 150 + "\n")

                type_mapping = {
                    "domain": "域名",
                    "company": "公司名称",
                    "icp": "备案号",
                    "keyword": "关键词"
                }

                for i, result in enumerate(self.results, 1):
                    query_type = type_mapping.get(result["query_type"], "未知")
                    f.write(f"[{i}] 查询类型: {query_type}, 查询目标: {result['target']}\n")

                    if result["success"] and "current_record" in result:
                        record = result["current_record"]
                        f.write(f"   序号: {record.get('序号', '')}\n")
                        f.write(f"   主办单位名称: {record.get('主办单位名称', '')}\n")
                        f.write(f"   主办单位性质: {record.get('主办单位性质', '')}\n")
                        f.write(f"   网站备案号: {record.get('网站备案号', '')}\n")
                        f.write(f"   网站名称: {record.get('网站名称', '')}\n")
                        f.write(f"   网站首页地址: {record.get('网站首页地址', '')}\n")
                        f.write(f"   审核日期: {record.get('审核日期', '')}\n")
                        f.write(f"   IP地址: {record.get('IP地址', '')}\n")
                        f.write(f"   IP归属地: {record.get('IP归属地', '')}\n")
                    else:
                        f.write(f"   状态: {result.get('message', '查询失败')}\n")

                    f.write("-" * 150 + "\n")

            QMessageBox.information(self, "成功", f"已成功导出 {len(self.results)} 条结果到 {file_path}")
            self.statusBar().showMessage(f"已导出结果到 {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出文本文件时发生错误: {str(e)}")

    def export_to_csv(self, file_path):
        """导出结果到CSV文件，包含IP解析信息"""
        try:
            with open(file_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                # 写入表头
                writer.writerow([
                    "序号", "查询类型", "查询目标", "记录序号",
                    "主办单位名称", "主办单位性质", "网站备案号",
                    "网站名称", "网站首页地址", "审核日期",
                    "IP地址", "IP归属地"
                ])

                type_mapping = {
                    "domain": "域名",
                    "company": "公司名称",
                    "icp": "备案号",
                    "keyword": "关键词"
                }

                for i, result in enumerate(self.results, 1):
                    query_type = type_mapping.get(result["query_type"], "未知")

                    if result["success"] and "current_record" in result:
                        record = result["current_record"]
                        writer.writerow([
                            i,
                            query_type,
                            result["target"],
                            record.get("序号", ""),
                            record.get("主办单位名称", ""),
                            record.get("主办单位性质", ""),
                            record.get("网站备案号", ""),
                            record.get("网站名称", ""),
                            record.get("网站首页地址", ""),
                            record.get("审核日期", ""),
                            record.get("IP地址", ""),
                            record.get("IP归属地", "")
                        ])
                    else:
                        writer.writerow([
                            i,
                            query_type,
                            result["target"],
                            "", "", "",
                            result.get("message", "查询失败"),
                            "", "", "", "", ""
                        ])

            QMessageBox.information(self, "成功", f"已成功导出 {len(self.results)} 条结果到 {file_path}")
            self.statusBar().showMessage(f"已导出结果到 {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"导出CSV文件时发生错误: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = ICPInquiryTool()
    window.show()
    sys.exit(app.exec())
