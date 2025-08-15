import sys
import re
from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                               QWidget, QPushButton, QTableWidget, QTableWidgetItem,
                               QHeaderView, QMessageBox, QMenu, QLabel, QProgressBar,
                               QTextEdit, QGroupBox)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont, QIcon


class AntivirusDetector(QThread):
    """杀软检测线程"""
    progress_updated = Signal(int)
    result_ready = Signal(list)
    finished = Signal()

    def __init__(self, tasklist_data):
        super().__init__()
        self.tasklist_data = tasklist_data

    def run(self):
        try:
            results = self.parse_tasklist(self.tasklist_data)
            self.result_ready.emit(results)
        except Exception as e:
            self.result_ready.emit([])
        finally:
            self.finished.emit()

    def parse_tasklist(self, data):
        """解析tasklist输出并识别杀软"""
        results = []
        lines = data.strip().split('\n')

        # 杀软进程特征库
        antivirus_patterns = {
            # 360安全卫士
            r'360sd\.exe': '360杀毒',
            r'360tray\.exe': '360安全卫士',
            r'360safe\.exe': '360安全卫士',
            r'zhudongfangyu\.exe': '360主动防御',

            # 腾讯电脑管家
            r'qqpctray\.exe': '腾讯电脑管家',
            r'qqpcrtp\.exe': '腾讯电脑管家',
            r'qqpcmgr\.exe': '腾讯电脑管家',
            r'qqpcsoftmgr\.exe': '腾讯电脑管家',
            # 腾讯电脑管家
            r'TrustedInstaller\.exe': '腾讯电脑管家',  # 注意：此进程名也可能关联到Windows系统组件，请根据实际情况判断
            r'QQPCRTP\.exe': '腾讯电脑管家',

            # 金山毒霸
            r'kxescore\.exe': '金山毒霸',
            r'kxetray\.exe': '金山毒霸',
            r'kavsvc\.exe': '金山毒霸',
            r'KSafeSvc\.exe': '金山毒霸',

            # 瑞星
            r'rav\.exe': '瑞星杀毒',
            r'ravmond\.exe': '瑞星杀毒',
            r'ravstub\.exe': '瑞星杀毒',

            # 卡巴斯基
            r'avp\.exe': '卡巴斯基',
            r'avpui\.exe': '卡巴斯基',
            r'kav\.exe': '卡巴斯基',
            r'kavfsck\.exe': '卡巴斯基安全软件',
            r'kavshell\.exe': '卡巴斯基安全软件',

            # 诺顿
            r'ccsvchst\.exe': '诺顿',
            r'nav\.exe': '诺顿',
            r'nsm\.exe': '诺顿',
            r'nissrv\.exe': '诺顿网络安全服务',
            r'nortonsecurity\.exe': '诺顿安全',
            r'n360\.exe': '诺顿360',
            r'navw32\.exe': '诺顿杀毒软件',


            # 迈克菲
            r'mcshield\.exe': '迈克菲',
            r'mcafee\.exe': '迈克菲',
            r'frameworkservice\.exe': '迈克菲',
            r'vsrt\w+\.exe': 'McAfee 病毒扫描',

            # 赛门铁克
            r'symantec\.exe': '赛门铁克',
            r'rtvscan\.exe': '赛门铁克',

            # 小红伞
            r'avguard\.exe': '小红伞',
            r'avcenter\.exe': '小红伞',
            r'avconfig\.exe': '小红伞',

            # 比特梵德
            r'bdagent\.exe': '比特梵德',
            r'bdredline\.exe': '比特梵德',
            r'bdss\.exe': '比特梵德',

            # 趋势科技
            r'tmproxy\.exe': '趋势科技',
            r'tmntsrv\.exe': '趋势科技',
            r'tmcc\.exe': '趋势科技',

            # 微软Defender
            r'msmpeng\.exe': 'Windows Defender',
            r'msseces\.exe': 'Windows Defender',
            r'windefend\.exe': 'Windows Defender',
            r'configsecuritypolicy\.exe': 'Windows Defender 安全策略配置',
            r'discoveryservice\.exe': 'Windows Defender 发现服务',
            r'ekrn\.exe': 'Windows Defender 网络检查服务',  # 企业版相关
            r'fhsvc\.exe': 'Windows 防御性备份服务',
            r'identityservice\.exe': 'Windows Defender 身份服务',
            r'mpssvc\.exe': 'Windows Defender 防火墙服务',
            r'mpcmdrun\.exe': 'Windows Defender 命令行工具',
            r'mpenginedb\.exe': 'Windows Defender 引擎数据库',
            r'mpui\.exe': 'Windows Defender 用户界面',
            r'netsh\.exe': 'Windows 防火墙配置工具',  # 与 Defender 防火墙相关
            r'secHealthUI\.exe': 'Windows 安全中心界面',  # Defender 前端界面
            r'svchost\.exe -k secsvcs': 'Windows Defender 相关服务宿主',  # 服务进程
            r'wscsvc\.exe': 'Windows 安全中心服务',  # 管理 Defender 等安全软件状态
            r'wuauclt\.exe': 'Windows 更新客户端',  # 与 Defender 病毒库更新相关

            # 火绒
            r'hipsdaemon\.exe': '火绒安全',
            r'hipsmain\.exe': '火绒安全',
            r'hrconfig\.exe': '火绒安全',
            r'firewall\.exe': '火绒安全软件',
            r'hips\.exe': '火绒主机入侵防御',
            r'qrmon\.exe': '火绒实时监控',

            # 奇安信（原360企业安全）
            r'qianxinav\.exe': '奇安信杀毒主程序',
            r'qxdefender\.exe': '奇安信终端安全',
            r'qxdp\.exe': '奇安信数据防护',
            r'qxtray\.exe': '奇安信托盘程序',
            r'qxsafemon\.exe': '奇安信实时监控',
            r'edrserver\.exe': '奇安信EDR组件',

            # 亚信安全
            r'axengine\.exe': '亚信安全引擎',
            r'axtray\.exe': '亚信安全托盘程序',
            r'axupdate\.exe': '亚信安全更新程序',
            r'axshield\.exe': '亚信安全防护进程',
            r'axconsole\.exe': '亚信安全控制台',
            r'NTRtScan\.exe': '亚信安全深度威胁发现设备',
            r'TmCCSvc\.exe': '亚信安全云安全智能防护平台',

            # 北信源
            r'vrvscan\.exe': '北信源杀毒程序',
            r'vrvtray\.exe': '北信源托盘程序',
            r'vrvcenter\.exe': '北信源控制中心',
            r'vrvupdate\.exe': '北信源更新服务',
            r'vrvfirewall\.exe': '北信源防火墙组件',
            r'vrvprotect\.exe': '北信源实时防护',

            # 其他国内安全厂商补充
            r'kingsoftantivirus\.exe': '金山毒霸（企业版）',
            r'jiangminkv\.exe': '江民杀毒（企业版）',
            r'risingav\.exe': '瑞星企业版杀毒程序',

            # 其他常见杀软
            r'eset\.exe': 'ESET',
            r'egui\.exe': 'ESET',
            r'avast\.exe': 'Avast',
            r'avastui\.exe': 'Avast',
            r'avastsvc\.exe': 'Avast',
            r'avira\.exe': 'Avira',
            r'QaxEngManager\.exe': 'QAX 天擎',
            r'nod32\.exe': 'ESET NOD32',
            r'TQClient\.exe': 'QAX 天擎',
            r'TQDefender\.exe': 'QAX 天擎',
            r'kvmonxp\.exe': '江民杀毒软件',
            r'kvcenter\.exe': '江民控制中心',
            r'360skylar64\.exe': '奇安信天擎',
            r'QAXTray\.exe': '奇安信安全防护',
            r'QAVPFCore\.exe': '奇安信防病毒系统',
            r'SecCenter\.exe': '天融信安全审计系统',
            r'TopFilter\.exe': '天融信网络卫士',
            r'NSFOCUSIDS\.exe': '绿盟科技入侵检测系统',
            r'NSFOCUSIPS\.exe': '绿盟科技入侵防御系统',
            r'SangforACAgent\.exe': '深信服上网行为管理客户端',
            r'SangforEndpoint\.exe': '深信服终端安全管理系统',
            r'edr_agent\.exe': '深信服EDR',
            r'EdrTray\.exe': '深信服EDR',
            r'seclog_cli\.exe': '深信服日志采集客户端',
            r'SangforUpdate\.exe': '深信服终端安全更新模块',
        }

        for i, line in enumerate(lines):
            # 跳过标题行和空行
            if i == 0 or not line.strip():
                continue

            # 解析进程信息
            parts = line.split()
            if len(parts) >= 2:
                process_name = parts[0]
                process_id = parts[1]

                # 检查是否为杀软进程
                antivirus_name = "未知"
                for pattern, av_name in antivirus_patterns.items():
                    if re.search(pattern, process_name, re.IGNORECASE):
                        antivirus_name = av_name
                        break

                # 只添加识别到的杀软进程
                if antivirus_name != "未知":
                    results.append({
                        'process_name': process_name,
                        'process_id': process_id,
                        'antivirus_name': antivirus_name
                    })

                # 更新进度
                progress = int((i + 1) / len(lines) * 100)
                self.progress_updated.emit(progress)

        return results


class AntivirusDetectorTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.worker = None
        self.results = []

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("Windows杀软查询工具")
        self.setGeometry(100, 100, 800, 600)

        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        layout = QVBoxLayout(central_widget)

        # 输入区域GroupBox
        input_group = QGroupBox("输入区域")
        input_layout = QVBoxLayout(input_group)

        # 输入区域标题
        input_title = QLabel("输入tasklist /svc结果")
        input_layout.addWidget(input_title)

        # 输入框
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText(
            "请粘贴tasklist /svc命令的输出结果...\n\n示例格式:\nImage Name                     PID Services\n========================= ======== ==========================================\nSystem Idle Process              0 N/A\nSystem                           4 N/A")
        input_layout.addWidget(self.input_edit)

        # 功能按钮区域
        button_layout = QHBoxLayout()

        # 检测按钮
        self.detect_btn = QPushButton("🔍 检测杀软")
        self.detect_btn.clicked.connect(self.start_detection)
        button_layout.addWidget(self.detect_btn)

        # 清空按钮
        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(self.clear_btn)

        # 导出按钮
        self.export_btn = QPushButton("💾 导出结果")
        self.export_btn.clicked.connect(self.export_results)
        button_layout.addWidget(self.export_btn)

        # 复制按钮
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.setIcon(QIcon.fromTheme("document-new"))
        self.copy_btn.clicked.connect(self.copy_results)
        button_layout.addWidget(self.copy_btn)

        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # button_layout.addStretch()
        input_layout.addLayout(button_layout)

        layout.addWidget(input_group)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 输出区域GroupBox
        output_group = QGroupBox("检测结果")
        output_layout = QVBoxLayout(output_group)

        # 结果统计
        self.result_label = QLabel("检测结果: 0 个杀软进程")
        output_layout.addWidget(self.result_label)

        # 表格
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["进程名称", "进程ID", "杀软名称"])

        # 设置表格样式
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

        self.table.setColumnWidth(1, 150)

        # 启用右键菜单
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

        output_layout.addWidget(self.table)
        layout.addWidget(output_group)

        # 状态栏
        self.statusBar().showMessage("就绪")

    def start_detection(self):
        """开始检测"""
        input_text = self.input_edit.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, "警告", "请输入tasklist /svc的输出信息")
            return

        # 禁用按钮
        self.detect_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        # 创建并启动检测线程
        self.worker = AntivirusDetector(input_text)
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.result_ready.connect(self.handle_results)
        self.worker.finished.connect(self.detection_finished)
        self.worker.start()

        self.statusBar().showMessage("正在检测杀软进程...")

    def update_progress(self, value):
        """更新进度条"""
        self.progress_bar.setValue(value)

    def handle_results(self, results):
        """处理检测结果"""
        self.results = results
        self.populate_table()
        self.update_result_label()

    def detection_finished(self):
        """检测完成"""
        self.detect_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage(f"检测完成，发现 {len(self.results)} 个杀软进程")

    def populate_table(self):
        """填充表格数据"""
        self.table.setRowCount(len(self.results))

        for i, result in enumerate(self.results):
            # 进程名称
            process_name_item = QTableWidgetItem(result['process_name'])
            self.table.setItem(i, 0, process_name_item)

            # 进程ID
            process_id_item = QTableWidgetItem(result['process_id'])
            process_id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(i, 1, process_id_item)

            # 杀软名称
            antivirus_item = QTableWidgetItem(result['antivirus_name'])
            self.table.setItem(i, 2, antivirus_item)

    def update_result_label(self):
        """更新结果统计标签"""
        self.result_label.setText(f"检测结果: {len(self.results)} 个杀软进程")

    def clear_all(self):
        """清空所有内容"""
        self.input_edit.clear()
        self.table.setRowCount(0)
        self.results = []
        self.update_result_label()
        self.statusBar().showMessage("已清空")

    def export_results(self):
        """导出结果"""
        if not self.results:
            QMessageBox.warning(self, "警告", "没有结果可导出")
            return

        try:
            import pandas as pd
            from datetime import datetime

            # 创建DataFrame
            df = pd.DataFrame(self.results)
            df.columns = ['进程名称', '进程ID', '杀软名称']

            # 生成文件名
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"杀软检测结果_{timestamp}.xlsx"

            # 导出
            df.to_excel(filename, index=False, engine='openpyxl')

            QMessageBox.information(self, "成功", f"结果已导出到 {filename}")
            self.statusBar().showMessage(f"已导出到 {filename}")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")

    def copy_results(self):
        """复制结果"""
        if not self.results:
            QMessageBox.warning(self, "警告", "没有结果可复制")
            return

        try:
            # 构建复制文本
            text_lines = ["进程名称\t进程ID\t杀软名称"]
            for result in self.results:
                line = f"{result['process_name']}\t{result['process_id']}\t{result['antivirus_name']}"
                text_lines.append(line)

            text = '\n'.join(text_lines)

            # 复制到剪贴板
            clipboard = QApplication.clipboard()
            clipboard.setText(text)

            QMessageBox.information(self, "成功", "结果已复制到剪贴板")
            self.statusBar().showMessage("结果已复制到剪贴板")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"复制失败: {str(e)}")

    def show_context_menu(self, position):
        """显示右键菜单"""
        menu = QMenu()

        # 复制选中行
        copy_action = QAction("复制选中行", self)
        copy_action.triggered.connect(self.copy_selected_rows)
        menu.addAction(copy_action)

        # 复制全部
        copy_all_action = QAction("复制全部", self)
        copy_all_action.triggered.connect(self.copy_results)
        menu.addAction(copy_all_action)

        menu.addSeparator()

        # 清空
        clear_action = QAction("清空", self)
        clear_action.triggered.connect(self.clear_all)
        menu.addAction(clear_action)

        menu.exec(self.table.mapToGlobal(position))

    def copy_selected_rows(self):
        """复制选中的行"""
        selected_rows = set(item.row() for item in self.table.selectedItems())

        if not selected_rows:
            QMessageBox.warning(self, "警告", "请先选择要复制的行")
            return

        try:
            # 构建复制文本
            text_lines = ["进程名称\t进程ID\t杀软名称"]
            for row in sorted(selected_rows):
                if row < len(self.results):
                    result = self.results[row]
                    line = f"{result['process_name']}\t{result['process_id']}\t{result['antivirus_name']}"
                    text_lines.append(line)

            text = '\n'.join(text_lines)

            # 复制到剪贴板
            clipboard = QApplication.clipboard()
            clipboard.setText(text)

            QMessageBox.information(self, "成功", f"已复制 {len(selected_rows)} 行结果到剪贴板")
            self.statusBar().showMessage(f"已复制 {len(selected_rows)} 行结果")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"复制失败: {str(e)}")


def main():
    app = QApplication(sys.argv)

    # 设置应用程序样式
    app.setStyle('Fusion')

    # 创建主窗口
    window = AntivirusDetectorTool()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()