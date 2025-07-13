import sys
import cv2
import numpy as np
import qrcode
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QTextEdit, QFileDialog,
    QColorDialog, QSplitter, QApplication, QMessageBox,
    QFrame, QSizePolicy, QMainWindow
)
from PySide6.QtGui import (
    QColor, QPixmap, QImage, QPainter, QPen, QBrush, QIcon,
    QCursor, QScreen
)
from PySide6.QtCore import Qt, QSize, QPoint, QRect, QTimer

from pyzbar.pyzbar import decode
from PIL import Image
import io


class ColorDisplay(QWidget):
    """颜色显示组件，带颜色块和十六进制值显示"""

    def __init__(self, initial_color, parent=None):
        super().__init__(parent)
        self.color = initial_color

        # 布局设置
        layout = QHBoxLayout(self)
        layout.setSpacing(5)
        layout.setContentsMargins(0, 0, 0, 0)

        # 颜色块
        self.color_block = QFrame()
        self.color_block.setFixedSize(24, 24)
        self.color_block.setStyleSheet(f"background-color: {self.color.name()}; border: 1px solid #aaa;")
        layout.addWidget(self.color_block)

        # 颜色值显示
        self.color_label = QLabel(self.color.name())
        self.color_label.setStyleSheet("font-size: 12px;")
        layout.addWidget(self.color_label)

    def set_color(self, color):
        self.color = color
        self.color_block.setStyleSheet(f"background-color: {self.color.name()}; border: 1px solid #aaa;")
        self.color_label.setText(self.color.name())

    def get_color(self):
        return self.color


class ScreenCaptureWidget(QWidget):
    """全屏截图选区组件"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
        self.setWindowState(Qt.WindowFullScreen)
        self.setStyleSheet("background-color: rgba(0, 0, 0, 100);")

        # 保存当前屏幕截图
        self.screenshot = QApplication.primaryScreen().grabWindow(0)

        # 选区相关变量
        self.begin = QPoint()
        self.end = QPoint()
        self.is_drawing = False

        # 显示截图作为背景
        self.show()

    def paintEvent(self, event):
        # 绘制全屏半透明遮罩
        painter = QPainter(self)
        painter.drawPixmap(0, 0, self.screenshot)

        # 绘制选区矩形
        if not self.begin.isNull() and not self.end.isNull():
            rect = QRect(self.begin, self.end).normalized()

            # 绘制选区外的半透明遮罩
            painter.setBrush(QBrush(QColor(0, 0, 0, 150)))
            painter.setPen(Qt.NoPen)

            # 上部分
            painter.drawRect(0, 0, self.width(), rect.top())
            # 左部分
            painter.drawRect(0, rect.top(), rect.left(), rect.height())
            # 右部分
            painter.drawRect(rect.right(), rect.top(), self.width() - rect.right(), rect.height())
            # 下部分
            painter.drawRect(0, rect.bottom(), self.width(), self.height() - rect.bottom())

            # 绘制选区边框
            painter.setPen(QPen(Qt.red, 2))
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(rect)

            # 绘制选区尺寸提示
            width = rect.width()
            height = rect.height()
            painter.setPen(QPen(Qt.white, 1))
            painter.setBrush(QBrush(QColor(0, 0, 0, 180)))
            painter.drawRect(rect.left(), rect.top() - 20, 100, 20)
            painter.drawText(rect.left() + 5, rect.top() - 5, f"{width} x {height}")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.begin = event.pos()
            self.end = event.pos()
            self.is_drawing = True
            self.update()

    def mouseMoveEvent(self, event):
        if self.is_drawing:
            self.end = event.pos()
            self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.is_drawing:
            self.end = event.pos()
            self.is_drawing = False

            # 获取选区
            rect = QRect(self.begin, self.end).normalized()

            # 确保选区有效
            if rect.width() > 10 and rect.height() > 10:
                # 裁剪选区图像
                cropped = self.screenshot.copy(rect)

                # 转换为 PIL 图像
                buffer = io.BytesIO()
                cropped.save(buffer, "PNG")
                buffer.seek(0)
                pil_img = Image.open(buffer).convert("RGB")

                # 返回选区图像
                self.parent().process_screen_capture(pil_img)

            # 关闭截图窗口
            self.close()


class QRCodeTool(QMainWindow):
    """主窗口"""

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # 中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局（垂直，包含 分割布局 + 功能按钮布局 ）
        main_layout = QVBoxLayout(central_widget)

        # 分割布局：左侧输入区域、右侧输出区域
        splitter = QSplitter(Qt.Horizontal)
        splitter.setSizes([350, 500])  # 调整右侧区域更宽

        # 左侧输入区域布局
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setSpacing(15)

        # 内容输入
        self.content_label = QLabel("内容:")
        self.content_edit = QTextEdit()
        self.content_edit.setPlaceholderText("请输入要生成二维码的内容")
        self.content_edit.setMinimumHeight(100)

        # 颜色配置区域
        color_frame = QFrame()
        color_frame.setFrameShape(QFrame.StyledPanel)
        color_frame.setStyleSheet("background-color: #f9f9f9; padding: 10px;")
        color_layout = QVBoxLayout(color_frame)

        # 前景色选择
        fg_layout = QHBoxLayout()
        self.foreground_label = QLabel("前景色:")
        self.foreground_display = ColorDisplay(QColor(Qt.black))
        self.foreground_btn = QPushButton("选择颜色")
        # self.foreground_btn.setFixedWidth(100)
        self.foreground_btn.clicked.connect(self.choose_foreground_color)

        fg_layout.addWidget(self.foreground_label)
        fg_layout.addWidget(self.foreground_display)
        fg_layout.addStretch()
        fg_layout.addWidget(self.foreground_btn)

        color_layout.addLayout(fg_layout)

        # 背景色选择
        bg_layout = QHBoxLayout()
        self.background_label = QLabel("背景色:")
        self.background_display = ColorDisplay(QColor(Qt.white))
        self.background_btn = QPushButton("选择颜色")
        # self.background_btn.setFixedWidth(100)
        self.background_btn.clicked.connect(self.choose_background_color)

        bg_layout.addWidget(self.background_label)
        bg_layout.addWidget(self.background_display)
        bg_layout.addStretch()
        bg_layout.addWidget(self.background_btn)

        color_layout.addLayout(bg_layout)

        # 其他配置
        config_frame = QFrame()
        config_frame.setFrameShape(QFrame.StyledPanel)
        config_frame.setStyleSheet("background-color: #f9f9f9; padding: 10px;")
        config_layout = QHBoxLayout(config_frame)

        self.margin_label = QLabel("边距:")
        self.margin_edit = QLineEdit("2")  # 默认边距增加到2

        self.size_label = QLabel("尺寸:")
        self.size_combo = QComboBox()
        self.size_combo.addItems(["小 (300x300)", "中 (400x400)", "大 (500x500)", "超大 (600x600)"])
        self.size_combo.setCurrentIndex(1)  # 默认中等尺寸

        self.format_label = QLabel("图片格式:")
        self.format_combo = QComboBox()
        self.format_combo.addItems(["png", "jpg", "bmp"])
        self.format_combo.setFixedWidth(80)

        config_layout.addWidget(self.margin_label)
        config_layout.addWidget(self.margin_edit)
        config_layout.addWidget(self.size_label)
        config_layout.addWidget(self.size_combo)
        config_layout.addStretch()
        config_layout.addWidget(self.format_label)
        config_layout.addWidget(self.format_combo)

        left_layout.addWidget(self.content_label)
        left_layout.addWidget(self.content_edit)
        left_layout.addWidget(color_frame)
        left_layout.addWidget(config_frame)
        left_layout.addStretch()

        left_widget.setLayout(left_layout)

        # 右侧输出区域布局
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setAlignment(Qt.AlignCenter)

        # 二维码显示区域（居中）
        self.qr_container = QFrame()
        self.qr_container.setFrameShape(QFrame.StyledPanel)
        self.qr_container.setStyleSheet("background-color: #ffffff; border: 1px solid #cccccc;")
        self.qr_container.setMinimumSize(520, 520)
        self.qr_container.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        qr_layout = QVBoxLayout(self.qr_container)
        qr_layout.setAlignment(Qt.AlignCenter)

        self.qr_label = QLabel("生成的二维码将显示在此")
        self.qr_label.setAlignment(Qt.AlignCenter)
        self.qr_label.setStyleSheet("color: #888888; font-size: 14px;")
        self.qr_label.setFixedSize(400, 400)  # 增大默认显示尺寸

        qr_layout.addWidget(self.qr_label)

        # 识别结果显示
        self.result_label = QLabel("识别结果将显示在此")
        self.result_label.setAlignment(Qt.AlignCenter)
        self.result_label.setStyleSheet("color: #555555; font-size: 12px;")
        self.result_label.setWordWrap(True)
        self.result_label.setMaximumHeight(60)

        right_layout.addWidget(self.qr_container)
        right_layout.addWidget(self.result_label)

        right_widget.setLayout(right_layout)

        # 添加到分割布局
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)

        # 功能按钮区域（下部）
        button_layout = QHBoxLayout()

        self.generate_btn = QPushButton("生成二维码")
        self.generate_btn.setIcon(QIcon.fromTheme("document-new"))
        self.generate_btn.setMinimumHeight(40)
        self.generate_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.generate_btn.clicked.connect(self.generate_qr)

        self.save_btn = QPushButton("保存二维码")
        self.save_btn.setIcon(QIcon.fromTheme("document-save"))
        self.save_btn.setMinimumHeight(40)
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0b7dda;
            }
        """)
        self.save_btn.clicked.connect(self.save_qr)

        self.decode_file_btn = QPushButton("从文件识别")
        self.decode_file_btn.setIcon(QIcon.fromTheme("document-open"))
        self.decode_file_btn.setMinimumHeight(40)
        self.decode_file_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #e68a00;
            }
        """)
        self.decode_file_btn.clicked.connect(self.decode_from_file)

        # self.decode_screen_btn = QPushButton("从屏幕识别")
        # self.decode_screen_btn.setIcon(QIcon.fromTheme("video-display"))
        # self.decode_screen_btn.setMinimumHeight(40)
        # self.decode_screen_btn.setStyleSheet("""
        #     QPushButton {
        #         background-color: #9C27B0;
        #         color: white;
        #         border-radius: 5px;
        #     }
        #     QPushButton:hover {
        #         background-color: #89229b;
        #     }
        # """)
        # self.decode_screen_btn.clicked.connect(self.decode_from_screen)

        self.clear_btn = QPushButton("清空内容")
        self.clear_btn.setIcon(QIcon.fromTheme("edit-clear"))
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.clear_btn.clicked.connect(self.clear_content)

        button_layout.addWidget(self.generate_btn)
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.decode_file_btn)
        # button_layout.addWidget(self.decode_screen_btn)
        button_layout.addWidget(self.clear_btn)
        button_layout.setAlignment(Qt.AlignCenter)

        # 组装主布局
        main_layout.addWidget(splitter)
        main_layout.addLayout(button_layout)

        self.setWindowTitle("高级二维码工具")
        self.resize(1000, 700)

    def choose_foreground_color(self):
        """选择前景色"""
        color = QColorDialog.getColor(self.foreground_display.get_color(), self, "选择前景色")
        if color.isValid():
            self.foreground_display.set_color(color)

    def choose_background_color(self):
        """选择背景色"""
        color = QColorDialog.getColor(self.background_display.get_color(), self, "选择背景色")
        if color.isValid():
            self.background_display.set_color(color)

    def generate_qr(self):
        """生成二维码"""
        content = self.content_edit.toPlainText()
        if not content:
            QMessageBox.warning(self, "提示", "请输入要生成二维码的内容")
            return

        # 获取颜色配置
        fg_color = self.foreground_display.get_color()
        bg_color = self.background_display.get_color()
        fg_rgb = (fg_color.red(), fg_color.green(), fg_color.blue())
        bg_rgb = (bg_color.red(), bg_color.green(), bg_color.blue())

        # 获取其他配置
        try:
            margin = int(self.margin_edit.text())
            if margin < 0:
                raise ValueError("边距必须为非负整数")
        except ValueError:
            QMessageBox.warning(self, "参数错误", "边距必须为非负整数")
            return

        # 获取尺寸配置
        size_index = self.size_combo.currentIndex()
        box_sizes = [8, 10, 12, 15]  # 对应不同尺寸选项的 box_size
        box_size = box_sizes[size_index]

        # 获取显示尺寸
        display_sizes = [300, 400, 500, 600]
        display_size = display_sizes[size_index]
        self.qr_label.setFixedSize(display_size, display_size)

        img_format = self.format_combo.currentText()

        # 生成二维码 - 提高 box_size 以增加清晰度
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=box_size,  # 增大每个模块的像素数
            border=margin,
        )
        qr.add_data(content)
        qr.make(fit=True)

        qr_img = qr.make_image(fill_color=fg_rgb, back_color=bg_rgb)
        qr_img = qr_img.convert("RGB")

        # 保存原始 PIL 图像用于保存/识别
        self.generated_qr_img = qr_img

        # 转换为 QImage/QPixmap 显示
        width, height = qr_img.size
        bytes_per_line = 3 * width
        q_image = QImage(
            qr_img.tobytes(),
            width,
            height,
            bytes_per_line,
            QImage.Format_RGB888
        )
        pixmap = QPixmap.fromImage(q_image).scaled(
            self.qr_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
        )
        self.qr_label.setPixmap(pixmap)
        self.result_label.setText(f"二维码内容: {content[:30]}...")

    def save_qr(self):
        """保存二维码"""
        if not hasattr(self, "generated_qr_img"):
            QMessageBox.warning(self, "提示", "请先生成二维码")
            return

        img_format = self.format_combo.currentText()
        file_path, _ = QFileDialog.getSaveFileName(
            self, "保存二维码", "", f"{img_format} Files (*.{img_format})"
        )
        if file_path:
            # 保存高清晰度版本
            self.generated_qr_img.save(file_path, dpi=(300, 300))
            QMessageBox.information(self, "成功", f"二维码已成功保存至: {file_path}")

    def decode_from_file(self):
        """从文件识别二维码"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择二维码图片", "", "图片文件 (*.png *.jpg *.jpeg *.bmp *.gif)"
        )
        if file_path:
            try:
                # 打开图片并转换为 PIL 图像
                img = Image.open(file_path).convert("RGB")
                self.decode_image(img)
            except Exception as e:
                QMessageBox.critical(self, "错误", f"无法打开图片: {str(e)}")

    def decode_from_screen(self):
        """从屏幕识别二维码"""
        # 最小化主窗口
        self.showMinimized()

        # 延迟启动截图工具，确保窗口已最小化
        QTimer.singleShot(300, self.start_screen_capture)

    def start_screen_capture(self):
        """启动屏幕截图工具"""
        # 确保应用在活动状态
        QApplication.setActiveWindow(self)

        # 创建并显示截图窗口
        self.screen_capture = ScreenCaptureWidget(self)

    def process_screen_capture(self, img):
        """处理屏幕截图结果"""
        # 恢复主窗口
        self.showNormal()
        self.activateWindow()

        # 解码截图中的二维码
        self.decode_image(img)

    def decode_image(self, img):
        """解码图像中的二维码"""
        try:
            # 转换为 OpenCV 格式
            cv_img = np.array(img)
            cv_img = cv2.cvtColor(cv_img, cv2.COLOR_RGB2BGR)

            # 检测并解码二维码
            barcodes = decode(cv_img)

            if barcodes:
                result = barcodes[0].data.decode("utf-8")
                self.content_edit.setText(result)
                self.result_label.setText(f"识别结果: {result[:30]}...")

                # 显示识别的二维码（带边框）
                if hasattr(barcodes[0], 'rect'):
                    x, y, w, h = barcodes[0].rect
                    cv2.rectangle(cv_img, (x, y), (x + w, y + h), (0, 255, 0), 2)

                    result_img = Image.fromarray(cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB))
                    width, height = result_img.size
                    bytes_per_line = 3 * width
                    q_image = QImage(
                        result_img.tobytes(),
                        width,
                        height,
                        bytes_per_line,
                        QImage.Format_RGB888
                    )
                    pixmap = QPixmap.fromImage(q_image).scaled(
                        self.qr_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
                    )
                    self.qr_label.setPixmap(pixmap)
            else:
                # 尝试增强图像以提高识别率
                gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
                _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                barcodes = decode(thresh)

                if barcodes:
                    result = barcodes[0].data.decode("utf-8")
                    self.content_edit.setText(result)
                    self.result_label.setText(f"识别结果: {result[:30]}...")

                    # 显示增强后的图像
                    enhanced_img = Image.fromarray(thresh)
                    width, height = enhanced_img.size
                    bytes_per_line = width
                    q_image = QImage(
                        enhanced_img.tobytes(),
                        width,
                        height,
                        bytes_per_line,
                        QImage.Format_Grayscale8
                    )
                    pixmap = QPixmap.fromImage(q_image).scaled(
                        self.qr_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation
                    )
                    self.qr_label.setPixmap(pixmap)
                else:
                    QMessageBox.warning(self, "识别结果", "未检测到二维码或识别失败")

        except Exception as e:
            QMessageBox.critical(self, "错误", f"二维码识别失败: {str(e)}")

    def clear_content(self):
        """清空内容"""
        self.content_edit.clear()
        self.qr_label.clear()
        self.qr_label.setText("生成的二维码将显示在此")
        self.result_label.setText("识别结果将显示在此")
        if hasattr(self, "generated_qr_img"):
            del self.generated_qr_img


# if __name__ == "__main__":
#     # 确保中文正常显示
#     QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
#     app = QApplication(sys.argv)
#     app.setApplicationName("高级二维码工具")
#
#     # 设置应用样式
#     app.setStyle("Fusion")
#
#     window = QRCodeTool()
#     window.show()
#
#     sys.exit(app.exec_())