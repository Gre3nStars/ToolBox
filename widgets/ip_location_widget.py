"""
Author: Gre3nStars
Date: 2025-07-21 17:11:32
LastEditTime: 2025-08-12 09:13:41
Description: 
FilePath: ToolBox_internal/widgets/ip_location_widget.py
Copyright: Copyright (c) 2025 by Gre3nStars, All Rights Reserved. 
"""
import struct
import sys
import re
import socket
import requests
import json
import os
from urllib.parse import urlparse

from PySide6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout,
                               QWidget, QLineEdit, QPushButton, QTableWidget,
                               QTableWidgetItem, QHeaderView, QMessageBox, QMenu,
                               QLabel, QProgressBar, QTextEdit, QComboBox, QGroupBox,
                               QFileDialog, QSpinBox, QSplitter)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QAction, QFont, QIcon
import pandas as pd
from datetime import datetime


class QQWryReader:
    def __init__(self, db_file='qqwry.dat'):
        # 获取资源文件的正确路径
        self.db_path = self.get_resource_path(os.path.join('resource', db_file))
        self.f_db = open(self.db_path, "rb")
        # self.f_db = open(db_file, "rb")
        bs = self.f_db.read(8)
        (self.first_index, self.last_index) = struct.unpack('II', bs)
        self.index_count = int((self.last_index - self.first_index) / 7 + 1)
        self.cur_start_ip = None
        self.cur_end_ip_offset = None
        self.cur_end_ip = None

        # print(self.get_version(), " 纪录总数: %d 条 " % (self.index_count))

    @staticmethod
    def get_resource_path(relative_path):
        """获取资源文件的绝对路径，适配开发和打包后的环境"""
        if getattr(sys, 'frozen', False):
            # 打包后的环境，资源文件位于sys._MEIPASS目录下
            base_path = sys._MEIPASS
        else:
            # 开发环境，资源文件位于项目根目录
            base_path = os.path.abspath(".")

        # 拼接完整路径并返回
        return os.path.join(base_path, relative_path)

    def get_version(self):
        '''
        获取版本信息，最后一条IP记录 255.255.255.0-255.255.255.255 是版本信息
        :return: str
        '''
        s = self.get_addr_by_ip(0xffffff00)
        # print(s)
        return s

    def get_index_count(self):
        count_num = int((self.last_index - self.first_index) / 7 + 1)
        return count_num

    def _get_area_addr(self, offset=0):
        if offset:
            self.f_db.seek(offset)
        bs = self.f_db.read(1)
        (byte,) = struct.unpack('B', bs)
        if byte == 0x01 or byte == 0x02:
            p = self.getLong3()
            if p:
                return self.get_offset_string(p)
            else:
                return ""
        else:
            self.f_db.seek(-1, 1)
            return self.get_offset_string(offset)

    def _get_addr(self, offset):
        '''
        获取offset处记录区地址信息(包含国家和地区)
        如果是中国ip，则是 "xx省xx市 xxxxx地区" 这样的形式
        (比如:"福建省 电信", "澳大利亚 墨尔本Goldenit有限公司")
        :param offset:
        :return:str
        '''
        self.f_db.seek(offset + 4)
        bs = self.f_db.read(1)
        (byte,) = struct.unpack('B', bs)
        if byte == 0x01:  # 重定向模式1
            country_offset = self.getLong3()
            self.f_db.seek(country_offset)
            bs = self.f_db.read(1)
            (b,) = struct.unpack('B', bs)
            if b == 0x02:
                country_addr = self.get_offset_string(self.getLong3())
                self.f_db.seek(country_offset + 4)
            else:
                country_addr = self.get_offset_string(country_offset)
            area_addr = self._get_area_addr()
        elif byte == 0x02:  # 重定向模式2
            country_addr = self.get_offset_string(self.getLong3())
            area_addr = self._get_area_addr(offset + 8)
        else:  # 字符串模式
            country_addr = self.get_offset_string(offset + 4)
            area_addr = self._get_area_addr()
        return country_addr + " " + area_addr

    def dump(self, first, last):
        '''
        打印数据库中索引为first到索引为last(不包含last)的记录
        :param first:
        :param last:
        :return:
        '''
        if last > self.index_count:
            last = self.index_count
        for index in range(first, last):
            offset = self.first_index + index * 7
            self.f_db.seek(offset)
            buf = self.f_db.read(7)
            (ip, of1, of2) = struct.unpack("IHB", buf)
            address = self._get_addr(of1 + (of2 << 16))
            print("%d %s %s" % (index, self.ip2str(ip), address))

    def _set_ip_range(self, index):
        offset = self.first_index + index * 7
        self.f_db.seek(offset)
        buf = self.f_db.read(7)
        (self.cur_start_ip, of1, of2) = struct.unpack("IHB", buf)
        self.cur_end_ip_offset = of1 + (of2 << 16)
        self.f_db.seek(self.cur_end_ip_offset)
        buf = self.f_db.read(4)
        (self.cur_end_ip,) = struct.unpack("I", buf)

    def get_addr_by_ip(self, ip):
        '''
        通过ip查找其地址
        :param ip: (int or str)
        :return: str
        '''
        if type(ip) == str:
            ip = self.str2ip(ip)
        L = 0
        R = self.index_count - 1
        while L < R - 1:
            M = int((L + R) / 2)
            self._set_ip_range(M)
            if ip == self.cur_start_ip:
                L = M
                break
            if ip > self.cur_start_ip:
                L = M
            else:
                R = M
        self._set_ip_range(L)
        # version information, 255.255.255.X, urgy but useful
        if ip & 0xffffff00 == 0xffffff00:
            self._set_ip_range(R)
        if self.cur_start_ip <= ip <= self.cur_end_ip:
            address = self._get_addr(self.cur_end_ip_offset)
        else:
            address = "未找到该IP的地址"
        return address

    def get_ip_range(self, ip):
        '''
        返回ip所在记录的IP段
        :param ip: ip(str or int)
        :return: str
        '''
        if type(ip) == str:
            ip = self.str2ip(ip)
        self.get_addr_by_ip(ip)
        range = self.ip2str(self.cur_start_ip) + ' - ' \
                + self.ip2str(self.cur_end_ip)
        return range

    def get_offset_string(self, offset=0):
        '''
        获取文件偏移处的字符串(以'\0'结尾)
        :param offset: 偏移
        :return: str
        '''
        if offset:
            self.f_db.seek(offset)
        bs = b''
        ch = self.f_db.read(1)
        (byte,) = struct.unpack('B', ch)
        while byte != 0:
            bs += ch
            ch = self.f_db.read(1)
            (byte,) = struct.unpack('B', ch)
        return bs.decode('gbk')

    def ip2str(self, ip):
        '''
        整数IP转化为IP字符串
        :param ip:
        :return:
        '''
        return str(ip >> 24) + '.' + str((ip >> 16) & 0xff) + '.' + str((ip >> 8) & 0xff) + '.' + str(ip & 0xff)

    def str2ip(self, s):
        '''
        IP字符串转换为整数IP
        :param s:
        :return:
        '''
        (ip,) = struct.unpack('I', socket.inet_aton(s))
        return ((ip >> 24) & 0xff) | ((ip & 0xff) << 24) | ((ip >> 8) & 0xff00) | ((ip & 0xff00) << 8)

    def getLong3(self, offset=0):
        '''
        3字节的数值
        :param offset:
        :return:
        '''
        if offset:
            self.f_db.seek(offset)
        bs = self.f_db.read(3)
        (a, b) = struct.unpack('HB', bs)
        return (b << 16) + a


# 全局纯真IP数据库读取器
qqwry_reader = None
HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

class OnlineIPLocationQuery:
    def ip_addr_query(self,ip):
        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
            response = requests.get(url, timeout=10)
            data = response.json()

            if data.get('status') == 'success':
                country = data.get('country', '')
                region = data.get('regionName', '')
                city = data.get('city', '')
                isp = data.get('isp', '')

                # 云服务商英文到中文映射
                cloud_map = {
                    'Tencent': '腾讯云',
                    'Tencent Cloud': '腾讯云',
                    'Alibaba': '阿里云',
                    'Alibaba Cloud': '阿里云',
                    'Aliyun': '阿里云',
                    'Huawei': '华为云',
                    'Huawei Cloud': '华为云',
                    'Baidu': '百度云',
                    'Baidu Cloud': '百度云',
                    'JD Cloud': '京东云',
                    'Kingsoft': '金山云',
                    'Kingsoft Cloud': '金山云',
                    'UCloud': 'UCloud',
                    'AWS': '亚马逊云',
                    'Amazon': '亚马逊云',
                    'Amazon Cloud': '亚马逊云',
                    'Microsoft': '微软云',
                    'Azure': '微软云',
                    'Google': '谷歌云',
                    'Google Cloud': '谷歌云',
                }
                for k, v in cloud_map.items():
                    if k.lower() in isp.lower():
                        isp = v
                        break

                location_parts = []
                if country:
                    location_parts.append(country)
                if region:
                    location_parts.append(region)
                if city:
                    location_parts.append(city)
                if isp:
                    location_parts.append(f"({isp})")

                return '-'.join(location_parts) if location_parts else 'Unknown'
            else:
                return 'Query failed'

        except Exception as e:
            return f'Error: {str(e)}'


class FileLoadWorker(QThread):
    """文件加载线程"""
    progress_updated = Signal(int)
    data_loaded = Signal(list)
    finished = Signal()
    error_occurred = Signal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            # 读取文件内容
            with open(self.file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # 处理每一行
            processed_lines = []
            total_lines = len(lines)

            for i, line in enumerate(lines):
                # 清理行内容
                line = line.strip()
                if line and not line.startswith('#'):  # 跳过空行和注释行
                    # 处理CSV格式（逗号分隔）
                    if ',' in line:
                        parts = line.split(',')
                        for part in parts:
                            part = part.strip()
                            if part:
                                processed_lines.append(part)
                    else:
                        processed_lines.append(line)

                # 更新进度
                progress = int((i + 1) / total_lines * 100)
                self.progress_updated.emit(progress)

            self.data_loaded.emit(processed_lines)
            self.finished.emit()

        except UnicodeDecodeError:
            # 如果UTF-8失败，尝试其他编码
            try:
                with open(self.file_path, 'r', encoding='gbk') as f:
                    lines = f.readlines()

                processed_lines = []
                total_lines = len(lines)

                for i, line in enumerate(lines):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 处理CSV格式（逗号分隔）
                        if ',' in line:
                            parts = line.split(',')
                            for part in parts:
                                part = part.strip()
                                if part:
                                    processed_lines.append(part)
                        else:
                            processed_lines.append(line)

                    progress = int((i + 1) / total_lines * 100)
                    self.progress_updated.emit(progress)

                self.data_loaded.emit(processed_lines)
                self.finished.emit()

            except Exception as e:
                self.error_occurred.emit(f"文件编码错误: {str(e)}")
                self.finished.emit()

        except Exception as e:
            self.error_occurred.emit(f"读取文件失败: {str(e)}")
            self.finished.emit()


class IPLocationWorker(QThread):
    """后台线程处理IP查询"""
    progress_updated = Signal(int)
    result_ready = Signal(dict)
    finished = Signal()

    def __init__(self, input_data, api_source="qqwry"):
        super().__init__()
        self.input_data = input_data
        self.api_source = api_source

    def run(self):
        results = []
        total = len(self.input_data)

        for i, item in enumerate(self.input_data):
            try:
                result = self.query_ip_location(item)
                results.append(result)
                self.progress_updated.emit(int((i + 1) / total * 100))
            except Exception as e:
                results.append({
                    'input': item,
                    'ip': 'Error',
                    'location': f'Error: {str(e)}',
                    'is_special': False
                })
                self.progress_updated.emit(int((i + 1) / total * 100))

        self.result_ready.emit({'results': results})
        self.finished.emit()

    def query_ip_location(self, input_text):
        """查询IP归属地"""
        # 清理输入
        input_text = input_text.strip()

        # 提取IP或域名
        ip_or_domain = self.extract_ip_or_domain(input_text)

        if not ip_or_domain:
            return {
                'input': input_text,
                'ip': '提取失败',
                'location': '提取失败',
                'is_special': False
            }

        # 解析IP
        ip_address = self.resolve_ip(ip_or_domain)

        if not ip_address:
            return {
                'input': input_text,
                'ip': '无法解析',
                'location': '无法解析',
                'is_special': False
            }

        # 检查是否为特殊IP地址
        special_type = self.check_special_ip(ip_address)
        if special_type:
            return {
                'input': input_text,
                'ip': ip_address,
                'location': special_type,
                'is_special': True
            }

        # 查询IP归属地
        location = self.get_ip_location(ip_address)

        return {
            'input': input_text,
            'ip': ip_address,
            'location': location,
            'is_special': False
        }

    def extract_ip_or_domain(self, text):
        """从输入中提取IPv4、IPv6或域名"""
        # IPv6地址正则表达式（支持标准格式和压缩格式）
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|' \
                       r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|' \
                       r'\b:(?::[0-9a-fA-F]{1,4}){1,7}:\b'

        # IP地址v4正则表达式
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

        # 先查找IPv6地址
        ipv6_match = re.search(ipv6_pattern, text)
        if ipv6_match:
            return ipv6_match.group()

        # 再查找IPv4地址
        ipv4_match = re.search(ipv4_pattern, text)
        if ipv4_match:
            return ipv4_match.group()

        # 尝试解析URL获取网络位置
        try:
            parsed = urlparse(text)
            if parsed.netloc:
                return parsed.netloc
        except:
            pass

        # 直接检查域名格式
        if '.' in text and not text.startswith('http'):
            return text

        return None

    def resolve_ip(self, domain):
        """解析域名到IP地址，支持IPv4和IPv6"""
        # IPv6地址正则表达式
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|' \
                       r'\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|' \
                       r'\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|' \
                       r'\b:(?::[0-9a-fA-F]{1,4}){1,7}:\b'

        # IPv4地址正则表达式
        ipv4_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

        try:
            # 检查是否为IPv6地址
            if re.match(ipv6_pattern, domain):
                return domain

            # 检查是否为IPv4地址
            if re.match(ipv4_pattern, domain):
                return domain

            # 尝试先解析IPv6地址
            try:
                ipv6 = socket.getaddrinfo(domain, None, socket.AF_INET6)[0][4][0]
                return ipv6
            except:
                # 如果IPv6解析失败，尝试解析IPv4地址
                ipv4 = socket.gethostbyname(domain)
                return ipv4

        except socket.gaierror:
            return None
        except Exception as e:
            # 捕获其他可能的异常
            return None

    def get_ip_location(self, ip):
        """获取IP归属地信息"""
        if self.api_source == "qqwry":
            return self.query_qqwry(ip)
        elif self.api_source == "ip-api":
            return self.query_ip_api(ip)
        elif self.api_source == "ipinfo":
            return self.query_ipinfo(ip)
        elif self.api_source == "ip138":
            return self.query_ip138(ip)
        else:
            return self.query_qqwry(ip)  # 默认使用纯真IP数据库

    def query_qqwry(self, ip):
        """使用纯真IP数据库查询"""
        global qqwry_reader
        try:
            if qqwry_reader is None:
                qqwry_reader = QQWryReader()

            # if qqwry_reader.db_file is None:
            #     return "纯真IP数据库未加载"

            location = qqwry_reader.get_addr_by_ip(ip)
            return location if location else "未找到"

        except Exception as e:
            return f'Error: {str(e)}'

    def query_ip_api(self, ip):
        """使用ip-api.com查询"""
        try:
            url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
            response = requests.get(url,headers=HEADERS,verify=False, timeout=10)
            data = response.json()

            if data.get('status') == 'success':
                country = data.get('country', '')
                region = data.get('regionName', '')
                city = data.get('city', '')
                isp = data.get('isp', '')

                # 云服务商英文到中文映射
                cloud_map = {
                    'Tencent': '腾讯云',
                    'Tencent Cloud': '腾讯云',
                    'Alibaba': '阿里云',
                    'Alibaba Cloud': '阿里云',
                    'Aliyun': '阿里云',
                    'Huawei': '华为云',
                    'Huawei Cloud': '华为云',
                    'Baidu': '百度云',
                    'Baidu Cloud': '百度云',
                    'JD Cloud': '京东云',
                    'Kingsoft': '金山云',
                    'Kingsoft Cloud': '金山云',
                    'UCloud': 'UCloud',
                    'AWS': '亚马逊云',
                    'Amazon': '亚马逊云',
                    'Amazon Cloud': '亚马逊云',
                    'Microsoft': '微软云',
                    'Azure': '微软云',
                    'Google': '谷歌云',
                    'Google Cloud': '谷歌云',
                }
                for k, v in cloud_map.items():
                    if k.lower() in isp.lower():
                        isp = v
                        break

                location_parts = []
                if country:
                    location_parts.append(country)
                if region:
                    location_parts.append(region)
                if city:
                    location_parts.append(city)
                if isp:
                    location_parts.append(f"({isp})")

                return '-'.join(location_parts) if location_parts else 'Unknown'
            else:
                return 'Query failed'

        except Exception as e:
            return f'Error: {str(e)}'

    def query_ipinfo(self, ip):
        """使用ipinfo.io查询"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            response = requests.get(url,headers=HEADERS,verify=False, timeout=10)
            data = response.json()

            if 'error' not in data:
                country = data.get('country', '')
                region = data.get('region', '')
                city = data.get('city', '')
                org = data.get('org', '')

                # 云服务商映射
                cloud_map = {
                    'Tencent': '腾讯云',
                    'Alibaba': '阿里云',
                    'Aliyun': '阿里云',
                    'Huawei': '华为云',
                    'Baidu': '百度云',
                    'JD Cloud': '京东云',
                    'Kingsoft': '金山云',
                    'UCloud': 'UCloud',
                    'AWS': '亚马逊云',
                    'Amazon': '亚马逊云',
                    'Microsoft': '微软云',
                    'Azure': '微软云',
                    'Google': '谷歌云',
                }
                for k, v in cloud_map.items():
                    if k.lower() in org.lower():
                        org = v
                        break

                location_parts = []
                if country:
                    location_parts.append(country)
                if region:
                    location_parts.append(region)
                if city:
                    location_parts.append(city)
                if org:
                    location_parts.append(f"({org})")

                return '-'.join(location_parts) if location_parts else 'Unknown'
            else:
                return 'Query failed'

        except Exception as e:
            return f'Error: {str(e)}'
        
    def query_ip138(self, ip):
        """使用ipinfo.io查询"""
        ip_addr = ip
        try:
            # url = f'https://api.ip138.com/ip/\?ip=｛ip_addr｝&datatype=txt&token=｛self.ip138_apikey｝'
            url =  f"https://api.ip138.com/ip/?ip={ip}&datatype=json&token=e00c1652ae493888ea84c0655feaedf8"
            response = requests.get(url,headers=HEADERS,verify=False,timeout=20)
            data = response.text
            # print(data)

            if 'ok' in data:
                ip_addr_info = json.loads(data)
                ip_addr_info = ip_addr_info['data']

                location_parts = ''
                for addr in ip_addr_info:
                    location_parts += addr + '-'
                return location_parts[:-1]
            else:
                return 'Query failed'

        except Exception as e:
            return f'Error: {str(e)}'


    def check_special_ip(self, ip):
        """判断是否为保留地址或内网地址，返回中文描述"""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return '局域网IP（内网）'
            if ip_obj.is_loopback:
                return '回环地址（本地）'
            if ip_obj.is_multicast:
                return '组播地址'
            if ip_obj.is_reserved:
                return '保留IP地址'
            if ip_obj.is_link_local:
                return '链路本地地址'
            if ip_obj.is_unspecified:
                return '未指定地址'
        except Exception:
            pass
        return None


class IPLocationTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.worker = None
        self.results = []
        # 分页相关
        self.current_page = 1
        self.page_size = 50
        self.total_pages = 1

    def init_ui(self):
        """初始化用户界面"""
        self.setWindowTitle("IP归属查询工具")
        self.setGeometry(100, 100, 1000, 700)

        # 创建中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # 主布局
        layout = QVBoxLayout(central_widget)

        # 创建QSplitter，设置为垂直方向
        splitter = QSplitter(Qt.Vertical)

        # 输入区域GroupBox
        input_group = QGroupBox("输入区域")
        input_layout = QVBoxLayout(input_group)

        # 第一块：输入区域标题
        input_title = QLabel("输入IP、URL或域名:")
        input_layout.addWidget(input_title)

        # 第二块：输入框和API选择
        input_content_layout = QHBoxLayout()

        # 输入框
        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText("请输入IP地址、URL或域名，每行一个或者直接拖拽文件到此处")
        input_content_layout.addWidget(self.input_edit)

        # 启用拖拽功能
        self.input_edit.setAcceptDrops(True)
        self.input_edit.dragEnterEvent = self.drag_enter_event
        self.input_edit.dragLeaveEvent = self.drag_leave_event
        self.input_edit.dropEvent = self.drop_event

        # API选择区域
        api_layout = QHBoxLayout()
        api_label = QLabel("查询接口:")
        api_layout.addWidget(api_label)
        self.api_combo = QComboBox()
        self.api_combo.addItem("纯真IP数据库", "qqwry")
        self.api_combo.addItem("ip-api.com", "ip-api")
        self.api_combo.addItem("ipinfo.io", "ipinfo")
        self.api_combo.addItem("ip138.com", "ip138")
        api_layout.addWidget(self.api_combo)
        api_layout.addStretch()

        input_layout.addLayout(input_content_layout)

        # 第三块：功能按钮
        button_layout = QHBoxLayout()
        button_layout.addLayout(api_layout)


        self.query_btn = QPushButton("🔍 查询")
        self.query_btn.clicked.connect(self.start_query)
        button_layout.addWidget(self.query_btn)

        self.load_file_btn = QPushButton("📁 从文件载入")
        self.load_file_btn.clicked.connect(self.load_from_file)
        button_layout.addWidget(self.load_file_btn)

        self.clear_btn = QPushButton("🗑️ 清空")
        self.clear_btn.clicked.connect(self.clear_table)
        button_layout.addWidget(self.clear_btn)

        self.export_btn = QPushButton("💾 导出Excel")
        self.export_btn.clicked.connect(self.export_to_excel)
        button_layout.addWidget(self.export_btn)

        self.copy_all_btn = QPushButton("复制全部")
        self.copy_all_btn.setIcon(QIcon.fromTheme("document-new"))
        self.copy_all_btn.clicked.connect(self.copy_all_data)
        button_layout.addWidget(self.copy_all_btn)

        button_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        input_layout.addLayout(button_layout)

        splitter.addWidget(input_group)

        # 进度条
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 输出区域GroupBox
        output_group = QGroupBox("查询结果")
        output_layout = QVBoxLayout(output_group)

        # 表格
        self.table = QTableWidget()
        self.table.resizeColumnsToContents()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["IP或域名", "IP", "IP归属"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 300)
        self.table.setColumnWidth(1, 180)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        output_layout.addWidget(self.table)

        # 分页控件区域
        pagination_layout = QHBoxLayout()
        pagination_layout.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.page_size_label = QLabel("每页显示:")
        pagination_layout.addWidget(self.page_size_label)

        self.page_size_spin = QSpinBox()
        # 确保能完整显示最大页码
        self.page_size_spin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.page_size_spin.setMinimumWidth(120)
        self.page_size_spin.setMaximumWidth(120)


        self.page_size_spin.setMinimum(1)
        self.page_size_spin.setMaximum(65525)
        self.page_size_spin.setValue(100)
        self.page_size_spin.valueChanged.connect(self.on_page_size_changed)
        pagination_layout.addWidget(self.page_size_spin)

        self.page_info_label = QLabel("第 1 / 1 页")
        pagination_layout.addWidget(self.page_info_label)

        self.first_page_btn = QPushButton("⏪ 首页")
        self.first_page_btn.clicked.connect(self.first_page)
        pagination_layout.addWidget(self.first_page_btn)

        self.prev_page_btn = QPushButton("◀️上一页")
        self.prev_page_btn.clicked.connect(self.prev_page)
        pagination_layout.addWidget(self.prev_page_btn)

        self.next_page_btn = QPushButton("▶️下一页")
        self.next_page_btn.clicked.connect(self.next_page)
        pagination_layout.addWidget(self.next_page_btn)

        self.last_page_btn = QPushButton("⏩ 末页")
        self.last_page_btn.clicked.connect(self.last_page)
        pagination_layout.addWidget(self.last_page_btn)

        self.goto_page_label = QLabel("跳转到:")
        pagination_layout.addWidget(self.goto_page_label)

        self.goto_page_spin = QSpinBox()
        self.goto_page_spin.setMinimumWidth(120)
        self.goto_page_spin.setMaximumWidth(120)
        self.goto_page_spin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.goto_page_spin.setMinimum(1)
        self.goto_page_spin.setMaximum(1)
        self.goto_page_spin.setValue(1)
        self.goto_page_spin.valueChanged.connect(self.goto_page)
        pagination_layout.addWidget(self.goto_page_spin)

        # pagination_layout.addStretch()
        pagination_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        output_layout.addLayout(pagination_layout)
        splitter.addWidget(output_group)
        layout.addWidget(splitter)

        # 状态栏
        self.statusBar().showMessage(f'{QQWryReader().get_version()}, 纪录总数: {QQWryReader().get_index_count()}条')

    def update_pagination(self):
        """更新分页信息和控件"""
        total = len(self.results)
        self.page_size = self.page_size_spin.value()
        self.total_pages = max(1, (total + self.page_size - 1) // self.page_size)
        if self.current_page > self.total_pages:
            self.current_page = self.total_pages
        self.page_info_label.setText(f"第 {self.current_page}/{self.total_pages} 页")
        self.goto_page_spin.setMaximum(self.total_pages)
        self.goto_page_spin.setValue(self.current_page)
        self.prev_page_btn.setEnabled(self.current_page > 1)
        self.next_page_btn.setEnabled(self.current_page < self.total_pages)

    def on_page_size_changed(self):
        """每页数量变更"""
        self.current_page = 1
        self.update_pagination()
        self.populate_table()

    def first_page(self):
        self.current_page = 1
        self.update_pagination()
        self.populate_table()

    def prev_page(self):
        if self.current_page > 1:
            self.current_page -= 1
            self.update_pagination()
            self.populate_table()

    def next_page(self):
        if self.current_page < self.total_pages:
            self.current_page += 1
            self.update_pagination()
            self.populate_table()

    def last_page(self):
        self.current_page = self.total_pages
        self.update_pagination()
        self.populate_table()

    def goto_page(self):
        val = self.goto_page_spin.value()
        if 1 <= val <= self.total_pages:
            self.current_page = val
            self.update_pagination()
            self.populate_table()

    def start_query(self):
        """开始查询"""
        input_text = self.input_edit.toPlainText().strip()
        if not input_text:
            QMessageBox.warning(self, "警告", "请输入要查询的内容")
            return

        input_list = [line.strip() for line in input_text.split('\n') if line.strip()]
        if not input_list:
            QMessageBox.warning(self, "警告", "请输入有效的IP、URL或域名")
            return

        self.query_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)

        selected_api = self.api_combo.currentData()
        self.worker = IPLocationWorker(input_list, selected_api)
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.result_ready.connect(self.handle_results)
        self.worker.finished.connect(self.query_finished)
        self.worker.start()
        self.statusBar().showMessage("正在查询...")

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def handle_results(self, data):
        self.results = data['results']
        self.current_page = 1
        self.update_pagination()
        self.populate_table()

    def query_finished(self):
        self.query_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.statusBar().showMessage(f"查询完成，共 {len(self.results)} 条结果")

    def populate_table(self):
        """填充表格数据（分页）"""
        total = len(self.results)
        self.page_size = self.page_size_spin.value()
        self.total_pages = max(1, (total + self.page_size - 1) // self.page_size)
        self.update_pagination()
        start = (self.current_page - 1) * self.page_size
        end = min(start + self.page_size, total)
        page_results = self.results[start:end]
        self.table.setRowCount(len(page_results))
        for i, result in enumerate(page_results):
            input_item = QTableWidgetItem(result['input'])
            self.table.setItem(i, 0, input_item)
            ip_item = QTableWidgetItem(result['ip'])
            self.table.setItem(i, 1, ip_item)
            location_item = QTableWidgetItem(result['location'])
            self.table.setItem(i, 2, location_item)
            if result.get('is_special'):
                from PySide6.QtGui import QColor
                for col in range(3):
                    self.table.item(i, col).setBackground(QColor('#d4fcdc'))

    def clear_table(self):
        self.table.setRowCount(0)
        self.results = []
        self.input_edit.clear()
        self.current_page = 1
        self.update_pagination()
        self.statusBar().showMessage("已清空")

    def export_to_excel(self):
        if not self.results:
            QMessageBox.warning(self, "警告", "没有数据可导出")
            return
        try:
            df = pd.DataFrame(self.results)
            df = df[["input", "ip", "location"]]
            df.columns = ["IP或域名", "IP", "IP归属"]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"IP归属查询结果_{timestamp}.xlsx"
            df.to_excel(filename, index=False, engine='openpyxl')
            QMessageBox.information(self, "成功", f"数据已导出到 {filename}")
            self.statusBar().showMessage(f"已导出到 {filename}")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"导出失败: {str(e)}")

    def copy_all_data(self):
        if not self.results:
            QMessageBox.warning(self, "警告", "没有数据可复制")
            return
        try:
            text_lines = ["IP或域名\tIP\tIP归属"]
            for result in self.results:
                line = f"{result['input']}\t{result['ip']}\t{result['location']}"
                text_lines.append(line)
            text = '\n'.join(text_lines)
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            QMessageBox.information(self, "成功", "数据已复制到剪贴板")
            self.statusBar().showMessage("数据已复制到剪贴板")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"复制失败: {str(e)}")

    def show_context_menu(self, position):
        menu = QMenu()
        copy_action = QAction("复制选中行", self)
        copy_action.triggered.connect(self.copy_selected_rows)
        menu.addAction(copy_action)
        copy_all_action = QAction("复制全部", self)
        copy_all_action.triggered.connect(self.copy_all_data)
        menu.addAction(copy_all_action)
        menu.addSeparator()
        menu.addSeparator()
        clear_action = QAction("清空", self)
        clear_action.triggered.connect(self.clear_table)
        menu.addAction(clear_action)
        menu.exec(self.table.mapToGlobal(position))

    def copy_selected_rows(self):
        selected_rows = set(item.row() for item in self.table.selectedItems())
        if not selected_rows:
            QMessageBox.warning(self, "警告", "请先选择要复制的行")
            return
        try:
            text_lines = ["IP或域名\tIP\tIP归属"]
            # 只复制当前页的选中行
            start = (self.current_page - 1) * self.page_size
            for row in sorted(selected_rows):
                idx = start + row
                if idx < len(self.results):
                    result = self.results[idx]
                    line = f"{result['input']}\t{result['ip']}\t{result['location']}"
                    text_lines.append(line)
            text = '\n'.join(text_lines)
            clipboard = QApplication.clipboard()
            clipboard.setText(text)
            QMessageBox.information(self, "成功", f"已复制 {len(selected_rows)} 行数据到剪贴板")
            self.statusBar().showMessage(f"已复制 {len(selected_rows)} 行数据")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"复制失败: {str(e)}")

    def load_from_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "选择文件",
            "",
            "文本文件 (*.txt);;CSV文件 (*.csv);;所有文件 (*.*)"
        )
        if file_path:
            self.load_file_btn.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.file_worker = FileLoadWorker(file_path)
            self.file_worker.progress_updated.connect(self.update_file_load_progress)
            self.file_worker.data_loaded.connect(self.handle_file_data)
            self.file_worker.error_occurred.connect(self.handle_file_error)
            self.file_worker.finished.connect(self.file_load_finished)
            self.file_worker.start()
            self.statusBar().showMessage("正在加载文件...")

    def update_file_load_progress(self, value):
        self.progress_bar.setValue(value)

    def handle_file_data(self, data):
        self.input_edit.clear()
        for line in data:
            self.input_edit.append(line)
        QMessageBox.information(self, "成功", f"已从文件加载 {len(data)} 条记录")
        self.statusBar().showMessage(f"已从文件加载 {len(data)} 条记录")
        if len(data) > 0:
            reply = QMessageBox.question(
                self,
                "自动查询",
                f"已加载 {len(data)} 条记录，是否立即开始查询？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.start_query()

    def handle_file_error(self, error_msg):
        QMessageBox.critical(self, "错误", error_msg)
        self.statusBar().showMessage("文件加载失败")

    def file_load_finished(self):
        self.load_file_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

    def drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            for url in urls:
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if file_path.lower().endswith(('.txt', '.csv')):
                        event.acceptProposedAction()
                        self.input_edit.setStyleSheet("QTextEdit { border: 2px dashed #4CAF50; }")
                        return
            event.ignore()
        elif event.mimeData().hasText():
            event.acceptProposedAction()
            self.input_edit.setStyleSheet("QTextEdit { border: 2px dashed #4CAF50; }")
        else:
            event.ignore()

    def drag_leave_event(self, event):
        self.input_edit.setStyleSheet("")

    def drop_event(self, event):
        self.input_edit.setStyleSheet("")
        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            for url in urls:
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if file_path.lower().endswith(('.txt', '.csv')):
                        self.load_file_from_path(file_path)
                    else:
                        QMessageBox.warning(self, "警告", "只支持 .txt 和 .csv 文件")
                    break
        elif event.mimeData().hasText():
            text = event.mimeData().text()
            if text.strip():
                lines = text.strip().split('\n')
                added_count = 0
                for line in lines:
                    if line.strip():
                        self.input_edit.append(line.strip())
                        added_count += 1
                self.statusBar().showMessage(f"已添加 {added_count} 行文本")
                QMessageBox.information(self, "成功", f"已添加 {added_count} 行文本到输入框")

    def load_file_from_path(self, file_path):
        self.load_file_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.file_worker = FileLoadWorker(file_path)
        self.file_worker.progress_updated.connect(self.update_file_load_progress)
        self.file_worker.data_loaded.connect(self.handle_file_data)
        self.file_worker.error_occurred.connect(self.handle_file_error)
        self.file_worker.finished.connect(self.file_load_finished)
        self.file_worker.start()
        self.statusBar().showMessage(f"正在加载文件: {os.path.basename(file_path)}")

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    global qqwry_reader
    qqwry_reader = QQWryReader()
    window = IPLocationTool()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    # main()
    result = OnlineIPLocationQuery().ip_addr_query('117.132.1.1')
    print(result)
#     ip_query = QQWryReader()
#     result = ip_query.get_addr_by_ip("117.132.1.1")
#     print(result)