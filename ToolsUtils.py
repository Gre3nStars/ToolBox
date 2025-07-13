# ToolsUtils.py
import base64
import json

from PyQt5.QtWidgets import QTextEdit, QLineEdit, QStatusBar, QLabel
import re
import urllib.parse
from urllib.parse import parse_qs, urlparse
import codecs


class ToolUtils:
    @staticmethod
    def clear_content(input_widget, output_widget):
        """通用方法：清除输入和输出控件的内容"""
        if isinstance(input_widget, (QTextEdit, QLineEdit)):
            input_widget.clear()
        if isinstance(output_widget, (QTextEdit, QLineEdit)):
            output_widget.clear()

    @staticmethod
    def swap_content(input_widget:(QTextEdit,QLineEdit),output_widget:(QTextEdit,QLineEdit)):
        tmp_text = input_widget.toPlainText()
        output_text = output_widget.toPlainText()
        input_widget.setPlainText(output_text)
        output_widget.setPlainText(tmp_text)

    @staticmethod
    def update_textChanged_statusbar(input_widget:(QTextEdit,QLineEdit),output_widget:(QTextEdit,QLineEdit),status_bar:(QLabel)):
        input_len = len(input_widget.toPlainText())
        output_len = len(output_widget.toPlainText())
        # status_bar.setStyleSheet("QStatusBar::item { alignment: AlignRight; }")
        status_bar.setText(f"当前输入字符长度为：{input_len}，输出字符长度为：{output_len}")

    @staticmethod
    def test_decode():
        print(123)


class UnicodeDecoder:
    """解码字符串中混合的 Unicode 格式"""

    @staticmethod
    def decode_standard_escapes(text: str) -> str:
        """解码标准的 Python Unicode 转义序列（如 '\\u4e16'）"""
        return codecs.decode(text, 'unicode_escape')

    @staticmethod
    def decode_u_notation(text: str) -> str:
        """解码 'U+XXXX' 格式的 Unicode 编码"""
        return re.sub(r'U\+([0-9A-Fa-f]+)', lambda m: chr(int(m.group(1), 16)), text)

    @staticmethod
    def decode_mixed(text: str) -> str:
        """混合解码多种格式的 Unicode 编码"""
        text = UnicodeDecoder.decode_u_notation(text)
        return UnicodeDecoder.decode_standard_escapes(text)

    @staticmethod
    def decode_custom_format(text: str) -> str:
        """解码自定义格式的 Unicode 编码（如无前缀的十六进制）"""
        # 先处理 U+XXXX 格式
        text = UnicodeDecoder.decode_u_notation(text)

        # 再处理无前缀的十六进制
        text = re.sub(r'(?<!U\+)(?<!\\u)([0-9A-Fa-f]{4,6})',
                      lambda m: chr(int(m.group(0), 16)), text)

        # 最后处理标准转义序列
        return UnicodeDecoder.decode_standard_escapes(text)

class NormalUtils:
    def escape_text(s):
        def replace(c):
            code = ord(c)
            if code < 0x80:
                return urllib.parse.quote(c)
            elif code < 0x10000:
                return f'%u{code:04X}'
            else:
                # 处理大于 0xFFFF 的字符（代理对）
                # 参考：https://en.wikipedia.org/wiki/UTF-16#Code_points_from_0x10000_to_0x10FFFF
                code -= 0x10000
                high = (code >> 10) + 0xD800
                low = (code & 0x3FF) + 0xDC00
                return f'%u{high:04X}%u{low:04X}'

        return ''.join(replace(c) for c in s)

    def unescape_text(s):
        def replace(match):
            hex_str = match.group(1)
            if len(hex_str) == 2:
                # 处理 %xx 类型
                return bytes([int(hex_str, 16)]).decode('utf-8', errors='replace')
            elif len(hex_str) == 4:
                # 处理 %uXXXX 类型
                return chr(int(hex_str, 16))
            return ''

        # 匹配 %uXXXX 或 %xx
        s = s.replace('+', '%20')  # 兼容性处理
        return re.sub(r'%(?:([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4}))', replace, s, flags=re.IGNORECASE)

    def url_params_to_dict(url):
        # 解析整个 URL，提取查询参数部分
        parsed_url = urlparse(url)
        query_str = parsed_url.query

        # 使用 parse_qs 将查询字符串解析为字典
        params_dict = parse_qs(query_str)

        # 可选：将单值列表转为字符串，保留多值为数组
        for key in params_dict:
            if len(params_dict[key]) == 1:
                params_dict[key] = params_dict[key][0]

        return params_dict

    def jsonparam_to_url_params(json_str):
        json_param = json_str.replace("'", '"')
        json_param = json.loads(json_param)
        encoded_url = urllib.parse.urlencode(json_param, encoding='utf-8')
        return urllib.parse.unquote(encoded_url)

    def decode_decimal_entities(encoded_text):
        """Decodes HTML decimal entities back to original characters."""

        def replace(match):
            return chr(int(match.group(1)))

        return re.sub(r'&#(\d+);', replace, encoded_text)

    def decode_hexadecimal_entities(encoded_text):
        """Decodes HTML hexadecimal entities back to original characters."""

        def replace(match):
            return chr(int(match.group(1), 16))

        return re.sub(r'&#x([0-9a-fA-F]+);', replace, encoded_text)

class BrainfuckCodec:
    def encode(self, text):
        code = []
        for char in text:
            ascii_val = ord(char)
            code.append(f'+{"+" * (ascii_val - 1)}[>++++++[-<-------->]>+.[-]')
        return ''.join(code)

    def decode(self, bf_code):
        output = []
        memory = [0] * 30000
        ptr = 0
        i = 0

        while i < len(bf_code):
            if bf_code[i] == '+':
                memory[ptr] += 1
            elif bf_code[i] == '-':
                memory[ptr] -= 1
            elif bf_code[i] == '>':
                ptr += 1
            elif bf_code[i] == '<':
                ptr -= 1
            elif bf_code[i] == '.':
                output.append(chr(memory[ptr]))
            elif bf_code[i] == '[' and memory[ptr] == 0:
                loop_start = i
                balance = 1
                while balance > 0:
                    i += 1
                    if bf_code[i] == '[':
                        balance += 1
                    elif bf_code[i] == ']':
                        balance -= 1
                continue
            elif bf_code[i] == ']' and memory[ptr] != 0:
                loop_end = i
                balance = 1
                while balance > 0:
                    i -= 1
                    if bf_code[i] == '[':
                        balance -= 1
                    elif bf_code[i] == ']':
                        balance += 1
                continue
            i += 1

        return ''.join(output)

    def brainfuck_decode(code):
        # 初始化内存和指针
        memory = [0] * 30000
        pointer = 0

        # 结果字符串
        result = ""

        # 循环遍历 Brainfuck 代码
        i = 0
        while i < len(code):
            char = code[i]

            if char == '>':
                pointer += 1
            elif char == '<':
                pointer -= 1
            elif char == '+':
                memory[pointer] += 1
            elif char == '-':
                memory[pointer] -= 1
            elif char == '.':
                result += chr(memory[pointer])
            elif char == ',':
                # 这里需要实现读取用户输入的逻辑
                pass
            elif char == '[':
                # 如果当前指针所在的内存位置为0，则跳转到与之对应的"]"之后
                if memory[pointer] == 0:
                    loop_count = 1
                    while loop_count > 0:
                        i += 1
                        if code[i] == '[':
                            loop_count += 1
                        elif code[i] == ']':
                            loop_count -= 1
                else:
                    # 否则继续执行下面的指令
                    pass
            elif char == ']':
                # 如果当前指针所在的内存位置不为0，则跳转到与之对应的"["之前
                if memory[pointer] != 0:
                    loop_count = 1
                    while loop_count > 0:
                        i -= 1
                        if code[i] == ']':
                            loop_count += 1
                        elif code[i] == '[':
                            loop_count -= 1
                    # 因为循环结束后还会+1，所以这里需要减去1
                    i -= 1
                else:
                    # 否则继续执行下面的指令
                    pass

            i += 1

        return result




class OokCodec:
    ook_to_bf_map = {
        ('Ook.', 'Ook?'): '+',
        ('Ook?', 'Ook.'): '-',
        ('Ook.', 'Ook.'): '>',
        ('Ook!', 'Ook!'): '<',
        ('Ook?', 'Ook!'): '.',
        ('Ook!', 'Ook?'): ',',
        ('Ook!', 'Ook.'): '[',
        ('Ook.', 'Ook!'): ']'
    }

    def encode(self, text):
        brainfuck = BrainfuckCodec().encode(text)
        ook_code = ''
        for char in brainfuck:
            for key, value in self.ook_to_bf_map.items():
                if value == char:
                    ook_code += f'{key[0]} {key[1]} '
        return ook_code.strip()

    def decode(self, ook_code):
        ook_pairs = [tuple(pair.split()) for pair in ook_code.split(' ') if pair]
        brainfuck_code = ''.join([self.ook_to_bf_map[pair] for pair in ook_pairs])
        return BrainfuckCodec().decode(brainfuck_code)

class ShortOokCodec:
    short_ook_to_bf_map = {
        'oO': '+', 'Oo': '-', 'oo': '>', 'OO': '<', 'ou': '.', 'uO': ',', 'uo': '[', 'uu': ']'
    }

    def encode(self, text):
        brainfuck = BrainfuckCodec().encode(text)
        short_ook_code = ''
        for char in brainfuck:
            for key, value in self.short_ook_to_bf_map.items():
                if value == char:
                    short_ook_code += f'{key} '
        return short_ook_code.strip()

    def decode(self, short_ook_code):
        short_ook_pairs = short_ook_code.split()
        brainfuck_code = ''.join([self.short_ook_to_bf_map[pair] for pair in short_ook_pairs])
        return BrainfuckCodec().decode(brainfuck_code)

class TrollscriptCodec:
    trollscript_to_bf_map = {
        ('I', 'have', 'no', 'idea'): '+',
        ('What', 'the', 'hell', 'is', 'this?'): '-',
        ('This', 'is', 'getting', 'ridiculous'): '>',
        ('Why', 'do', 'we', 'need', 'all', 'these', 'words?'): '<',
        ('Can', 'someone', 'please', 'help', 'me?'): '.',
        ('Is', 'there', 'a', 'doctor', 'in', 'here?'): ',',
        ('Do', 'you', 'even', 'code?'): '[',
        ('Coding', 'is', 'fun'): ']'
    }

    def encode(self, text):
        brainfuck = BrainfuckCodec().encode(text)
        trollscript_code = ''
        for char in brainfuck:
            for key, value in self.trollscript_to_bf_map.items():
                if value == char:
                    trollscript_code += f'{" ".join(key)} '
        return trollscript_code.strip()

    def decode(self, trollscript_code):
        trollscript_phrases = [tuple(phrase.split()) for phrase in trollscript_code.split('   ') if phrase]
        brainfuck_code = ''.join([self.trollscript_to_bf_map[phrase] for phrase in trollscript_phrases])
        return BrainfuckCodec().decode(brainfuck_code)



if __name__ == '__main__':
    data = '''+++++ ++[-> +++++ ++<]> .+.+. --.+. +.--. +.+.< +++++ +[->+ +++++ <]>++
    +++++ +++.+ ++.++ +++++ ++.-- --.++ +++.< +++++ ++[-> ----- --<]> -----
    ----- --.+. +.<'''
    # bf = BrainfuckCodec.brainfuck_decode(data)
    ddd = 'eyJjb2RlIjoiRkhfUFVCX09LIiwibWVzc2FnZSI6IuaIkOWKnyIsImV4dHJhIjpudWxsLCJkYXRhIjpbeyJpZCI6IjEwMjAyNDA1MzAwMDAwMDAwMDAwMDAwMDAwMDAxMDAyIiwidGVuYW50Q29kZSI6InRlbGVjb20iLCJkb21haW5Db2RlIjoiWFhKU05FVyIsImFwcENvZGUiOiJYWEpTR0QiLCJiaXpUeXBlQ29kZSI6Ii0xIiwiYml6T2JqQ29kZSI6Ii0xIiwiYml6T2JqVmVyIjoiLTEiLCJhY3Rpdml0eUNvZGUiOiItMSIsIm93bmVyIjoiLTEiLCJjb25maWdJdGVtQ29kZSI6ImNvbWVVbml0IiwiY29uZmlnSXRlbU5hbWUiOiLmnaXmlofljZXkvY0iLCJjb25maWdJdGVtVmFsdWUiOiJbXCLkuK3np7votYTmnKzmjqfogqHmnInpmZDotKPku7vlhazlj7hcIixcIuiuvuiuoemZolwiLFwi5Lit5Zu956e75Yqo6YCa5L+h6ZuG5Zui6KW/6JeP5pyJ6ZmQ5YWs5Y+4XCIsXCLovpvlp4blt7Tnp5FcIixcIui0ouWKoeWFrOWPuFwiLFwi56CU56m26ZmiXCIsXCLnp7vliqjlhZrmoKFcIixcIuivgeWIuOS6i+WKoemDqO+8iOmmmea4r+acuuaehO+8iVwiLFwi5L6b5bqU6ZO+566h55CG5Lit5b+DXCIsXCLkv6Hmga/muK/kuK3lv4NcIixcIuS4reWbveenu+WKqOmAmuS/oembhuWbouWkqea0peaciemZkOWFrOWPuFwiLFwi5Lit5Zu956e75Yqo6YCa5L+h6ZuG5Zui6buR6b6Z5rGf5pyJ6ZmQ5YWs5Y+4XCIsXCLkuK3lm73np7vliqjpgJrkv6Hpm4blm6LmsrPljJfmnInpmZDlhazlj7hcIixcIuS4reWbveenu+WKqOmAmuS/oembhuWbouWGheiSmeWPpOaciemZkOWFrOWPuFwiLFwi5Lit5Zu956e75Yqo6YCa5L+h6ZuG5Zui5ZCJ5p6X5pyJ6ZmQ5YWs5Y+4XCIsXCLkuK3lm73np7vliqjpgJrkv6Hpm4blm6LlroHlpI/mnInpmZDlhazlj7hcIixcIuS4reWbveenu+WKqOmAmuS/oembhuWbouaWsOeWhuaciemZkOWFrOWPuFwiLFwi5Lit5Zu956e75Yqo6YCa5L+h6ZuG5Zui55SY6IKD5pyJ6ZmQ5YWs5Y+4XCIsXCLkuK3lm73np7vliqjpgJrkv6Hpm4blm6LpnZLmtbfmnA=='
    print(base64.b64decode(ddd).decode("utf-8",errors='ignore'))
    # str_code = "HelloWorld!!!"
