import base64

import base36
import base58
import base45
import base62
import py3base92
import pybase100
from base91 import decode as b91decode, encode as b91encode

import re
from typing import List, Dict, Optional, Callable

# 支持的编码列表
ENCODINGS = ['utf-8', 'gbk', 'gb2312', 'utf-16', 'big5', 'gb18030', 'iso-8859-1']

class BaseCodec:
    @staticmethod
    def base16_encode(data: str, encoding: str = 'utf-8') -> str:
        return base64.b16encode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base16_decode(data: str, encoding: str = 'utf-8') -> str:
        return base64.b16decode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base32_encode(data: str, encoding: str = 'utf-8') -> str:
        return base64.b32encode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base32_decode(data: str, encoding: str = 'utf-8') -> str:
        return base64.b32decode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base36_encode(data: str, encoding: str = 'utf-8') -> str:
        return base36.loads(data)

    @staticmethod
    def base36_decode(data: str, encoding: str = 'utf-8') -> str:
        return base36.dumps(int(data))


    @staticmethod
    def base45_encode(data: str, encoding: str = 'utf-8') -> str:
        return base45.b45encode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base45_decode(data: str, encoding: str = 'utf-8') -> str:
        return base45.b45decode(data).decode(encoding,errors='ignore')

    @staticmethod
    def base58_encode(data: str, encoding: str = 'utf-8') -> str:
        return base58.b58encode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base58_decode(data: str, encoding: str = 'utf-8') -> str:
        return base58.b58decode(data).decode(encoding,errors='ignore')

    @staticmethod
    def base62_encode(data: str, encoding: str = 'utf-8') -> str:
        return base62.encode(int(data))

    @staticmethod
    def base62_decode(data: str, encoding: str = 'utf-8') -> str:
        return base62.decode(data)

    @staticmethod
    def base64_encode(data: str, encoding: str) -> str:
        return base64.b64encode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base64_decode(data: str, encoding: str = 'utf-8') -> str:
        return base64.b64decode(data.encode(encoding)).decode(encoding,errors='ignore')

    @staticmethod
    def base85_encode(data: str, encoding: str = 'utf-8') -> str:
        return base64.a85encode(data.encode(encoding), adobe=True).decode(encoding,errors='ignore')

    @staticmethod
    def base85_decode(data: str, encoding: str = 'utf-8') -> str:
        return base64.a85decode(data.encode(encoding), adobe=True).decode(encoding,errors='ignore')

    @staticmethod
    def base91_encode(data: str, encoding: str = 'utf-8') -> str:
        return b91encode(data.encode(encoding))

    @staticmethod
    def base91_decode(data: str, encoding: str = 'utf-8') -> str:
        return b91decode(data).decode(encoding,errors='ignore')

    @staticmethod
    def base92_encode(data: str, encoding: str = 'utf-8') -> str:
        return py3base92.b92encode(data.encode(encoding))

    @staticmethod
    def base92_decode(data: str, encoding: str = 'utf-8') -> str:
        return py3base92.b92decode(data).decode(encoding,errors='ignore')

    @staticmethod
    def base100_encode(data: str, encoding: str = 'utf-8') -> str:
        return pybase100.encode(data).decode(encoding,errors='ignore')

    @staticmethod
    def base100_decode(data: str, encoding: str = 'utf-8') -> str:
        return pybase100.decode(data).decode(encoding,errors='ignore')

    @staticmethod
    def base122_encode(data: str, encoding: str = 'utf-8') -> str:
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        num = int.from_bytes(data.encode(encoding), 'big')
        encoded = ''
        while num > 0:
            num, idx = divmod(num, len(alphabet))
            encoded = alphabet[idx] + encoded
        return encoded

    @staticmethod
    def base122_decode(data: str, encoding: str = 'utf-8') -> str:
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&'()*+,-./:;<=>?@[]^_`{|}~"
        value = 0
        for char in data:
            value = value * len(alphabet) + alphabet.index(char)
        byte_length = (value.bit_length() + 7) // 8
        return value.to_bytes(byte_length, 'big').decode(encoding,errors='ignore')

    @staticmethod
    def auto_decode(data: str, encoding: str = 'utf-8') -> List[Dict[str, str]]:
        results = []
        decoders = {
            "base16": BaseCodec.base16_decode,
            "base32": BaseCodec.base32_decode,
            "base45": BaseCodec.base45_decode,
            "base58": BaseCodec.base58_decode,
            "base62": BaseCodec.base62_decode,
            "base64": BaseCodec.base64_decode,
            "base85": BaseCodec.base85_decode,
            "base91": BaseCodec.base91_decode,
            "base92": BaseCodec.base92_decode,
            "base100": BaseCodec.base100_decode,
            "base122": BaseCodec.base122_decode,
        }

        for base_name, decoder in decoders.items():
            try:
                result = decoder(data, encoding)
                # 过滤乱码，只保留 ASCII 可打印字符 + 中文
                # 修改为更宽松的字符输出
                # if re.match(r'^[\x20-\x7E\u4e00-\u9fa5]+$', result):
                # if result and all('\u0020' <= c <= '\uD7FF' or c in ('\n', '\r', '\t') for c in result):
                # if re.match(r'^[\u0020-\uFFFF\uD800-\uDBFF\uDC00-\uDFFF\n\r\t]+$', result):
                results.append({
                    "base": base_name,
                    "result": result
                })
            except Exception:
                continue
        return results

if __name__ == '__main__':
    data = '1111111'
    print(base62.encode(int(data)))
    print(base62.decode("sU7"))