import base64
import binascii
from enum import Enum
from typing import Union, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter


class PaddingMode(Enum):
    PKCS7 = 'pkcs7'
    PKCS5 = 'pkcs5'
    ZERO = 'zero'
    NONE = 'none'
    ISO10126 = 'iso10126'


class OutputFormat(Enum):
    HEX = 'hex'
    BASE64 = 'base64'


class EncodingType(Enum):
    UTF8 = 'utf-8'
    HEX = 'hex'
    BASE64 = 'base64'


class AESCipher:
    def __init__(self,
                 key: str,
                 mode: str = 'CBC',
                 padding: Union[str, PaddingMode] = PaddingMode.PKCS7,
                 iv: Optional[str] = None,
                 encoding: str = EncodingType.UTF8,
                 block_size: int = 128,
                 output_format: str = OutputFormat.HEX):

        self.block_size = block_size // 8  # in bytes
        self.key = self._process_key(key, encoding)
        self.iv = self._process_iv(iv, encoding) if iv else None
        self.mode = mode.upper()
        self.padding = PaddingMode(padding.lower()) if isinstance(padding, str) else padding
        # self.output_format = OutputFormat(output_format.lower())
        if isinstance(output_format, str):
            self.output_format = OutputFormat(output_format.lower())
        else:
            self.output_format = output_format

    def _process_key(self, key: str, encoding: str) -> bytes:
        # 错误写法 ❌
        # enc_type = EncodingType(encoding.lower())
        # 正确写法 ✅
        if isinstance(encoding, str):
            enc_type = EncodingType(encoding.lower())
        else:
            enc_type = encoding

        if enc_type == EncodingType.UTF8:
            return key.encode('utf-8')[:self.block_size]
        elif enc_type == EncodingType.HEX:
            return binascii.unhexlify(key)
        elif enc_type == EncodingType.BASE64:
            return base64.b64decode(key)
        raise ValueError("Unsupported encoding type")

    def _process_iv(self, iv: str, encoding: str) -> bytes:
        if isinstance(encoding, str):
            enc_type = EncodingType(encoding.lower())
        else:
            enc_type = encoding
        if enc_type == EncodingType.UTF8:
            return iv.encode('utf-8')[:self.block_size]
        elif enc_type == EncodingType.HEX:
            return binascii.unhexlify(iv)
        elif enc_type == EncodingType.BASE64:
            return base64.b64decode(iv)
        raise ValueError("Unsupported encoding type")

    def _apply_padding(self, data: bytes) -> bytes:
        if self.padding in (PaddingMode.PKCS7, PaddingMode.PKCS5):
            return pad(data, self.block_size, style='pkcs7')
        elif self.padding == PaddingMode.ZERO:
            pad_len = self.block_size - len(data) % self.block_size
            return data + b'\x00' * pad_len
        elif self.padding == PaddingMode.ISO10126:
            return pad(data, self.block_size, style='randomized')
        elif self.padding == PaddingMode.NONE:
            if len(data) % self.block_size != 0:
                raise ValueError("Data not padded and length not multiple of block size")
            return data
        raise ValueError("Unsupported padding mode")

    def _remove_padding(self, data: bytes) -> bytes:
        if self.padding in (PaddingMode.PKCS7, PaddingMode.PKCS5):
            return unpad(data, self.block_size, style='pkcs7')
        elif self.padding == PaddingMode.ZERO:
            return data.rstrip(b'\x00')
        elif self.padding == PaddingMode.ISO10126:
            return unpad(data, self.block_size, style='randomized')
        elif self.padding == PaddingMode.NONE:
            return data
        raise ValueError("Unsupported padding mode")

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode('utf-8')

        if self.mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            ciphertext = cipher.encrypt(self._apply_padding(data))
        elif self.mode == 'CBC':
            cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
            ciphertext = cipher.encrypt(self._apply_padding(data))
        elif self.mode == 'CFB':
            cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=128)
            ciphertext = cipher.encrypt(data)
        elif self.mode == 'OFB':
            cipher = AES.new(self.key, AES.MODE_OFB, iv=self.iv)
            ciphertext = cipher.encrypt(data)
        elif self.mode == 'CTR':
            counter = Counter.new(64, prefix=self.iv[:8], initial_value=0)
            cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
            ciphertext = cipher.encrypt(data)
        elif self.mode == 'GCM':
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.iv)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            # Combine encrypted data and tag
            ciphertext = ciphertext + tag
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

        if self.output_format == OutputFormat.HEX:
            return binascii.hexlify(ciphertext).decode('utf-8')
        elif self.output_format == OutputFormat.BASE64:
            return base64.b64encode(ciphertext).decode('utf-8')
        else:
            raise ValueError("Unsupported output format")

    def decrypt(self, ciphertext: str) -> str:
        if self.output_format == OutputFormat.HEX:
            data = binascii.unhexlify(ciphertext)
        elif self.output_format == OutputFormat.BASE64:
            data = base64.b64decode(ciphertext)
        else:
            raise ValueError("Unsupported input format")

        if self.mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            plaintext = cipher.decrypt(data)
        elif self.mode == 'CBC':
            cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
            plaintext = cipher.decrypt(data)
        elif self.mode == 'CFB':
            cipher = AES.new(self.key, AES.MODE_CFB, iv=self.iv, segment_size=128)
            plaintext = cipher.decrypt(data)
        elif self.mode == 'OFB':
            cipher = AES.new(self.key, AES.MODE_OFB, iv=self.iv)
            plaintext = cipher.decrypt(data)
        elif self.mode == 'CTR':
            counter = Counter.new(64, prefix=self.iv[:8], initial_value=0)
            cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
            plaintext = cipher.decrypt(data)
        elif self.mode == 'GCM':
            # Split the tag from the end
            tag = data[-16:]
            cipher_data = data[:-16]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=self.iv)
            plaintext = cipher.decrypt_and_verify(cipher_data, tag)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

        if self.padding != PaddingMode.NONE:
            plaintext = self._remove_padding(plaintext)

        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt_data(
            data: str,
            key: str,
            mode: str = 'CBC',
            padding: str = 'pkcs7',
            key_encoding: str = 'utf-8',
            iv: Optional[str] = None,
            iv_encoding: str = 'utf-8',
            block_size: int = 128,
            output_format: str = 'hex'
    ) -> str:
        return AESCipher._process_data(
            data=data,
            key=key,
            mode=mode,
            padding=padding,
            key_encoding=key_encoding,
            iv=iv,
            iv_encoding=iv_encoding,
            block_size=block_size,
            output_format=output_format,
            is_encrypt=True
        )

    @staticmethod
    def decrypt_data(
            data: str,
            key: str,
            mode: str = 'CBC',
            padding: str = 'pkcs7',
            key_encoding: str = 'utf-8',
            iv: Optional[str] = None,
            iv_encoding: str = 'utf-8',
            block_size: int = 128,
            input_format: str = 'hex'
    ) -> str:
        return AESCipher._process_data(
            data=data,
            key=key,
            mode=mode,
            padding=padding,
            key_encoding=key_encoding,
            iv=iv,
            iv_encoding=iv_encoding,
            block_size=block_size,
            output_format=input_format,  # 复用 output_format 字段作为输入格式
            is_encrypt=False
        )

    @staticmethod
    def _process_data(
            data: str,
            key: str,
            mode: str,
            padding: str,
            key_encoding: str,
            iv: Optional[str],
            iv_encoding: str,
            block_size: int,
            output_format: str,
            is_encrypt: bool
    ) -> str:
        """
        统一处理加密/解密的内部方法。
        """
        cipher = AESCipher(
            key=key,
            mode=mode,
            padding=padding,
            iv=iv,
            encoding=key_encoding,  # 可复用 key_encoding 作为默认编码
            block_size=block_size,
            output_format=output_format
        )

        if is_encrypt:
            return cipher.encrypt(data)
        else:
            return cipher.decrypt(data)

if __name__ == '__main__':
    # 示例参数
    key = "1234567890abcdef1234567890abcdef"  # 16字节
    iv = "1234567890abcdef"
    data = "Hello, World!"

    # 创建加密器
    aes = AESCipher(
        key=key,
        iv=iv,
        mode='ECB',
        padding=PaddingMode.NONE,
        block_size=128,
        encoding="hex",
        output_format=OutputFormat.BASE64
    )

    # 加密
    encrypted = aes.encrypt(data)
    print("Encrypted:", encrypted)

    # 解密
    decrypted = aes.decrypt(encrypted)
    # print("Decrypted:", decrypted)