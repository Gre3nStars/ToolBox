import base64
import binascii
from enum import Enum
from typing import Union, Optional
from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

class PaddingMode(Enum):
    PKCS5 = 'pkcs5'
    ZERO = 'zero'
    NONE = 'none'


class OutputFormat(Enum):
    HEX = 'hex'
    BASE64 = 'base64'


class EncodingType(Enum):
    UTF8 = 'utf-8'
    HEX = 'hex'
    BASE64 = 'base64'


class TripleDESCipher:
    BLOCK_SIZE = 8  # 3DES block size is also 64 bits (8 bytes)

    def __init__(self,
                 key: str,
                 mode: str = 'ECB',
                 padding: Union[str, PaddingMode] = PaddingMode.PKCS5,
                 iv: Optional[str] = None,
                 key_encoding: str = 'utf-8',
                 iv_encoding: str = 'utf-8',
                 output_format: str = OutputFormat.HEX):

        self.key = self._process_key(key, key_encoding)
        print(self.key)
        print(len(self.key))
        if len(self.key) not in (16, 24):
            raise ValueError("3DES key must be 16 or 24 bytes long")

        self.iv = self._process_iv(iv, iv_encoding) if iv else None
        if mode.upper() not in ('ECB', 'CBC'):
            raise ValueError("Only ECB and CBC modes are supported for 3DES")
        self.mode = mode.upper()

        self.padding = PaddingMode(padding.lower()) if isinstance(padding, str) else padding
        self.output_format = OutputFormat(output_format.lower())

    def _process_key(self, key: str, encoding: str) -> bytes:
        enc_type = EncodingType(encoding.lower())
        if enc_type == EncodingType.UTF8:
            raw = key.encode('utf-8')
            if len(raw) < 16:
                raw += b'\x00' * (16 - len(raw))  # 自动补零到 16 字节
            return raw[:24]
        elif enc_type == EncodingType.HEX:
            return binascii.unhexlify(key)
        elif enc_type == EncodingType.BASE64:
            return base64.b64decode(key)
        raise ValueError("Unsupported encoding type")

    def _process_iv(self, iv: str, encoding: str) -> bytes:
        enc_type = EncodingType(encoding.lower())
        if enc_type == EncodingType.UTF8:
            return iv.encode('utf-8')[:8]
        elif enc_type == EncodingType.HEX:
            return binascii.unhexlify(iv)
        elif enc_type == EncodingType.BASE64:
            return base64.b64decode(iv)
        raise ValueError("Unsupported encoding type")

    def _apply_padding(self, data: bytes) -> bytes:
        if self.padding == PaddingMode.PKCS5:
            return pad(data, self.BLOCK_SIZE, style='pkcs7')
        elif self.padding == PaddingMode.ZERO:
            pad_len = self.BLOCK_SIZE - len(data) % self.BLOCK_SIZE
            return data + b'\x00' * pad_len
        elif self.padding == PaddingMode.NONE:
            if len(data) % self.BLOCK_SIZE != 0:
                raise ValueError("Data not padded and length not multiple of block size")
            return data
        raise ValueError("Unsupported padding mode")

    def _remove_padding(self, data: bytes) -> bytes:
        if self.padding == PaddingMode.PKCS5:
            return unpad(data, self.BLOCK_SIZE, style='pkcs7')
        elif self.padding == PaddingMode.ZERO:
            return data.rstrip(b'\x00')
        elif self.padding == PaddingMode.NONE:
            return data
        raise ValueError("Unsupported padding mode")

    def encrypt(self, plaintext: str) -> str:
        data = plaintext.encode('utf-8')

        if self.mode == 'ECB':
            cipher = DES3.new(self.key, DES3.MODE_ECB)
            ciphertext = cipher.encrypt(self._apply_padding(data))
        elif self.mode == 'CBC':
            cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.iv)
            ciphertext = cipher.encrypt(self._apply_padding(data))
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
            cipher = DES3.new(self.key, DES3.MODE_ECB)
            plaintext = cipher.decrypt(data)
        elif self.mode == 'CBC':
            cipher = DES3.new(self.key, DES3.MODE_CBC, iv=self.iv)
            plaintext = cipher.decrypt(data)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

        if self.padding != PaddingMode.NONE:
            plaintext = self._remove_padding(plaintext)

        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt_data(
        data: str,
        key: str,
        mode: str = 'ECB',
        padding: str = 'pkcs5',
        key_encoding: str = 'utf-8',
        iv: Optional[str] = None,
        iv_encoding: str = 'utf-8',
        output_format: str = 'hex'
    ) -> str:
        return TripleDESCipher._process_data(
            data=data,
            key=key,
            mode=mode,
            padding=padding,
            key_encoding=key_encoding,
            iv=iv,
            iv_encoding=iv_encoding,
            output_format=output_format,
            is_encrypt=True
        )

    @staticmethod
    def decrypt_data(
        data: str,
        key: str,
        mode: str = 'ECB',
        padding: str = 'pkcs5',
        key_encoding: str = 'utf-8',
        iv: Optional[str] = None,
        iv_encoding: str = 'utf-8',
        input_format: str = 'hex'
    ) -> str:
        return TripleDESCipher._process_data(
            data=data,
            key=key,
            mode=mode,
            padding=padding,
            key_encoding=key_encoding,
            iv=iv,
            iv_encoding=iv_encoding,
            output_format=input_format,
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
        output_format: str,
        is_encrypt: bool
    ) -> str:
        cipher = TripleDESCipher(
            key=key,
            mode=mode,
            padding=padding,
            key_encoding=key_encoding,
            iv=iv,
            iv_encoding=iv_encoding,
            output_format=output_format
        )
        if is_encrypt:
            return cipher.encrypt(data)
        else:
            return cipher.decrypt(data)
