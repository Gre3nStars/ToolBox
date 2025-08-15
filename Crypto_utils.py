from gmssl import sm2, sm3, sm4, func
import os

# SM2 密钥对生成
def sm2_generate_keypair():
    private_key = func.random_hex(sm2.SM2_PRIVATE_KEY_LEN)
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key=None)
    public_key = sm2_crypt._kg(int(private_key, 16), sm2_crypt.ecc_table['g'])
    return private_key, public_key

# SM2 加密
def sm2_encrypt(public_key, data: bytes) -> bytes:
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key='')
    return sm2_crypt.encrypt(data)

# SM2 解密
def sm2_decrypt(private_key, data: bytes) -> bytes:
    sm2_crypt = sm2.CryptSM2(public_key='', private_key=private_key)
    return sm2_crypt.decrypt(data)

# SM2 签名
def sm2_sign(private_key, data: bytes) -> str:
    sm2_crypt = sm2.CryptSM2(public_key='', private_key=private_key)
    return sm2_crypt.sign(data, func.random_hex(sm2.SM2_PRIVATE_KEY_LEN))

# SM2 验签
def sm2_verify(public_key, data: bytes, signature: str) -> bool:
    sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key='')
    return sm2_crypt.verify(signature, data)

# SM3 摘要
def sm3_digest(data: bytes) -> str:
    return sm3.sm3_hash(func.bytes_to_list(data))

# SM4 ECB 加密
def sm4_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
    return crypt_sm4.crypt_ecb(data)

# SM4 ECB 解密
def sm4_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
    return crypt_sm4.crypt_ecb(data)

# SM4 CBC 加密
def sm4_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(key, sm4.SM4_ENCRYPT)
    return crypt_sm4.crypt_cbc(iv, data)

# SM4 CBC 解密
def sm4_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(key, sm4.SM4_DECRYPT)
    return crypt_sm4.crypt_cbc(iv, data)
