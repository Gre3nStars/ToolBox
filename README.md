# ToolBox ver 1.0
这是由PySide6开发的一个集编解码、普通加解密以及常用小工具于一体的工具箱，只为日常工作使用，工具的实现大部分由AI生成编写。

Q：为什么写这个工具，市面上有很多类似的工具了，如编解码、加解密工具cyberchef非常强大

A：因为使用习惯问题，及一些工具使用频次情况，还有就是页面切换使用习惯问题，当我处理一个编解码或加解密等时，我希望互不干扰，同时使用又方便切换！

目前已有功能：

1、密码学工具

（1）编解码工具（常用编解码、base系列编解码、HEX、ASCII、HTML转换等）

（2）加解密工具（AES、DES、3DES）

（3）RSA加解密工具（RSA加解密、密钥生成与解析）

（4）MD5工具（各类md5算法密文生成、普通md5爆破、文件hash计算）

2、开发调试工具

（1）Json处理工具（解析提取对应字段的json数据并导出，格式化输出、树状输出显示）

（2）正则表达式工具（文本正则匹配）

（3）JWT处理工具（json web token解析、生成、爆破密钥，密钥爆破仅支持HS系列）

（4）Hosts修改工具（方便修改hosts）

3、渗透辅助工具

（1）常用命令工具（生成常用的反弹shell或文件上传下载命令）

4、其它小工具

（1）二维码工具（二维码生成和识别，仅支持从文件读取二维码识别）

（2）Unix时间戳工具（Unix时间戳转换~）



使用方法：

1、安装必要的依赖，pip install -r requirements.txt（部分依赖可能还需要运行库，如pyzbar，windows需要vs2013的运行库，mac需要brew install zbar并配置）

2、启动程序：python3 ToolBoxMainFrame.py

工具截图：

<img width="1649" height="1047" alt="image" src="https://github.com/user-attachments/assets/db0b5ad6-2acf-46c0-bbe9-8014e8eeedc4" />

<img width="1642" height="1051" alt="image" src="https://github.com/user-attachments/assets/5775afa5-d0ea-44b5-9696-34f852d909ff" />

<img width="1649" height="1049" alt="image" src="https://github.com/user-attachments/assets/17302d83-fff9-4de8-8ffa-e370f5d65b1e" />

<img width="1646" height="1046" alt="image" src="https://github.com/user-attachments/assets/332ce6bc-6a58-4e78-89fe-912932058b0d" />

<img width="1649" height="1045" alt="image" src="https://github.com/user-attachments/assets/5375ebb9-7af4-4f0a-ab45-8a5be039712c" />







