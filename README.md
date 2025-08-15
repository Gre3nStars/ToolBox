# ToolBox ver 1.0.11

1、新增功能

2、修复部分bug

# ToolBox ver 1.0.5

第一个正式版本发布~

# ToolBox

这是由PySide6编写的一个集编解码、普通加解密以及常用小工具于一体的工具箱，只为日常工作使用，工具的实现大部分由AI生成编写。

Q：为什么写这个工具，市面上有很多类似的工具了，如编解码、加解密工具cyberchef非常强大

A：因为使用习惯问题，及一些工具使用频次情况，还有就是页面切换使用习惯问题，当我处理一个编解码或加解密等时，我希望互不干扰，同时使用又方便切换！或不想同时打开N多个软件窗口页面？！

目前已有功能：

1、密码学工具

（1）编解码工具（常用编解码、base系列编解码、HEX、ASCII、HTML转换等）

（2）加解密工具（AES、DES、3DES）

（3）RSA加解密工具（RSA加解密、密钥生成与解析）

（4）MD5工具（各类md5算法密文生成、普通md5爆破、文件hash计算）

（5）HMAC工具

（6）Bcrypt加密工具

（7）国密算法工具

2、开发调试工具

（1）Json处理工具（解析提取对应字段的json数据并导出，格式化输出、树状输出显示）

（2）正则表达式工具（文本正则匹配）

（3）JWT处理工具（json web token解析、生成、爆破密钥，密钥爆破仅支持HS系列）

（4）Hosts修改工具（方便修改hosts）

3、渗透辅助工具

（1）常用命令工具（生成常用的反弹shell或文件上传下载命令）

（2）杀软查询工具（一般般，规则库不够...）

（3）ICP查询工具

（4）子域名查询工具

4、其它小工具

（1）二维码工具（二维码生成和识别，仅支持从文件读取二维码识别）

（2）Unix时间戳工具（Unix时间戳转换~）

（3）IP查询工具（查询IP归属信息，离线为IP纯真库，在线为免费API接口，新增ip138(目前key写死)）

（4）随机字符生成工具（包括随机字符字母数字生成、UUID、GUID、随机个人信息生成器）

（5）IP计算器工具（IP地址转换，子网转换计算）


# 工具目录结构

ToolBoxMainFrame.py 主程序入口

  -utils 工具库目录
  
  -widgets 窗口工具目录
  
ToolBoxMainFrame.spec pyinstaller打包可使用此配置


使用方法：

源代码运行：

1、安装必要的依赖，pip install -r requirements.txt（部分依赖可能还需要运行库，如pyzbar，windows需要vs2013的运行库，mac需要brew install zbar并配置）

2、启动程序：python3 ToolBoxMainFrame.py

打包工具运行：

点击exe启动

ps：Release版本目前使用pyinstaller打包，文件较大~~欢迎提bug~


工具截图：

<img width="1645" height="1059" alt="image" src="https://github.com/user-attachments/assets/9011fd03-8f2b-4e10-8425-d31b0b055278" />












