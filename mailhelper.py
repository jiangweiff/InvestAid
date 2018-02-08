#!/usr/bin/python
# -*- coding: UTF-8 -*-
 
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from email.utils import parseaddr, formataddr
 
my_sender='13386160317@163.com'    # 发件人邮箱账号
my_pass = 'Windows2000'              # 发件人邮箱密码
def sendmail(to, sendername, title, content='AJ'):
    ret=True
    try:
        msg=MIMEText(content,'plain','utf-8')
        msg['From']=formataddr([Header(sendername,'utf-8').encode(),my_sender])  # 括号里的对应发件人邮箱昵称、发件人邮箱账号
        msg['To']=','.join(to)              # 括号里的对应收件人邮箱昵称、收件人邮箱账号
        msg['Subject']=unicode(title, 'utf-8')                # 邮件的主题，也可以说是标题
 
        server=smtplib.SMTP_SSL("smtp.163.com", 465)  # 发件人邮箱中的SMTP服务器，端口是25
        server.login(my_sender, my_pass)  # 括号中对应的是发件人邮箱账号、邮箱密码
        server.sendmail(my_sender,to,msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
        server.quit()  # 关闭连接
    except Exception,e:  # 如果 try 中的语句没有执行，则会执行下面的 ret=False
        print e
        ret=False
    return ret

#sendmail(['17538006@qq.com',], "henda", "henda", "四点七万")
