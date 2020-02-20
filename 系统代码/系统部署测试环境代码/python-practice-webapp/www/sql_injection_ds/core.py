#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pickle

import time

import word_process as wp
import MySQLdb
import conf as dsConf
import numpy as np
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
import smtplib
import re
import time

# 从dns数据库中获取向量和算法模型，用于后面的预测
vec_list = {}
clf = {}
conn = MySQLdb.connect(**dsConf.db_cfg)
cur = conn.cursor()
try:
    cur.execute('SELECT vec_list_pickle FROM pickle')
    result = cur.fetchall()
    output = open('tmp.pickle', 'wb')
    output.write(result[0][0])
    output.close()
    with open('tmp.pickle', 'rb') as f:
        vec_list = pickle.load(f)
    cur.execute('SELECT clf_pickle FROM pickle')
    result = cur.fetchall()
    output = open('tmp.pickle', 'wb')
    output.write(result[0][0])
    output.close()
    with open('tmp.pickle', 'rb') as f:
        clf = pickle.load(f)
except Exception as e:
    print u'获取向量和模型发生异常：', e
finally:
    # 释放数据连接
    if cur:
        cur.close()
    if conn:
        conn.close()


def get_risk_level(num):
    if num > 20:
        return 4, u'致命'
    if num > 10:
        return 3, u'高危'
    if num > 5:
        return 2, u'中危'
    return 1, u'低危'

total_num = 0
attack_num = 0
predict_total_time = 0.0
predict_aver_time = 0.0
start_time = 0


def outputLog ():
    global total_num
    global attack_num
    global predict_total_time
    global predict_aver_time
    global start_time
    print '攻击总数为', total_num, '; 未检测到的攻击数量为 ', total_num - attack_num
    predict_total_time = predict_total_time + (time.time() - start_time)
    predict_aver_time = predict_total_time / total_num
    print '平均响应时间为', predict_aver_time


def predict(request):
    global total_num
    global predict_total_time
    global predict_aver_time
    global start_time

    start_time = time.time()
    total_num = total_num + 1
    params = request.input().values()[0]
    print "用户输入payload为：", params
    src_ip = request.remote_addr
    print "攻击源IP为：", src_ip
    method = request.request_method
    print "攻击方法为：", method
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
    print "攻击时间戳为：", timestamp
    example = params
    params, keyword_num = wp.changeParams(params)
    print "词法分析后特征数组为：", params
    risk_level, risk_level_text = get_risk_level(keyword_num)
    params = wp.wordToVec(vec_list, params)
    params = np.array(params).reshape((1, -1))
    predict_result = clf.predict(params)[0]
    # if total_num == 100:
    #     total_num = total_num + 1000
    #     attack_num = attack_num + 1000
    #     predict_total_time = predict_total_time + (1000 * predict_aver_time)
    if predict_result == 1:  # 如果检测结果为攻击
        print "判定结果为：攻击威胁"
        print "威胁分级结果：", risk_level_text
        global attack_num
        attack_num = attack_num + 1

        # 如果检测结果为攻击，则将本次样本添加到待确定样本数据表
        conn = MySQLdb.connect(**dsConf.db_cfg)
        cur = conn.cursor()
        try:
            sql = '''CREATE TABLE if NOT EXISTS before_confirm_params(
              id INT AUTO_INCREMENT, 
              content TEXT,
              level VARCHAR(50),
              src_ip VARCHAR(50),
              method VARCHAR(50),
              timestamp VARCHAR(50),
              PRIMARY KEY (id)
            )'''
            save_sql = 'INSERT INTO before_confirm_params(content, level, src_ip, method, timestamp) VALUES(%s, %s, %s, %s, %s);'
            cur.execute(sql)
            cur.execute(save_sql, [example, risk_level, src_ip, method, timestamp])
            conn.commit()
        except Exception as e:
            print u'保存样本参数发生异常：', e
            conn.rollback()
        finally:
            if cur:
                    cur.close()
            if conn:
                conn.close()

        # 发邮件通知管理员
        def _format_addr(s):
            name, addr = parseaddr(s)
            return formataddr(( \
                Header(name, 'utf-8').encode(), \
                addr.encode('utf-8') if isinstance(addr, unicode) else addr))

        from_addr = dsConf.email_cfg['from_addr']
        password = dsConf.email_cfg['password']
        smtp_server = dsConf.email_cfg['smtp_server']
        to_addr = dsConf.email_cfg['to_addr']
        msg = MIMEText('检测到您的网站遭到疑似SQL注入攻击，已为您自动拦截，请登录控制台查看详情。', 'plain', 'utf-8')
        msg['From'] = _format_addr(u'SQL注入检测系统 <%s>' % from_addr)
        msg['Subject'] = Header('[' + risk_level_text + ']'+ u'SQL注入攻击告警', 'utf-8').encode()
        server = smtplib.SMTP_SSL(smtp_server, dsConf.email_cfg['smtp_port'])
        server.set_debuglevel(1)
        server.login(from_addr, password)
        server.sendmail(from_addr, [to_addr], msg.as_string())
        server.quit()
        print "成功发送告警邮件。"
        outputLog()
        return True  # 异常

    # 如果检测结果不是攻击，则将本次样本添加到正常样本训练集
    conn = MySQLdb.connect(**dsConf.db_cfg)
    cur = conn.cursor()
    try:
        save_sql = "INSERT INTO normal_params_final(content) VALUES(%s);"
        cur.execute(save_sql, example)
        conn.commit()
    except Exception as e:
        print u'保存样本参数发生异常：', e
        conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    outputLog()
    return False  # 非异常