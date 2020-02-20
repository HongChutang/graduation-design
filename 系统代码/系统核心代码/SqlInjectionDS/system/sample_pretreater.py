#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SQL注入检测系统--样本数据预处理器模块
"""

import re
import urllib
import MySQLdb
import os

import db_cfg as db_cfg


def normal_sample_pretreat():
    # 打开文件
    f = open(os.path.join(os.path.join(os.path.dirname(__file__), 'data_src'), 'access_log_normal_require.html'))

    # 匹配链接
    link_pattern = re.compile(r'(href=".*?\")')
    links = []
    for line in f.readlines():
        links = link_pattern.findall(line)

    # 匹配参数值
    paras = []
    para_pattern = re.compile(r'(\=.*?&amp;)')
    # 链接修剪并匹配
    for link in links:
        # 修剪
        link = link[6:-1]
        # 匹配
        paraList = para_pattern.findall(link)
        for para in paraList:
            paras.append(urllib.unquote(para[1:-5]))  # url转码

    # 写入数据库
    conn = MySQLdb.connect(**db_cfg.config)
    cur = conn.cursor()

    # 新建数据表
    cur.execute('DROP TABLE IF EXISTS normal_params')
    sql = """CREATE TABLE normal_params( 
            id INT AUTO_INCREMENT, 
            content TEXT,
            PRIMARY KEY (id)
            )"""
    cur.execute(sql)
    add_list = []
    sql = "INSERT INTO normal_params(content) VALUES(%s);"

    # 每满1000插入数据库
    for index, item in enumerate(paras):
        innerList = [item]
        add_list.append(innerList)
        if (index + 1) % 1000 == 0:
            try:
                cur.executemany(sql, add_list)
                conn.commit()
                add_list = []
            except Exception as e:
                print u'发生异常', e
                conn.rollback()

    # 将剩余插入数据库
    try:
        cur.executemany(sql, add_list)
        conn.commit()
    except:
        print u'发生异常', Exception
        conn.rollback()

    # 释放数据连接
    if cur:
        cur.close()
    if conn:
        conn.close()


def attack_sample_pretreat():
    f = open(os.path.join(os.path.join(os.path.dirname(__file__), 'data_src'), 'access_log_payload.txt'))

    # 目标字符串正则
    lkp = re.compile(r'\?.*?HTTP')
    # 逐行匹配并进行提取和转码
    payloads = []
    for line in f.readlines():
        result = lkp.findall(line)
        if result:
            pl = re.sub(r'\?.*?\=', '', result[0])
            pl = re.sub(r' HTTP', '', pl)
            pl = urllib.unquote(pl)  # url转码
            payloads.append(pl)

    # 写入数据库
    conn = MySQLdb.connect(**db_cfg.config)
    cur = conn.cursor()

    # 新建数据表
    cur.execute('DROP TABLE IF EXISTS payload_params')
    sql = """CREATE TABLE payload_params( 
            id INT AUTO_INCREMENT, 
            content TEXT,
            PRIMARY KEY (id)
            )"""
    cur.execute(sql)
    add_list = []
    sql = "INSERT INTO payload_params(content) VALUES(%s);"

    # 每满1000插入数据库
    for index, item in enumerate(payloads):
        inner_list = [item]
        add_list.append(inner_list)
        if (index + 1) % 1000 == 0:
            try:
                cur.executemany(sql, add_list)
                conn.commit()
                add_list = []
            except Exception as e:
                print u'发生异常', e
                conn.rollback()

    # 将剩余插入数据库
    try:
        cur.executemany(sql, add_list)
        conn.commit()
    except:
        print u'发生异常', Exception
        conn.rollback()

    # 释放数据连接
    if cur:
        cur.close()
    if conn:
        conn.close()


if __name__ == '__main__':
    normal_sample_pretreat()
    attack_sample_pretreat()
