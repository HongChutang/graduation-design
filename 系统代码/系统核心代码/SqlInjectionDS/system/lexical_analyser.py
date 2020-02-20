#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SQL注入检测系统--词法分析器模块
"""

import re
import os

# 匹配还有数字的字符串的正则
_RE_INCLUDE_NUM = re.compile(r'[0-9]')


# 从文件中读取关键词
_key_list = []
f_key = open(os.path.join(os.path.join(os.path.dirname(__file__), 'data_src'), 'key_list.txt'))
for line in f_key.readlines():
    _key_list.append(line.strip('\n'))


# 判断是否是非常规字符（非数字和字母）
def _is_strange_chr(char):
    temp = ord(char)
    if 47 < temp < 58 or 64 < temp < 91 or 96 < temp < 123:
        return False
    else:
        return True


# 分析器主方法
def analyse(payload):
    payload = payload.lower()
    p_list = []

    # 关键字抽取
    for word in _key_list:
        while word in payload:
            start = payload.find(word)
            end = start + len(word)
            if start != 0 and end != len(payload):  # 中间的单词
                if _is_strange_chr(payload[start - 1]) and _is_strange_chr(payload[end]):
                    p_list.append(word)
                    payload = payload[:start] + payload[end:]
                else:
                    payload = payload[:start] + payload[end:]
            elif start == 0 and end != len(payload):  # 起始的单词
                if _is_strange_chr(payload[end]):
                    p_list.append(word)
                    payload = payload[:start] + payload[end:]
                else:
                    payload = payload[:start] + payload[end:]
            else:  # 末尾的单词
                if _is_strange_chr(payload[start - 1]):
                    p_list.append(word)
                    payload = payload[:start] + payload[end:]
                else:
                    payload = payload[:start] + payload[end:]

    # 特殊字符转化
    for i in payload:
        ascii = ord(i)
        if ascii < 48 and ascii != 32 or 57 < ascii < 65 or 90 < ascii < 95 or 95 < ascii < 97 or ascii > 122:
            p_list.append('ascii' + str(ascii))
            if i != " ":
                payload = payload.replace(i, "")

    # 16进制转化
    payload = re.split(r'\s+', payload)
    for word in payload:
        if word[0:2] == "0x":
            p_list.append("16hex")
            payload.remove(word)

    # 剩下就是normal_word或者normal_num
    for word in payload:
        if _RE_INCLUDE_NUM.match(word):
            p_list.append("normal_num")
        else:
            p_list.append("normal_word")
    return p_list


if __name__ == '__main__':
    import utils

    sample_params = utils.get_params()
    norm_list = sample_params['normal']
    pl_list = sample_params['payload']

    payloads = []
    for pl in pl_list:
        payloads.append(analyse(pl))
    print len(payloads)
    print payloads[0]

    requires = []
    for req in norm_list:
        requires.append(analyse(req))
    print len(requires)
    print requires[0]
