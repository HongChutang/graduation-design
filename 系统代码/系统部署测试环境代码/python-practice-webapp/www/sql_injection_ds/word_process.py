#!/usr/bin/env python
# -*- coding: utf-8 -*-

# 正则
import re
import os

# 读取关键词列表
f_key = open(os.path.join(os.path.join(os.path.abspath('.'), 'sql_injection_ds'), 'key_list.txt'))

# 把关键词生成数组
key_list = []
for line in f_key.readlines():
    line = line.strip('\n')
    key_list.append(line)

# 检测是否有数字的正则
has_num = re.compile(r'[0-9]')


# 定义转化函数
def changeParams(payload):
    payload = payload.lower()
    p_list = []
    keyword_num = 0

    # 是否是关键字
    for word in key_list:
        while word in payload:
            start = payload.find(word)
            end = start + len(word)
            if start != 0 and end != len(payload): # 中间的单词
                if isStrangeChr(payload[start - 1]) and isStrangeChr(payload[end]):
                    p_list.append(word)
                    payload = payload[:start] + payload[end:]
                else:
                    payload = payload[:start] + payload[end:]
            elif start == 0 and end != len(payload): # 起始的单词
                if isStrangeChr(payload[end]):
                    p_list.append(word)
                    payload = payload[:start] + payload[end:]
                else:
                    payload = payload[:start] + payload[end:]
            else: # 末尾的单词
                if isStrangeChr(payload[start - 1]):
                    p_list.append(word)
                    payload = payload[:start] + payload[end:]
                else:
                    payload = payload[:start] + payload[end:]

            keyword_num = keyword_num + 1

    # 特殊字符转化
    for i in payload:
        ascii = ord(i)
        if ascii < 48 and ascii != 32 or 57 < ascii < 65 or 90 < ascii < 95 or 95 < ascii < 97 or ascii > 122:
            # if(('ascii'+ str(ascii)) not in p_list): # 去重
            p_list.append('ascii' + str(ascii))
            if i != " ":
                payload = payload.replace(i, "")

    # 16进制转化
    payload = re.split(r'\s+', payload)
    for word in payload:
        if word[0:2] == "0x":
            p_list.append("16hex")
            payload.remove(word)

    # 如果还剩下东西，那就是normal_word或者normal_num了
    for word in payload:
        if has_num.match(word):
            p_list.append("normal_num")
        else:
            p_list.append("normal_word")
    return p_list, keyword_num


# 函数：为每一个训练样本生成一个向量，词集模型
def wordToVec(vecList, doc):
    return_vec = [0] * len(vecList)
    for word in doc:
        if word in vecList:
            return_vec[vecList.index(word)] = 1
        else:
            print("word is not contained:  " + word)
    return return_vec


# 判断是否是非常规字符（非数字和字母）
def isStrangeChr(char):
    temp = ord(char)
    if 47 < temp < 58 or 64 < temp < 91 or 96 < temp < 123:
        return False
    else:
        return True
