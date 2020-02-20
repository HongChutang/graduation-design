#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SQL注入检测系统--工具方法
"""

import db_cfg as dbCfg
import MySQLdb


# 获取样本参数集
def get_params():
    conn = MySQLdb.connect(**dbCfg.config)
    cur = conn.cursor()
    cur.execute('SELECT content FROM payload_params')
    results = cur.fetchall()
    payloads = []
    for r in results:
        payloads.append(r[0])

    cur.execute('SELECT content FROM normal_params_final')
    results = cur.fetchall()
    normals = []
    for r in results:
        normals.append(r[0])

    pl_list = []
    for line in payloads:
        line = line.strip('\n')
        pl_list.append(line)

    norm_list = []
    for line in normals:
        line = line.strip('\n')
        norm_list.append(line)

    return {
        'normal': norm_list,
        'payload': pl_list
    }


# 为经过词法分析后所有样本集创建文本训练集
def create_doc_vec(payloads, requires):
    vec = set([])
    for doc in payloads:
        vec = vec | set(doc)
    for doc in requires:
        vec = vec | set(doc)
    return list(vec)


# 为经过词法分析后的每个样本参数生成向量，词集模型
def param_to_vec(vecList, doc):
    return_vec = [0] * len(vecList)
    for word in doc:
        if word in vecList:
            return_vec[vecList.index(word)] = 1
        else:
            print("word is not contained:  " + word)
    return return_vec


if __name__ == '__main__':
    import lexical_analyser

    sample_params = get_params()
    norm_list = sample_params['normal']
    pl_list = sample_params['payload']
    print u'正常样本集总数：', len(norm_list)
    print u'攻击样本集总数：', len(pl_list)

    # 词法分析
    payloads = []
    for pl in pl_list:
        payloads.append(lexical_analyser.analyse(pl))

    requires = []
    for req in norm_list:
        requires.append(lexical_analyser.analyse(req))

    # 为经过词法分析后所有样本集创建文本训练集向量
    vec_list = create_doc_vec(payloads, requires)
    print u'文本训练集向量长度：', len(vec_list)

    # 为经过词法分析后的每个样本参数生成向量，词集模型
    payloads_vec = []
    requires_vec = []
    for payload in payloads:
        payloads_vec.append(param_to_vec(vec_list, payload))
    print u'第一个攻击样本生成的向量：', payloads_vec[0]

    for require in requires:
        requires_vec.append(param_to_vec(vec_list, require))
    print u'第一个正常样本生成的向量：', requires_vec[0]
