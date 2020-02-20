#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SQL注入检测系统--核心运行模块
"""

# 公共模块
import time
import MySQLdb
import pickle
import numpy as np
from sklearn import svm
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import cross_val_score

# 自建模块
import db_cfg
import sample_pretreater as pretreater
import lexical_analyser as analyser
import utils


def compare_valid():

    # -----------------朴素贝叶斯交叉验证-----------
    start = time.time()
    clf = MultinomialNB()
    scores = cross_val_score(clf, X, Y, cv=10, scoring='accuracy')
    print u'用时%f 秒！' % (time.time() - start)
    print u'朴素贝叶斯10重交叉验证评分：', scores
    print u'朴素贝叶斯10重交叉验证平均分：', scores.mean()
    # ------------------end-----------------

    # -----------------svm交叉验证-----------------
    start = time.time()
    clf = svm.SVC(kernel='sigmoid')
    scores = cross_val_score(clf, X, Y, cv=10, scoring='accuracy')
    print u'用时%f 秒！' % (time.time() - start)
    print u'svm10重交叉验证评分：', scores
    print u'svm10重交叉验证平均分：', scores.mean()
    # ------------------end-----------------

    # ----------------KNN交叉验证------------------
    # 取近邻数为4
    start = time.time()
    knn = KNeighborsClassifier(n_neighbors=4)
    scores = cross_val_score(knn, X, Y, cv=10, scoring='accuracy')
    print u'用时%f 秒！' % (time.time() - start)
    print u'近邻数为4的K近邻10重交叉验证评分：', scores
    print u'近邻数为4的K近邻10重交叉验证平均分：', scores.mean()

    # 对比取不同近邻数的效果
    k_range = range(1, 10)
    for k in k_range:
        start = time.time()
        knn = KNeighborsClassifier(n_neighbors=k)
        scores = cross_val_score(knn, X, Y, cv=10, scoring='accuracy')
        print u'用时%f 秒！' % (time.time() - start)
        print u'近邻数为', k,  u'的K近邻10重交叉验证平均分：', scores.mean()
    # ------------------end-----------------


def run():
    # ------------------样本预处理---------------
    pretreater.attack_sample_pretreat()
    pretreater.normal_sample_pretreat()
    # ------------------end---------------

    # ------------------词法分析-----------------
    # 获取两类样本集
    res = utils.get_params()
    norm_list = res['normal']
    pl_list = res['payload']

    payloads = []
    for pl in pl_list:
        payloads.append(analyser.analyse(pl))

    requires = []
    for req in norm_list:
        requires.append(analyser.analyse(req))
    # ------------------end-----------------

    # -------------------向量化------------------
    # 为经过词法分析后所有样本集创建文本训练集向量
    vec_list = utils.create_doc_vec(payloads, requires)

    # 为经过词法分析后的每个样本参数生成向量，词集模型
    payloads_vec = []
    requires_vec = []
    for payload in payloads:
        payloads_vec.append(utils.param_to_vec(vec_list, payload))

    for require in requires:
        requires_vec.append(utils.param_to_vec(vec_list, require))

    # numpy处理一下
    payloads_vec = np.array(payloads_vec)
    requires_vec = np.array(requires_vec)
    # -------------------end------------------

    # ----------生成X和Y用于训练或测试-------------
    # 生成X
    X = np.concatenate((payloads_vec, requires_vec))

    # 生成Y
    Y = []
    for i in range(0, len(payloads_vec)):
        Y.append(1)
    for i in range(0, len(requires_vec)):
        Y.append(0)
    # -------------------end------------------

    # ---------------机器学习算法训练并保存模型-------------
    clf = MultinomialNB()
    start_time = time.time()
    clf.fit(X, Y)
    print u'训练用了%f 秒！' % (time.time() - start_time)

    # 保存模型向量和算法模型到数据库
    vec_list_pickle = pickle.dumps(vec_list)
    clf_pickle = pickle.dumps(clf)

    conn = MySQLdb.connect(**db_cfg.config)
    cur = conn.cursor()

    # 新建数据表
    cur.execute('DROP TABLE IF EXISTS pickle')
    sql = """CREATE TABLE pickle(
                vec_list_pickle TEXT,
                clf_pickle TEXT
               )"""
    cur.execute(sql)

    sql = "INSERT INTO pickle(vec_list_pickle, clf_pickle) VALUES (%s, %s)"
    try:
        cur.execute(sql, (vec_list_pickle, clf_pickle))
        conn.commit()
    except Exception as e:
        print e
        conn.rollback()

    # 释放数据连接
    if cur:
        cur.close()
    if conn:
        conn.close()
    # ---------------end-------------

    # ---------------------查看分类错的样本-----------------
    error_num = 0;
    for i in range(len(X)):
        temp = np.array(X[i]).reshape((1, -1))
        if clf.predict(temp)[0] != Y[i]:
            # 如果预测错误，打印出原文
            if i < len(pl_list):
                print u"将攻击错误分类成正常请求"
                print pl_list[i]
                print payloads[i]
            else:
                print u"将正常请求错误分类成攻击"
                print norm_list[(i - len(pl_list))]
                print requires[(i - len(pl_list))]
            print u'该错误分类样本在整个样本集中的索引为：', i
            error_num = error_num + 1
    print u'分类错误的数量：', error_num
    # ---------------end-------------

    # print u'是否需要进行多种算法的交叉验证结果对比？y(是）/ n（否）：'
    # while True:
    #     input = raw_input()
    #     if input.lower() == 'y':
    #         compare_valid()
    #         break
    #     elif input.lower() == 'n':
    #         break
    #     print u'输入错误，请重新输入：'


if __name__ == '__main__':
    run()
