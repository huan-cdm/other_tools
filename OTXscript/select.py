#!/usr/bin/python
# -*- coding: UTF-8 -*-

import MySQLdb
import os
import sys


reload(sys)
sys.setdefaultencoding("utf-8")
# 打开数据库连接
db = MySQLdb.connect("localhost", "root", "", "zr", charset='utf8' )
# 使用cursor()方法获取操作游标 
cursor = db.cursor()
#输入查询条件如：'sid > 50000000'
where = input("Please input where...   ")
print where
# SQL 查询语句
sql = "select * from otx where " + where

#输入文件名如：'filename.txt'
filename = input("Please input filename.txt...   ")
print filename
#打开文件
file = open(filename,'w+')

try:
    cursor.execute(sql)
    results = cursor.fetchall()
    for row in results:
        id = row [0]
        sid = row[2]
        name = row [6]
        adversary = row [8]
        referrence = row [13]
        targeted_countries = row [14]
        indicators = row [15]
        #查询MD5
        sql_hash = 'select * from otx_indicators where type = "FileHash-MD5" and otx_id = ' + '"' + indicators + '"'
        try:
            cursor.execute(sql_hash)
            hashs = cursor.fetchall()
            MD5s = []
            for hash in hashs:
                MD5 = '"' + hash [1] + '"'
                MD5s.append(MD5)
        except:
            print "Error: unable to fecth data MD5"

        #查询domain
        sql_hash = 'select * from otx_indicators where type = "domain" or type = "hostname" and otx_id = ' + '"' + indicators + '"'
        try:
            cursor.execute(sql_hash)
            hashs = cursor.fetchall()
            Domains = []
            for hash in hashs:
                Domain = '"' + hash [1] + '"'
                Domains.append(Domain)
        except:
            print "Error: unable to fecth data Domain"

        #查询IPv4
        sql_hash = 'select * from otx_indicators where type = "IPv4" and otx_id = ' + '"' + indicators + '"'
        try:
            cursor.execute(sql_hash)
            hashs = cursor.fetchall()
            IPv4s = []
            for hash in hashs:
                IPv4 = '"' + hash [1] + '"'
                IPv4s.append(IPv4)
        except:
            print "Error: unable to fecth data IPv4s"

        if MD5s != None:
            MD5 = '[' + ','.join(MD5s) + ']'
        else:
            MD5 = '[]'

        if Domains != None:
            Domain = '[' + ','.join(Domains) + ']'
        else:
            Domain = '[]'
        
        if IPv4s != None:
            IPv4 = '[' + ','.join(IPv4s) + ']'
        else:
            IPv4 = '[]'

        # 打印结果
        data ='{' + '"sid":' + '"' + sid + '"' + "," + '"name":' + '"' + name + '"' + "," + '"adversary":' + '"' + adversary + '"' + "," + '"referrence":' + '"' + referrence + '"' + "," + '"country":' + '"' + targeted_countries + '"' + "," + '"hash":' + '"' + MD5 + '"' + "," + '"IPv4":' + '"' + IPv4 + "," + '"Domain":' + '"' + Domain + '"''}'
        print data
        #print sql_hash
        file.write(data + '\n')
    file.close
except:
    print "Error: unable to fecth data"

# 关闭数据库连接
db.close()



