#!/usr/bin/python
# -*- coding: UTF-8 -*-
#coding=utf-8

import MySQLdb



def CreateTableOTX():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX`(
		`id` int UNSIGNED AUTO_INCREMENT,
		`otx_id` varchar(100),
		`sid` varchar(100),
		`industries` varchar(100),
		`tlp` varchar(100),
		`description` varchar(2000),
		`name` varchar(200),
		`tags` varchar(100),
		`adversary` varchar(100),
		`created` date,
		`modified` date,
		`author_name` varchar(100),
		`extract_source` varchar(100),
		`reference` varchar(100),
		`targeted_countries` varchar(100),
		`indicators` varchar(100),
		PRIMARY KEY ( `id` )
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()
	
def CreateTable_OTX_industries():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX_industries`(
		`industrie_id` int UNSIGNED AUTO_INCREMENT,
		`industries` varchar(200),
		`otx_id` varchar(100),
		PRIMARY KEY (`industrie_id`)
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()
	
def CreateTable_OTX_tag():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX_tag`(
		`tag_id` int UNSIGNED AUTO_INCREMENT,
		`tag` varchar(50),
		`otx_id` varchar(100),
		PRIMARY KEY (`tag_id`)
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()

def CreateTable_OTX_extract_source():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX_extract_source`(
		`extract_source_id` int UNSIGNED AUTO_INCREMENT,
		`extract_source` varchar(100),
		`otx_id` varchar(100),
		PRIMARY KEY ( `extract_source_id` )
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()
	
def CreateTable_OTX_reference():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX_reference`(
		`reference_id` int UNSIGNED AUTO_INCREMENT,
		`reference` varchar(200),
		`otx_id` varchar(100),
		PRIMARY KEY ( `reference_id` )
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()

def CreateTable_OTX_targeted_countries():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX_targeted_countries`(
		`country_id` int UNSIGNED AUTO_INCREMENT,
		`country` varchar(100),
		`otx_id` varchar(100),
		PRIMARY KEY ( `country_id` )
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()

def CreateTable_OTX_indicators():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )
	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	# 创建数据表OTX SQL语句
	sql="""create table `OTX_indicators`(
		`indicator_id` int UNSIGNED AUTO_INCREMENT,
		`indicator` varchar(200),
		`description` varchar(500),
		`title` varchar(100),
		`created` date,
		`content` varchar(100),
		`type` varchar(50),
		`otx_id` varchar(100),
		PRIMARY KEY ( `indicator_id` )
	)ENGINE=InnoDB DEFAULT CHARSET=utf8;
	"""
	data = cursor.execute(sql)
	# 关闭数据库连接
	db.close()
	
def deltable():
	# 打开数据库连接
	db = MySQLdb.connect("192.168.1.104", "root", "root", "zr", charset='utf8' )

	# 使用cursor()方法获取操作游标 
	cursor = db.cursor()
	#删除表
	sql="drop table OTX,otx_extract_source,otx_indicators,otx_industries,otx_reference,otx_tag,otx_targeted_countries;"
	data = cursor.execute(sql)
	print("删除成功")
	# 关闭数据库连接
	db.close()
	
def insert_otx(db,cursor,otx_id,sid,industrie,tlp,description,name,tag,adversary,created,modified,author_name,extract_source,detail,country):

	#创建插入语句
	sql="INSERT INTO OTX(otx_id,sid,industries,tlp,description,name,tags,adversary,created,modified,author_name,extract_source,reference,targeted_countries,indicators) VALUES (" + otx_id +"," + sid + "," + industrie + "," + tlp + "," + description + "," + name + "," + tag + "," + adversary + "," + created + "," + modified + "," + author_name + "," + extract_source+ "," + detail + "," + country + "," + otx_id + ")"
	try:
		# 执行sql语句
		cursor.execute(sql)
		# 提交到数据库执行
		db.commit()
	except:
		# 发生错误时回滚
		db.rollback()
		
def insert_OTX_tag(db,cursor,tag,otx_id):
	#创建插入语句
	sql="INSERT INTO OTX_tag(tag,otx_id) VALUES (" + tag + "," + otx_id +")"
	try:
		# 执行sql语句
		cursor.execute(sql)
		# 提交到数据库执行
		db.commit()
	except:
		# 发生错误时回滚
		db.rollback()
		
def insert_otx_reference(db,cursor,reference,otx_id):
	#创建插入语句
	sql="INSERT INTO otx_reference(reference,otx_id) VALUES (" + reference + "," + otx_id +")"
	try:
		# 执行sql语句
		cursor.execute(sql)
		# 提交到数据库执行
		db.commit()
	except:
		# 发生错误时回滚
		db.rollback()

def insert_otx_indicators(db,cursor,otx_indicator,otx_description,otx_title,otx_created,otx_content,otx_type,otx_id):
	#创建插入语句
	sql="INSERT INTO otx_indicators(indicator,description,title,created,content,type,otx_id) VALUES (" + otx_indicator + "," + otx_description +"," + otx_title +"," + otx_created +"," + otx_content +"," + otx_type +"," + otx_id +")"
	try:
		# 执行sql语句
		cursor.execute(sql)
		# 提交到数据库执行
		db.commit()
	except:
		# 发生错误时回滚
		db.rollback()
