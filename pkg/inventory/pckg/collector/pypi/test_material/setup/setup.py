#!/usr/bin/env python

# coding=utf-8

from setuptools import setup

setup(

 name="abc", #pypi中的名称，pip或者easy_install安装时使用的名称

 version="1.0",

 author="abc",

 author_email="abc",

 description=("abc"),

 keywords="abc",

 packages=['abc'],


 # 需要安装的依赖

 install_requires=[

  'redis==2.10.5',

  'setuptools==16.0',

  " request2 == 2.0.2", ' url== 0.4.2',

 ],

)