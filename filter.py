#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os
import xlrd
import shutil
import time

num = 0

def classify(execelPath, ransomPath, newRootDir):
    data = xlrd.open_workbook(execelPath)
    table = data.sheet_by_name(u'Sheet1')
    nrows = table.nrows
    print nrows
    countNotExists = 0
    for i in xrange(1, nrows):
        ransomHash = table.cell(i,3).value
        ransomType = table.cell(i,4).value
        ransomHash = ransomHash.strip()
        if ransomType != 0.0:
            ransomType = ransomType.strip().lower()
        else:
            ransomType = '0'
        ransomTotalPath = ransomPath + '\\' +ransomHash
        if os.path.exists(ransomTotalPath):
            newFilePath = newRootDir + '\\' + ransomType
            if(os.path.exists(newFilePath) == False):
                os.makedirs(newFilePath)
            shutil.copy(ransomTotalPath, newFilePath)
        else:
            countNotExists += 1
            print ransomHash
    return countNotExists


def filesCount(rootDir):
    global num
    for lists in os.listdir(rootDir): 
        path = os.path.join(rootDir, lists) 
        if os.path.isfile(path):
            num += 1
        if os.path.isdir(path): 
            filesCount(path)


execelPath = 'C:\\Users\\wxr\\Desktop\\samples(new_version).xlsx'
ransomPath = 'C:\\Users\\wxr\\Desktop\\virustotal\\virus'
newRootDir = 'C:\\Users\\wxr\\Desktop\\ransomclassify2323'
#print classify(execelPath, ransomPath, newRootDir)

filesCount(newRootDir)
print num
notInTableList = []

def getInTableList(execelPath):
    data = xlrd.open_workbook(execelPath)
    table = data.sheet_by_name(u'Sheet1')
    inTableList = table.col_values(3)
    return inTableList

def getNotInTableList(ransomPath, inTableList):
    global notInTableList
    for lists in os.listdir(ransomPath): 
        path = os.path.join(ransomPath, lists)
        if os.path.isfile(path):
            ransomeName = path.split('\\').pop()
            ransomeName.strip()
            if ransomeName not in inTableList:
                notInTableList.append(ransomeName)
        if os.path.isdir(path): 
            getNotInTableList(path, inTableList)

#inTableList = getInTableList("C:\\Users\\wxr\\Desktop\\samples.xlsx")
#getNotInTableList(newRootDir, inTableList)
#print len(notInTableList)
#for item in notInTableList:
#    print item
files = []
def getFiles(ransomPath):
    global files
    for lists in os.listdir(ransomPath): 
        path = os.path.join(ransomPath, lists)
        if os.path.isfile(path):
            ransomeName = path.split('\\').pop()
            ransomeName.strip()
            files.append(ransomeName)
        if os.path.isdir(path): 
            getFiles(path)


def findNo(execelPath, files):
    data = xlrd.open_workbook(execelPath)
    table = data.sheet_by_name(u'Sheet1')
    inTableList = table.col_values(3)
    for item in inTableList:
        item = item.strip()
        if item not in files:
            print item
    
#getFiles(newRootDir)
#print len(files)
#findNo("C:\\Users\\wxr\\Desktop\\samples.xlsx", files)

def raped(execelPath):
    index = 0
    hashValues = []
    data = xlrd.open_workbook(execelPath)
    table = data.sheet_by_name(u'Sheet1')
    nrows = table.nrows
    for i in xrange(1, nrows):
        ransomHash = table.cell(i,3).value
        if ransomHash in hashValues:
            print ransomHash
            index += 1
        else:
            hashValues.append(ransomHash)
    return index

#print raped('C:\\Users\\wxr\\Desktop\\samples.xlsx')

