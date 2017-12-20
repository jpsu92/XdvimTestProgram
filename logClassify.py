# -*- coding: UTF-8 -*-

import os
import xlrd
import shutil


def classify(execelPath, ransomPath, newRootDir):
    data = xlrd.open_workbook(execelPath)
    table = data.sheet_by_name(u'Sheet1')
    nrows = table.nrows
    for i in xrange(1, nrows):
        ransomHash = table.cell(i, 3).value
        ransomType = table.cell(i, 4).value
        ransomHash = ransomHash.strip()
        if ransomType != 0.0:
            ransomType = ransomType.strip().lower()
        else:
            ransomType = '0'
        ransomTotalPath = ransomPath + '\\' + ransomHash + '.log'
        print ransomTotalPath
        if os.path.exists(ransomTotalPath):
            newFilePath = newRootDir + '\\' + ransomType
            if not os.path.exists(newFilePath):
                os.makedirs(newFilePath)
            shutil.copy(ransomTotalPath, newFilePath)

execelPath = 'C:\\Users\\Administrator\\Desktop\\samples(new_version).xlsx'
ransomPath = 'C:\\Users\\Administrator\\Desktop\\log1'
newRootDir = 'C:\\Users\\Administrator\\Desktop\\logClassify'

classify(execelPath, ransomPath, newRootDir)