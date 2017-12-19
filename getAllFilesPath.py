# -*- coding: UTF-8 -*-
import os

def getFilesAbsolutePath(directory, resultPath):
    with open(resultPath, 'a') as f:
        for root, dirs, files in os.walk(directory):
            for item in files:
                path = os.path.join(root, item)
                path = path.lower()
                if ('c:' in path):
                    i = path.index('c:')
                    if i + 2 < len(path):
                        path = path[i + 2:]
                f.write(path + '\n')

directory = 'c:\\'
resultPath = ''
getFilesAbsolutePath(directory, resultPath)