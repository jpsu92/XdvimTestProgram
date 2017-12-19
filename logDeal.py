# -*- coding: UTF-8 -*-
import os
import datetime

'''
获取目录directory下所有文件包括子目录文件的绝对路径，将每个文件的绝对路径中从keyName之后截取出来，放到一个列表中，
返回该列表
'''


def getFilesAbsolutePath(directory, keyName):
    filePathList = []
    for root, dirs, files in os.walk(directory):
        for f in files:
            path = os.path.join(root, f)
            if keyName != '':
                path = path[path.index(keyName):]
            filePathList.append(path.lower())
    return filePathList


def getAllHoneyFiles(path):
    result = []
    with open(path, 'r') as f:
        result = f.readlines()
        for i in range(len(result)):
            result[i] = result[i].strip('\n')
    return result


'''
从日志当中筛选出ransomware进程
'''


def filterProcess(logfilename, fileList, directoryList, resultPath):
    firstFilteredProcess = {}
    f = open(logfilename, 'r')
    for eachline in f:
        eachline = eachline.strip('\n')
        if eachline.startswith("[") and eachline.endswith("]"):
            eachline = eachline[1: len(eachline) - 1]
            arrayLine = eachline.split(",")
            filename = arrayLine[3]
            processName = arrayLine[1]
            if processName != '' and filename.lower() in fileList:
                if processName not in firstFilteredProcess:
                    processPath = arrayLine[7]
                    firstFilteredProcess[processName] = {"processPath": processPath}
    secondFilteredProcess = []
    print firstFilteredProcess
    with open(resultPath, 'a') as f:
        f.write('The ransom processes filted from log is:\n{processes}\n'.format(processes=firstFilteredProcess))
    for eachProcess in firstFilteredProcess:
        if firstFilteredProcess[eachProcess]["processPath"].lower() not in directoryList:
            secondFilteredProcess.append(eachProcess)
    return secondFilteredProcess


'''
对于新创建的加密文件，获取其对应的源文件名，方法的局限性很大
'''


def getOriginalFileName(fileName, honeyFiles):
    fileName = fileName.split('\\').pop()
    originalFileName = ''
    for f in honeyFiles:
        name = f.split('\\').pop()
        if fileName in name or (name != '' and name in fileName):
            originalFileName = f
            break
    return originalFileName


'''
字典的值是列表，向字典的值中添加一项
'''


def appendDictList(eachFileMember, member, key):
    if key in eachFileMember:
        eachFileMember[key]['entryList'].append(member)
    else:
        d = dict(entryList=[member])
        eachFileMember[key] = d


def getNetList(netActivities, startTime, endTime):
    result = []
    for item in netActivities:
        if item['time'] >= startTime and item['time'] <= endTime:
            result.append(item)
    return result


'''
将网络活动添加到文件活动的列表中，并将合并后的列表按照时间规则排序
'''
def addNet2FileList(eachFileMember, netActivities):
    entryList = eachFileMember.items()
    entryList.sort(key=lambda entry:entry[1]['entryList'][0]['time'])
    for i in range(len(entryList)):
        startTime = entryList[i][1]['entryList'][0]['time']
        endTime = entryList[i][1]['entryList'][-1]['time']
        netList = getNetList(netActivities, startTime, endTime)
        tmplist = entryList[i][1]['entryList']
        tmplist.sort(key=lambda entry: entry['time'])
        if netList:
            entryList[i][1]['entryList'].extend(netList)
            entryList[i][1]['entryList'].sort(key=lambda entry: entry['time'])
        if i == 0:
            startTime = datetime.datetime(1970, 1, 1, 0, 0, 0, 0)
        else:
            startTime = entryList[i - 1][1]['entryList'][-1]['time']
        endTime = entryList[i - 1][1]['entryList'][0]['time']
        tmp = getNetList(netActivities, startTime, endTime)
        entryList[i][1]['beforeList'] = tmp
    return entryList


'''
将代表每一个日志条目的字典转化为要输出的字符串格式
'''


def obj2Str(dict):
    syscallNumber = dict['syscallNum']
    item = ''
    if syscallNumber == '52':
        syscallName = 'NtCreateFile'
        createDisposition = dict['createOption']
        item = syscallName + '(' + dict['fileName'] + ', ' + createDisposition + ')'
    elif syscallNumber == '30':
        syscallName = 'NtOpenFile'
        item = syscallName + '(' + dict['fileName'] + ')'
    elif syscallNumber == '5':
        syscallName = 'NtWriteFile'
        bufferLength = dict['bufferLength']
        item = syscallName + '(' + dict['fileName'] + ', ' + bufferLength + 'B)'
    elif syscallNumber == '48':
        syscallName = 'FlushBuffersFile'
        item = syscallName + '(' + dict['fileName'] + ')'
    elif syscallNumber == '3':
        syscallName = 'NtReadFile'
        bufferLength = dict['bufferLength']
        item = syscallName + '(' + dict['fileName'] + ', ' + bufferLength + 'B)'
    elif syscallNumber == 'b2':
        syscallName = 'NtDeleteFile'
        item = syscallName + '(' + dict['fileName'] + ')'
    elif syscallNumber == '24':
        newFileName = dict['newFile']
        if newFileName == '':
            syscallName = 'NtSetInformation for delete'
            item = syscallName + '(' + dict['fileName'] + ')'
        else:
            syscallName = 'NtSetInformation for rename'
            item = syscallName + '(' + dict['fileName'] + ', ' + newFileName + ')'
    elif syscallNumber == 'c':
        syscallName = 'NtClose'
        item = syscallName + '(' + dict['fileName'] + ')'
    elif syscallNumber == '4':
        controlCode = dict['controlCode']
        if controlCode == '0x12003' or controlCode == '0x12007':
            item = dict['netOperation'] + '(' + dict['ip'] + ', ' + dict['port'] + ')'
        elif controlCode == '0x1201f' or controlCode == '0x12017':
            item = dict['netOperation'] + '(' + dict['infoLength'] + ')'
        elif controlCode == '0x12023' or controlCode == '0x1201b':
            item = dict['netOperation'] + '(' + dict['ip'] + ', ' + dict['port'] + dict['infoLength'] + ')'
    return item


def getSuccessiveMemberCount(memberList):
    result = []
    n = len(memberList)
    if n != 0:
        key = memberList[0]
        index = 0
        count = 0
        while index < n:
            if memberList[index] == key:
                count += 1
                index += 1
            else:
                result.append({key: count})
                key = memberList[index]
                count = 0
        result.append({key: count})
    return result


def sameSuccessiveMemberCount(memberList, width):
    arrowRight = '---->'
    size = len(memberList)
    i = 0
    resultList = []
    limitPosition = size - width
    while i <= limitPosition:
        parten = memberList[i: i + width]
        count = 1
        j = i + width
        nextToCmp = memberList[j: j + width]
        while parten == nextToCmp:
            count += 1
            j += width
            nextToCmp = memberList[j: j + width]
        if count > 1:
            temp = '['
            for x in xrange(width):
                if x == 0:
                    temp += parten[x]
                else:
                    temp = temp + arrowRight + parten[x]
            temp += ', ' + str(count) + ']'
            resultList.append(temp)
            i = j
        else:
            resultList.append(memberList[i])
            i += 1
    while i < size:
        resultList.append(memberList[i])
        i += 1
    return resultList


def merge(memberList):
    size = len(memberList)
    limit = size / 2
    width = 1
    preResultList = memberList
    resultList = sameSuccessiveMemberCount(preResultList, width)
    while width <= limit:
        if resultList == preResultList:
            width += 1
        else:
            preResultList = resultList
        resultList = sameSuccessiveMemberCount(preResultList, width)
    return resultList


def printList(memberList, f):
    index = 0
    count = len(memberList)
    arrowRight = '---->'
    for i in xrange(count):
        if i == count - 1:
            f.write(memberList[i])
        else:
            f.write(memberList[i] + arrowRight)
        index += 1
        if index == 3:
            f.write(os.linesep)
            index = 0


def output(beforeNetResult, memberMergeResult, ransomName, filename, resultPath):
    with open(resultPath, 'a') as f:
        f.write(filename + '\n')
        f.write('-' * 100 + os.linesep)
        count = len(memberMergeResult)
        if count == 0:
            f.write(ransomName + ' Not Found!!!' + os.linesep)
        else:
            f.write('~' * 50 + 'Network' + '~' * 50 + os.linesep)
            printList(beforeNetResult, f)
            f.write(os.linesep + '~' * 100 + os.linesep)

            f.write('+' * 50 + 'File + Network' + '+' * 50 + os.linesep)
            printList(memberMergeResult, f)
            f.write(os.linesep + '+' * 100 + os.linesep)
        f.write('-' * 100 + os.linesep * 2)


'''
将时间中某个部分时间转化成一定的长度，前面补0
'''
def convert2StandFormatTime(timeStr):
    tList = timeStr.split(' ')
    year, month, day = tList[0].split('-')
    hour, minute, second, usecond = tList[1].split(':')
    newTimeStr = '{y}-{m}-{d} {h}:{min}:{s}:{us}'.format(y=year, m=month.zfill(2), d=day.zfill(2), h=hour.zfill(2),
                                                         min=minute.zfill(2), s=second.zfill(2), us=usecond.zfill(6));
    return newTimeStr


'''
对ransomware进程的文件和网络活动进行分析
'''


def analysis(honeyFiles, logfilename, executProcess, resultPath):
    eachFileMember = {}
    newNameOfOldFile = {}
    netActivities = []
    with open(logfilename, 'r') as f:
        list1 = f.readlines()
        for i in range(len(list1)):
            # print i
            eachline = list1[i]
            eachline = eachline.strip('\n')
            if eachline.startswith("[") and eachline.endswith("]"):
                eachline = eachline[1: len(eachline) - 1]
                arrayLine = eachline.split(",")
                if len(arrayLine) <= 10:
                    # print len(arrayLine)
                    pname = arrayLine[1]
                    if pname.lower() == executProcess.lower():
                        syscallNum = arrayLine[0]
                        pid = arrayLine[2]
                        ppath = arrayLine[-2]
                        timeStr = convert2StandFormatTime(arrayLine[-1])
                        time = datetime.datetime.strptime(timeStr, '%Y-%m-%d %H:%M:%S:%f')
                        if syscallNum == '4':
                            controlCode = arrayLine[3]
                            port = ''
                            ip = ''
                            infoLength = ''
                            netoperation = ''
                            if controlCode == '0x12003' or controlCode == '0x12007':
                                port = arrayLine[5]
                                ip = arrayLine[6]
                                netoperation = 'bind' if controlCode == '0x12003' else 'connect'
                            elif controlCode == '0x1201f' or controlCode == '0x12017':
                                netoperation = 'tcpSend' if controlCode == '0x1201f' else 'tcpRecv'
                                infoLength = arrayLine[-3]
                            elif controlCode == '0x12023' or controlCode == '0x1201b':
                                netoperation = 'udpSend' if controlCode == '0x12023' else 'udpRecv'
                                infoLength = arrayLine[-3]
                            entry = dict(syscallNum=syscallNum, pName=pname, pId=pid, pPath=ppath,
                                         controlCode=controlCode, ip=ip, port=port, infoLength=infoLength,
                                         netOperation=netoperation, time=time)
                            netActivities.append(entry)
                        else:
                            createOption = arrayLine[4]
                            bufferLength = arrayLine[5]
                            filename = arrayLine[3].lower()
                            if ('c:' in filename):
                                i = filename.index('c:')
                                if i + 2 < len(filename):
                                    filename = filename[i+2:]
                            newFile = arrayLine[6].lower()
                            if ('c:' in newFile):
                                i = newFile.index('c:')
                                if i + 2 < len(newFile):
                                    newFile = newFile[i+2:]
                            entry = dict(syscallNum=syscallNum, pName=pname, pId=pid, pPath=ppath,
                                         createOption=createOption, bufferLength=bufferLength, fileName=filename,
                                         newFile=newFile, time=time)

                            if filename in honeyFiles and syscallNum == '24' and newFile != '':
                                newNameOfOldFile[filename] = newFile
                            if filename not in honeyFiles and syscallNum == '52' and createOption == '0x5':
                                originalFile = getOriginalFileName(filename, honeyFiles)
                                if originalFile != '':
                                    newNameOfOldFile[originalFile] = filename
                                    appendDictList(eachFileMember, entry, originalFile)
                            if filename in honeyFiles:
                                appendDictList(eachFileMember, entry, filename)
                            elif not newNameOfOldFile:
                                for key, value in newNameOfOldFile.items():
                                    t1 = filename.split('\\').pop()
                                    t2 = value.split('\\').pop()
                                    if (t1 != '' and t1 in t2) or (t2 != '' and t2 in t1):
                                        appendDictList(eachFileMember, entry, key)
                                        break
    entryList = addNet2FileList(eachFileMember, netActivities)

    for entry in entryList:
        filename = entry[0]
        beforeNetMemberList = []
        memberList = []
        for item in entry[1]['beforeList']:
            ret = obj2Str(item)
            if ret != '':
                beforeNetMemberList.append('[' + ret + ' ,1]')
        beforeNetResult = merge(beforeNetMemberList)

        for item in entry[1]['entryList']:
            ret = obj2Str(item)
            if ret != '':
                memberList.append('[' + ret + ' ,1]')
        memberMergeResult = merge(memberList)
        output(beforeNetResult, memberMergeResult, logfilename, filename, resultPath)


def getAnalysisResults(logfilePath, fileList, directoryList):
    logFileList = getFilesAbsolutePath(logfilePath, '')
    for logfilename in logFileList:
        resultPath = 'C:\\Users\\Administrator\\Desktop\\result\\' + logfilename.split('\\').pop()
        # myDocument = 'C:\Users\\Administrator\\Desktop\\myDocument'
        # myDocumentfiles = getFilesAbsolutePath(myDocument, keyName='\\myDocument')
        executProcessList = filterProcess(logfilename, fileList, directoryList, resultPath)
        if len(executProcessList) > 0:
            executProcess = executProcessList[0]
            analysis(fileList, logfilename, executProcess, resultPath)
        else:
            with open(resultPath, 'a') as f:
                f.write('When deal with {name} encountered with error：get process error!!!\n'.format(name=logfilename))
                f.write('~' * 200 + os.linesep)


directoryList = ['c:\\windows\\system32\\',
                 'c:\\users\\tf\\desktop\\ss_2.5.8_3.3.2\\shadowsocks-2.5.8\\',
                 '\\\?\\c:\\windows\\system32\\wbem\\']

honeyFilePath = 'C:\Users\\Administrator\\Desktop\\myDocument'
honeyFiles = getFilesAbsolutePath(honeyFilePath, keyName='\\myDocument')
# honeyFilePath = 'C:\\Users\\Administrator\\PycharmProjects\\log\\allFilesPath'
# honeyFiles = getAllHoneyFiles(honeyFilePath)
logfilePath = 'C:\\Users\\Administrator\\Desktop\\log'

getAnalysisResults(logfilePath, honeyFiles, directoryList)
