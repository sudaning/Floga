# -*- coding: utf-8 -*-

import os
import sys
import re
import copy
import codecs
import time
from glob import glob
from datetime import datetime
from platform import system as osys

from base.base import PRINT, INPUT, WRITELINES, getColor, getTerminalSize, getPathSeparator

class LogAnalyzer(object):
    __type = '' 
    __path = []
    __lines = []
    __showMode = "horizontal" # 水平horizontal, 垂直vertical

    __version = ""

    MAX_DIRNAME_LEN = 100
    MAX_DIRPATHNAME_LEN = 128
    MAX_LOGTIME_LEN = 26 #2016-04-14 16:28:35.995307

    SESS_LOG_DK = "log"
    SESS_KEYINFO_DK = "keyInfo"
    SESS_START_TIME_DK = "startTime"
    SESS_RESULT_DK = "result"
    SESS_RESULT_CONCLUSION_DK = "conclusion"
    SESS_RESULT_DETAILS_DK = "details"
    SESS_RESULT_NOTE_DK = "note"

    MOD_FSAPI = 'fsapi'
    MOD_FS = 'freeswitch'
    MOD_OUTSIDE = ''
    MOD_REST = 'rest'
    MOD_SM = 'statemachine'

    #定义构造方法 
    def __init__(self, t, ver = ""):
        self.__type = t
        self.__path = []
        self.__lines = []
        self.__showMode = "horizontal"
        self.__version = ver

    def getType(self):
        return self.__type

    def getPath(self):
        return self.__path

    def getPathEx(self, index):
        """获取日志文件绝对路径
        参数列表:
            index: 日志文件索引
        返回值：
            日志文件绝对路径
        异常：
            无
        """   
        return self.getBeautifulPath(self.getPath()[index] if len(self.getPath()) > index else "")

    def getBeautifulPath(self, p):
        # 若路径中含有‘..’则按照路径的表达式原则进行优化
        dotPos = p.rfind('..')
        sep = getPathSeparator()
        while(dotPos != -1):
            slashPos = p[0:dotPos - 1].rfind(sep)
            if slashPos == -1:
                return p
            p = p[:slashPos] + p[dotPos + 2:]
            dotPos = p.rfind('..')
        return p

    def getLines(self):
        return self.__lines

    def getShowMode(self):
        return self.__showMode

    def getVersion(self):
        return self.__version

    def changeShowMode(self):
        if self.__showMode in ["horizontal"]:
            self.__showMode = "vertical"
        else:
            self.__showMode = "horizontal"
        return self.__showMode
        
    def sortRecode(self, newSort=[]):

        p = copy.deepcopy(self.getPath())
        self.printProc(1, 2, widgetType = "percent")
        l = copy.deepcopy(self.getLines())
        self.printProc(2, 2, widgetType = "percent")

        if len(newSort) != len(p) or len(newSort) != len(l):
            return False

        for i, n in enumerate(newSort):
            self.__path[i] = p[n]
            self.__lines[i] = l[n]

        return True

    # 加载需要分析的文件
    def load(self, path, rl=False):
        # 路径是否存在
        s = "正在加载日志文件..."
        PRINT(s, end='')

        fileList = []
        for fileName in glob(path):
            if os.path.exists(fileName) and os.path.isfile(fileName):
                fileList.append(fileName)
        if not fileList:
            s = "ERROR"
            PRINT(s, color='red')
            return [], [(path, "文件不存在")]

        failedFileList = []
        successFileList = []
        fileListLen = len(fileList)
        process = 0
        f = None
        time1 = time.clock()
        for filePath in fileList:
            process = self.printProc(process, fileListLen, 1)
            # 打开
            filePath = self.getBeautifulPath(filePath)

            try:
                if f:
                    f.close()
                f = open(filePath, 'r')
                if f is None:
                    failedFileList.append((filePath, "打开文件失败"))
                    continue
            except Exception as err:
                failedFileList.append((filePath, "打开文件失败。%s" % err))
                continue

            # 重新加载文件
            if rl:
                rl = False
                self.__path=[filePath]
                # python3下面，若文件出现乱码0xFF，则会报错。python2无此问题
                try:
                    self.__lines=[f.readlines()]
                except Exception as err:
                    failedFileList.append((filePath, "日志文件含有乱码，请转换为UTF-8编码再进行加载。%s" % err))
                    continue
                
            # 添加一个文件
            else:
                if filePath in self.__path:
                    failedFileList.append((filePath, "文件已经加载"))
                    continue

                # python3下面，若文件出现乱码0xFF，则会报错。python2无此问题
                try:
                    self.__lines.append(f.readlines())
                except Exception as err:
                    failedFileList.append((filePath, "日志文件含有乱码，请转换为UTF-8编码再进行加载。%s" % err))
                    ok = False
                    continue

                self.__path.append(filePath)
                successFileList.append(filePath)
        else:
            if f:
                f.close()
            time2 = time.clock()
            if successFileList:
                s = "OK (耗时：%.2f秒)" % (time2 - time1)
                PRINT(s, color='green')
            else:
                s = "ERROR"
                PRINT(s, color='red')
                return successFileList, failedFileList

        # 加载完成之后，重新排序
        s = "正在对加载文件进行重排序..."
        PRINT(s, end='')
        time1 = time.clock()
        self.sortLogFile()
        time2 = time.clock()
        s = "OK (耗时：%.2f秒)" % (time2 - time1)
        PRINT(s, color='green')
        return successFileList, failedFileList


    # clear加载的文件
    def clear(self):
        self.__path=[]
        self.__lines=[]
        return True, ""
        
    # 开始分析文件    
    def run(self, mode = "normal"):
        
        return True, ""

    def makeDir(self, path):
        
        if os.path.exists(path):
            import shutil
            try:
                shutil.rmtree(path, True)
            except Exception as Err:
                print(Err)
                return False
        try:
            os.mkdir(path[0:self.MAX_DIRPATHNAME_LEN])
        except Exception as Err:
            print(Err)
            return False
        return path

    def __outputPre(self, outputPath, fileName, mode="w+"):
        # 判断路径是否存在
        if os.path.exists(outputPath) is False or not fileName:
            return False

        # 新建文件
        try:
            asbFilePath = os.path.join(outputPath, fileName)[0:self.MAX_DIRPATHNAME_LEN]
            #f = codecs.open(asbFilePath, mode, encoding='cp936')
            f = codecs.open(asbFilePath, mode, encoding='utf-8')
        except Exception as err:
            print(err)
            return False

        return f

    def __outputComplete(self, f):
        f.close()

    # 输出日志行到文件
    def output(self, logDict, outputPath, fileName, header="", tail="", mode="w+"):

        f = self.__outputPre(outputPath, fileName, mode)
        if not f:
            return False
            
        # 开始写入
        WRITELINES(f, header)
        s = "\n\n%-6s %s\n" % ("原始行","日志")
        WRITELINES(f, s)

        for (k,v) in sorted(logDict.items(), key=lambda logDict:logDict[0]):
            logList = sorted(v.items(), key=lambda v:v[0])
            f.writelines("%s\n" % self.getPathEx(k)) 
            for (line, log) in logList:
                s = ("%-6d %s" + (log.rfind("\n") and "\n" or "")) % (line + 1, log)
                WRITELINES(f, s)
        
        self.__outputComplete(f)
        return True

    # 输出额外信息到文件
    def outputEx(self, outputPath, fileName, content = "", mode="w+"):
        if not content:
            return True

        f = self.__outputPre(outputPath, fileName, mode)
        if not f:
            return False
        WRITELINES(f, content)
        self.__outputComplete(f)
        return True

    # 重新对加载的文件进行排序
    def sortLogFile(self, reExpr = "(\\d{4})-(\\d{1,2})-(\\d{1,2}) (\\d{2}):(\\d{2}):(\\d{2}).(\\d{6})", expLen = 7):
        lines = self.getLines()
        if len(lines) < 2:
            return True

        logTime = {}

        for f, l in enumerate(lines):
            for i, line in enumerate(l):
                # 按照时间提取
                res = self.reMatch(reExpr, line, expLen)
                if res:
                    logTime[f] = datetime(int(res[0]), int(res[1]), int(res[2]), int(res[3]), int(res[4]), int(res[5]))
                    break
        else:
            # 计算出新的顺序，进行排序
            if not logTime:
                return False
            
            timeNewSort = [x[0] for x in sorted(logTime.items(), key=lambda logTime:logTime[1])]
            self.sortRecode(timeNewSort)
            return True

    # 重复的项
    def findDupl(self, lst):
        exists, dupl = set(), set()
        for item in lst:
            if item in exists:
                dupl.add(item)
            else:
                exists.add(item)
        return dupl

    def inputContinue(self, curIndex, count, total, flag, fun=None, *arg):
        if count and count % 10 == 0 and not flag:
            s = "\n(%d/%d)按任意键继续...(q:退出 c:不再提示)" % (count, total)
            content = INPUT(s, color='yellow')
            if content.lower() in ['q']:
                return False, flag
            elif content.lower() in ['c']:
                flag = True
            else:
                if curIndex + 1 != total:
                    fun and fun(*arg)
                pass
        return True, flag

    def printProc(self, process, total, step = 1, widgetType = "count", begin = 0, end = 100, widgetFromat = "(%d/%d)"):
        if osys() not in ['Linux']:
            return process
        try:
            if widgetType in ["count"]:
                s = widgetFromat % (process, total)
            elif widgetType in ["percent"]:
                if end < begin or begin < 0 or end > 100:
                    return process

                needPercent = end - begin
                s = "(%0.2f%%)" % ((float(process) / float(total)) * needPercent + begin)

            else:
                s = widgetFromat % (process, total)
            s += "\b" * len(s)
            sys.stdout.write(s)
            sys.stdout.flush()
            return process + step
        except Exception as err:
            return process
        

    # 输出
    def printList(self, l, lineLimited, header="", tail=""):
        # 头部
        if header:
            s = "\n%s\n" % str(header)
            PRINT(s, end='')
        
        # 中间
        cnt = 0
        total = len(l)
        flag = False
        for i, item in enumerate(l):
            if not item:
                continue
            cnt += 1
            if cnt % lineLimited is 0:
                s = "%s\n" % str(item)
                PRINT(s)
                if cnt % (lineLimited * 10) == 0 and not flag:
                    s = "\n(%d/%d)按任意键继续...(q:退出 c:不再提示)" % (cnt, total)
                    content = INPUT(s, color='yellow')
                    if (content and content.lower() in ['q']):
                        return
                    elif content and content.lower() in ['c']:
                        flag = True
                    else:
                        if i + 1 != total and header:
                            s = "\n%s\n" % str(header)
                            PRINT(s)
            else:
                s = "%s\t" % str(item)
                PRINT(s, end='')
        else:
            # 中间的特殊处理
            s = "\n\n" if cnt % lineLimited is not 0 else "\n"
            PRINT(s)
            
            # 尾部
            if tail:
                s = "%s\n" % tail
                PRINT(s)

    def showNote(self, note, sep="->", lineLimited = 8, space = 20):
        s = ""
        for i, x in enumerate(note.split(sep)):
            item = " " + x.strip() + " " + sep
            if (i + 1) % lineLimited is 0:
                s += "\n" + " " * space + item
            else:
                s += item
        else:
            return s[1:-2]

    # 正则匹配
    def reMatch(self, reExpr, log, expLen):
        """正则匹配
        参数列表:
            reExpr: 正则表达式
            log: 待匹配字符串
            expLen: 期望返回元祖长度
        返回值：
            正则提取的元祖
        异常：
            无
        """
        tmp = re.search(reExpr, log)
        if tmp:
            res = tmp.groups()
            if len(res) >= expLen:
                return res[0:expLen]
        return ()

    def reFind(self, reExpr, log):
        return True if re.search(reExpr, log) else False
        
    def reFindList(self, reExprList, log):
        for l in reExprList:
            if self.reFind(l, log):
                return True
        else:
            return False
        
    def caseMatch(self, detailsDict, case):
        for k in case.keys():
            # print k, detailsDict.get(k), case[k]
            if detailsDict.get(k, None) is not None:
                if detailsDict[k] != case[k]:
                    return False
        return True

    # 格式化日志时间，统一返回datetime
    def getLogTime(self, log):
        logDate = log[:self.MAX_LOGTIME_LEN].strip()
        logDateLen = len(logDate)
        if self.MAX_LOGTIME_LEN > logDateLen:
            pos = logDate.rfind('.')
            # 微秒若不为6位，则省略了前面的0，需要添上
            logDate = logDate[:pos + 1] + '0' * (self.MAX_LOGTIME_LEN - logDateLen if self.MAX_LOGTIME_LEN > logDateLen else 0) + logDate[pos + 1:]
        try:
            dt = datetime.strptime(logDate, "%Y-%m-%d %H:%M:%S.%f")
        except Exception as Err:
            dt = datetime.strptime("1970-01-01 00:00:00.000000", "%Y-%m-%d %H:%M:%S.%f")
        return dt



