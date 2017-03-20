# -*- coding: utf-8 -*-

import sys
import os
from cmd import Cmd

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY2:
    from analyzer.analyzer_fs import FsLogAnalyzer
    from manager import Manager, Command
else:
    from analyzer.analyzer_fs import FsLogAnalyzer
    from manager.manager import Manager, Command

    def unicode(s, code):
        return s

class FsManager(Manager):

    def __init__(self, rootPath = "", pwd = "", ):
        if PY2:
            return Manager.__init__(self, FsLogAnalyzer(), pwd = pwd, rootPath = rootPath)
        else:
            return super(FsManager, self).__init__(FsLogAnalyzer(), pwd = pwd, rootPath = rootPath)

    def showCallNumberList(self, cmd):
        return self.getAnalyzer().showCallNumberList()

    def showUUIDList(self, cmd):
        return self.getAnalyzer().showSessUUIDList()

    def showResultByCallNumber(self, cmd):

        an = self.getAnalyzer()

        callNumber = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""

        an.showResult(callNumber = callNumber if callNumber.lower() not in ["all"] else "", conclusion = conclusion)

        return True

    def showResultByUUID(self, cmd):

        an = self.getAnalyzer()

        UUID = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""

        an.showResult(sessUUID = UUID if UUID.lower() not in ["all"] else "", conclusion = conclusion)

        return True

    def showDetailsByCallNumber(self, cmd):

        an = self.getAnalyzer()

        callNumber = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""
        res = an.showDetails(callNumber = callNumber if callNumber.lower() not in ["all"] else "", conclusion = conclusion)

        return True

    def showDetailsByUUID(self, cmd):

        an = self.getAnalyzer()

        UUID = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""
        res = an.showDetails(sessUUID = UUID if UUID.lower() not in ["all"] else "", conclusion = conclusion)

        return True

    def outputResultByCallNumber(self, cmd):

        an = self.getAnalyzer()

        cmd, name = self.getOption(cmd, '-name')
        callNumber = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""
        outputPath = self.getOutputDir()

        res, path, fileList = an.outputReslut(outputPath, callNumber = callNumber if callNumber.lower() not in ["all"] else "", conclusion = conclusion, fileName = name)
   
        return self.outputLogRet("呼叫号码", callNumber, res, path, fileList)

    def outputResultByUUID(self, cmd):

        an = self.getAnalyzer()

        cmd, name = self.getOption(cmd, '-name')
        UUID = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""
        outputPath = self.getOutputDir()

        res, path, fileList = an.outputReslut(outputPath, sessUUID = UUID if UUID.lower() not in ["all"] else "", conclusion = conclusion, fileName = name)
        
        return self.outputLogRet("UUID", UUID, res, path, fileList)

    def outputLogByCallNumber(self, cmd):

        an = self.getAnalyzer()

        cmd, name = self.getOption(cmd, '-name')
        callNumber = cmd[0]
        outputPath = self.getOutputDir()
        
        res, path, fileList = an.outputOriginLog(outputPath, callNumber = callNumber if callNumber.lower() not in ["all"] else "", name = name)
   
        return self.outputLogRet("呼叫号码", callNumber, res, path, fileList)

    def outputLogByUUID(self, cmd):

        an = self.getAnalyzer()

        cmd, name = self.getOption(cmd, '-name')
        UUID = cmd[0]
        outputPath = self.getOutputDir()

        res, path, fileList = an.outputOriginLog(outputPath, sessUUID = UUID if UUID.lower() not in ["all"] else "", name = name)
            
        return self.outputLogRet("UUID", UUID, res, path, fileList)

    def outputDetailsByCallNumber(self, cmd):

        an = self.getAnalyzer()

        cmd, name = self.getOption(cmd, '-name')
        callNumber = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""
        outputPath = self.getOutputDir()
        res, path, fileList = an.outputDetailsByCallNumber(outputPath, fileName = name, callNumber = callNumber if callNumber.lower() not in ["all"] else "", conclusion = conclusion)

        return self.outputLogRet("呼叫号码", callNumber, res, path, fileList)   

    def outputDetailsByUUID(self, cmd):

        an = self.getAnalyzer()

        cmd, name = self.getOption(cmd, '-name')
        UUID = cmd[0]
        conclusion = cmd[1] if len(cmd) == 2 else ""
        outputPath = self.getOutputDir()
        res, path, fileList = an.outputDetailsByUUID(outputPath, fileName = name, sessUUID = UUID if UUID.lower() not in ["all"] else "", conclusion = conclusion)
        
        return self.outputLogRet("呼叫号码", UUID, res, path, fileList)


fsMgr = FsManager(os.path.join(sys.path[0], os.pardir), sys.path[0])

class FsCmd(Command):

    __cmdLists = [
            (True, ['', ''], 0, '', ''),
            
            (True, ['fsshowcallnumberlist', 'fsscl'], 0, "显示呼叫号码列表", "无"),
            (True, ['fsshowuuidlist', 'fssul'], 0, "显示UUID列表", "无"),
            
            (True, ['fsshowresultbycallnumber', 'fssrc'], 1, "按号码显示结果", "[呼叫号码|'all'] {'OK'|'ERROR'}"),
            (True, ['fsshowresultbyuuid', 'fssru'], 1, "按UUID显示结果", "[UUID|'all'] {'OK'|'ERROR'}"),
            
            (True, ['fsshowdetailsbycallnumber', 'fssdc'], 1, "按号码显示详细分析结果", "[呼叫号码|'all'] {'OK'|'ERROR'}"),
            (True, ['fsshowdetailsbyuuid', 'fssdu'], 1, "按UUID显示详细分析结果", "[UUID|'all'] {'OK'|'ERROR'}"),
            
            (True, ['fsoutputresultbycallnumber', 'fsorc'], 1, "按号码输出结果到文件", "[呼叫号码|'all'] {-name 指定文件或文件夹名}" ),
            (True, ['fsoutputresultbyuuid', 'fsoru'], 1, "按UUID输出结果到文件", "[UUID|'all'] {-name 指定文件或文件夹名}"),
            
            (True, ['fsoutputlogbycallnumber', 'fsoc'], 1, "按号码输出日志到文件", "[呼叫号码|'all'] {-name 指定文件或文件夹名}"),
            (True, ['fsoutputlogbyuuid', 'fsou'], 1, "按UUID输出日志到文件", "[UUID|'all'] {-name 指定文件或文件夹名}"),

            (True, ['fsoutputdetailsbycallnumber', 'fsodc'], 1, "按号码输出详细分析结果到文件", "[呼叫号码|'all'] {'OK'|'ERROR'} {-name 指定文件或文件夹名}"),
            (True, ['fsoutputdetailsbyuuid', 'fsodu'], 1, "按UUID输出详细分析结果到文件", "[UUID|'all'] {'OK'|'ERROR'} {-name 指定文件或文件夹名}"),
        ]

    def __init__(self):
        if PY2:
            Command.__init__(self)
            Command.addCmdList(self, self.__cmdLists)
        else:
            super(FsCmd, self).__init__()
            super(FsCmd, self).addCmdList(self.__cmdLists)

    # 显示呼叫号码列表
    def do_fsshowcallnumberlist(self, line):
        p = self.checkParmater("fsscl", line)
        p and fsMgr.showCallNumberList(p)

    do_fsscl = do_fsshowcallnumberlist

    # 显示UUID列表
    def do_fsshowuuidlist(self, line):
        p = self.checkParmater("fssul", line)
        p and fsMgr.showUUIDList(p)

    do_fssul = do_fsshowuuidlist

    # 按号码显示结果
    def do_fsshowresultbycallnumber(self, line):
        p = self.checkParmater("fssrc", line)
        p and fsMgr.showResultByCallNumber(p)

    do_fssrc = do_fsshowresultbycallnumber

    # 按UUID显示结果
    def do_fsshowresultbyuuid(self, line):
        p = self.checkParmater("fssru", line)
        p and fsMgr.showResultByUUID(p)

    do_fssru = do_fsshowresultbyuuid

    # 按号码显示详细分析结果
    def do_fsshowdetailsbycallnumber(self, line):
        p = self.checkParmater("fssdc", line)
        p and fsMgr.showDetailsByCallNumber(p)

    do_fssdc = do_fsshowdetailsbycallnumber

    # 按UUID显示详细分析结果
    def do_fsshowdetailsbycalluuid(self, line):
        p = self.checkParmater("fssdu", line)
        p and fsMgr.showDetailsByUUID(p)

    do_fssdu = do_fsshowdetailsbycalluuid

    # 按号码输出简单日志到文件
    def do_fsoutputresultbycallnumber(self, line):
        p = self.checkParmater("fsorc", line)
        p and fsMgr.outputResultByCallNumber(p)

    do_fsorc = do_fsoutputresultbycallnumber

    # 按UUID输出日志到文件
    def do_fsoutputresultbyuuid(self, line):
        p = self.checkParmater("fsoru", line)
        p and fsMgr.outputResultByUUID(p)

    do_fsoru = do_fsoutputresultbyuuid

    # 按号码输出日志到文件
    def do_fsoutputlogbycallnumber(self, line):
        p = self.checkParmater("fsoc", line)
        p and fsMgr.outputLogByCallNumber(p)

    do_fsoc = do_fsoutputlogbycallnumber

    # 按UUID输出日志到文件
    def do_fsoutputlogbyuuid(self, line):
        p = self.checkParmater("fsou", line)
        p and fsMgr.outputLogByUUID(p)

    do_fsou = do_fsoutputlogbyuuid

    # 按号码输出详细分析结果到文件
    def do_fsoutputdetailsbycallnumber(self, line):
        p = self.checkParmater("fsodc", line)
        p and fsMgr.outputDetailsByCallNumber(p)

    do_fsodc = do_fsoutputdetailsbycallnumber

    # 按号码输出详细分析结果到文件
    def do_fsoutputdetailsbyuuid(self, line):
        p = self.checkParmater("fsodu", line)
        p and fsMgr.outputDetailsByUUID(p)

    do_fsodu = do_fsoutputdetailsbyuuid

