# -*- coding: utf-8 -*-

import os
import sys
import types
from cmd import Cmd

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

from base.base import PRINT, INPUT, getColor

from manager.manager_fs import fsMgr, FsCmd

class FLog(FsCmd):

    __xDict = {
        "Manager":{"fs": fsMgr}, 
    }

    def __init__(self):
        cmdLists = [
            # 使能标记, [命令全称,命令简写],参数最少个数,命令简介,参数说明
            (True, ['load', 'l'], 2, "加载分析文件", "[日志文件类型('fs','cb')] [日志文件列表(至少一个，可多个，支持 * ? [] 三种通配符)]\n{-r 日志文件路径 -o 输出路径 -mode 模式('session','memory','mix')}"),
            (False, ['reload', 'rl'], 2, "重新加载分析文件", "[日志文件类型('fs','cb')] [日志文件列表(至少一个，可多个，支持 * ? [] 三种通配符)] {-r 日志文件路径 -o 输出路径}"),
            (True, ['clear', 'c'], 0, "清除已加载的分析文件", "无"),
            (True, ['showloadfile', 'slf'], 0, "查看已加载的日志文件", "{'all'|日志文件类型('fs','cb')}"),
            (True, ['quit', 'q'], 0, "退出", "无"),
            (True, ['help', 'h', '?'], 0, "帮助", "{command}"),
        ]
        if PY2:
            FsCmd.__init__(self)
        else:
            super(FLog, self).__init__()
        
        self.addCmdList(cmdLists)

        self.prompt = "(Log Analyser)>> "
        self.intro = self.showIntroduce()
    
    def __getManager(self, logType):
        # 按照日志类型构造日志分析器
        mgrDict = self.__xDict["Manager"]
        manager = mgrDict.get(logType, None)
        if manager is None:
            s = "类型错误'%s'" % logType
            PRINT(s)
        return manager

    def __getOption(self, cmd):
        cmd, logDir = self.__xDict["Manager"]["fs"].getOption(cmd, '-r')
        cmd, outputDir = self.__xDict["Manager"]["fs"].getOption(cmd, '-o')
        cmd, mode = self.__xDict["Manager"]["fs"].getOption(cmd, '-mode')
        return True, cmd, logDir, outputDir, mode or "session"

    # load命令  
    def do_load(self, line):
        cmd = line.split()
        manager = self.__getManager(cmd[0])
        if manager is None:
            return False

        ok, cmd, logDir, outputDir, mode = self.__getOption(cmd)
        if not ok:
            return False
        needload = False
        
        for c in cmd[1:]:
            successFileList, failedFileList, filePath = manager.load(c, False, logDir, outputDir)
            
            for fileName, msg in failedFileList:
                s = "日志加载失败。模式: '" + mode + "'" + " 日志类型: '" + cmd[0] + "' 文件路径: " + fileName + " 原因: " + msg
                PRINT(s)
            
            for fileName in successFileList:
                s = "日志加载成功。模式: '" + mode + "'" + " 日志类型: '" + cmd[0] + "' 文件路径: " + fileName
                needload = True
                PRINT(s)
            
        else:
            if needload:
                s = "%d个日志需要分析" % (len(successFileList))
                ok, msg = manager.run(mode)
                if not ok:
                    s = "运行失败。原因:'%s'" % (msg)
                    PRINT(s)

    do_l = do_load

    # reload命令       
    def do_reload(self, line):
        cmd = line.split()
        manager = self.__getManager(cmd[0])
        if manager is None:
            return False
        
        for i, c in enumerate(cmd[1:]):
            s = "加载日志文件 '%s' %s" % (cmd[0], c)
            PRINT(s)
            ok, msg = manager.load(c, i == 0)
            if not ok:
                s = "加载日志失败。原因:%s" % (msg)
                PRINT(s)
        else:
            ok, msg = manager.run()
            if not ok:
                s = "运行失败。原因:%s" % (msg)
                PRINT(s)
    
    do_rl = do_reload

    # clear命令       
    def do_clear(self, line):
        cmd = line.split()
        if len(cmd) > 0:
            manager = self.__getManager(cmd[0])
            if manager:
                s = "清除'%s'日志文件..." % cmd[0]
                PRINT(s, end='')
                manager.clear()
                s = "OK"
                PRINT(s)
        else:
            mgrDict = self.__xDict["Manager"]
            for logType in mgrDict.keys():
                s = "清除'%s'日志文件..." % logType
                PRINT(s, end='')
                mgrDict[logType].clear()
                s = "OK"
                PRINT(s)

    do_c = do_clear

    # 查看已加载的日志文件
    def do_showloadfile(self, line):
        path = []
        cmd = line.split()
        if len(cmd) > 0 and cmd[0].lower() not in ["all"]:
            manager = self.__getManager(cmd[0])
            if manager:
                path += manager.getAnalyzerLogPath()
        else:
            mgrDict = self.__xDict["Manager"]
            for logType in mgrDict.keys():
                path += mgrDict[logType].getAnalyzerLogPath()

        if path:
            s = "已加载的日志文件列表："
            PRINT(s)
            for p in path:
                PRINT(p)

    do_slf = do_showloadfile

    # 帮助    
    def do_help(self, line):
        if not line:
            self.showHelpHeader()
            self.showHelpBody("")
            self.showHelpTail()
        else:
            self.showHelpBody(line)
            pass
        
    do_h = do_help

    # 退出 
    def do_quit(self,line):
        s = "再见！"
        PRINT(s)
        sys.exit()
    do_q = do_quit

if __name__=='__main__': 
    cmd = FLog()  
    cmd.cmdloop()
