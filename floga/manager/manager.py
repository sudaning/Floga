# -*- coding: utf-8 -*-

import sys
import os
from cmd import Cmd
from platform import system as osys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

class Manager(object):
    """ 控制器基类
        衔接命令行框架与分析器
    """
    __an = None # 分析器

    __rootPath = "" # root路径
    __pwd = "" # 当前脚本路径
    __outputDir = "" # 输出路径
    
    def __init__(self, an, rootPath = "", pwd = ""):
        self.__an = an
        self.__rootPath = rootPath
        self.__pwd = pwd
        
    def getAnalyzer(self):
        """ 获取分析器实例
            参数列表:无
            返回值:分析器实例 instance
            异常:无
        """
        return self.__an

    def getRoot(self):
        """ 获取root路径
            参数列表:无
            返回值:root路径 str
            异常:无
        """
        return self.__rootPath

    def getPwd(self):
        """ 获取当前路径
            参数列表:无
            返回值:当前路径 str
            异常:无
        """
        return self.__pwd

    def getPath(self):
        """ 获取root路径和当前路径
            参数列表:无
            返回值:root路径和当前路径 元组(str,str)
            异常:无
        """
        return self.__rootPath, self.__pwd, self.__outputDir

    def getOutputDir(self):
        """ 获取输出目录
            参数列表:无
            返回值:输出路径 str
            异常:无
        """
        return self.__outputDir

    def getAnalyzerLogPath(self):
        return self.getAnalyzer().getPath()

    def load(self, fileName, rl=False, logDir="", outputDir=""):
        """ 加载
            参数列表:
                fileName:日志文件名
                rl:是否重新加载
                logDir:日志文件目录
                outputDir:输出目录
            返回值:分析器加载结果 结果值,错误信息 bool,str
            异常:无
        """
        # 获取分析器
        an = self.getAnalyzer()
        # 计算出日志存放的绝对路径=当前脚本目录的上层目录的log目录
        if not logDir:
            absLogPath = os.path.join(self.getPwd(), os.pardir, "log", fileName)
        else:
            sep = getPathSeparator()
            absLogPath = os.path.join(logDir if logDir[-1] == sep else logDir + sep, fileName)

        # 如果存在输出路径则选择输出路径，不存在则输出在工程路径的根目录下的output文件夹下
        if not outputDir:
            self.__outputDir = os.path.join(self.getRoot(), "output")
        else:
            sep = getPathSeparator()
            self.__outputDir = outputDir if outputDir[-1] == sep else outputDir + sep

        # 分析器加载日志并分析
        successFileList, failedFileList = an.load(absLogPath, rl)
        return successFileList, failedFileList, absLogPath

    def run(self, mode = "session"):
        """ 运行控制器
            参数列表:无
            返回值:分析器运行结果 结果值,错误信息 bool,str
            异常:无
        """
        return self.getAnalyzer().run(mode)
    
    def clear(self):
        """ 运行控制器
            参数列表:
                fileName:日志文件名
            返回值:分析器运行结果 结果值,错误信息 bool,str
            异常:无
        """
        # 获取分析器
        an = self.getAnalyzer()

        # 分析器加载日志并分析
        ret, msg = an.clear()
        
    def changeShowMode(self):
        return self.getAnalyzer().changeShowMode()

    def outputLogRet(self, condition, data, res, path, fileList, autoOpen = True):
        """ 输出文件到指定路径时的错误处理
            参数列表:
                condition:条件
                data:条件值
                res:成功输出文件个数
                path:文件路径
                fileList: 输出的文件列表
            返回值:分析器运行结果 结果值,错误信息 bool,str
            异常:无
        """
        if res is 0:
            s = "没有找到日志" if data.lower() in ["all"] else "不存在%s为'%s'的日志" % (condition, data)
            PRINT(s)
            return False
        else:
            s = "输出完成，%d个日志在路径:\n'%s':" % (res, path)
            PRINT(s)
            for i, f in enumerate(fileList):
                if i < 10:
                    s = " %s" % f
                    PRINT(s)
                else:
                    s = "......"
                    PRINT(s)
                    break

        if autoOpen:
            if osys() in ['Windows']:
                if res == 1:
                    # 打开那个文件
                    os.startfile(os.path.join(path, fileList[0] if fileList else ""))
                elif res > 1:
                    # 打开那个路径
                    os.startfile(path)

        return True

    def getOption(self, cmd, opt = ""):
        optVal = ""
        # python的 in list语法为全匹配，不存在子串的情况，除非有相同元素
        if opt in cmd:
            pos = cmd.index(opt)
            if len(cmd) >= pos + 2:
                optVal = cmd[pos + 1]
                del cmd[pos + 1], cmd[pos]
            elif len(cmd) >= pos + 1:
                del cmd[pos]
        
        return cmd, optVal

class Command(Cmd):
    """ 命令行框架基类
        衔接命令行界面与管理器
    """
    __cmdLists = [] # 命令行

    def __init__(self):
        if sys.version < "3":
            Cmd.__init__(self)
        else:
            self.__cmdLists = []
            return super(Command, self).__init__()

    def emptyline(self):
        pass

    def default(self, line):
        if line == "？":
            self.showHelpHeader()
            self.showHelpBody("")
            self.showHelpTail()
        else:
            s = "无法识别命令'%s'，请输入help/h/?查看帮助" % str(line)
            PRINT(s)

    def addCmdList(self, l):
        """ 增加命令列表
            各个模块继承此命令行框架基类，注册自己的命令到这里
            参数列表:
                l:命令列表
            返回值:无
            异常:无
        """
        self.__cmdLists = l + self.__cmdLists

    def getCmdList(self):
        return self.__cmdLists

    def checkParmater(self, cmd, parameter):
        for c in self.getCmdList():
            if cmd in c[1]:
                p = parameter.split()
                if c[2] <= len(p):
                    return p if c[2] > 0 else True
                else:
                    s = "此命令至少需要输入%d个参数" % c[2]
                    PRINT(s)
                    return []
        else:
            return []

    def showIntroduce(self):
        s = "\n"
        s += "                              *****\n"
        s += "         ****************   *********\n"
        s += "       *****************  *************\n"
        s += "     *****************  *****      ******\n"
        s += "    ****               ****         *****\n"
        s += "    ****                **          *****\n"
        s += "     **************                *****\n"
        s += "      *************               *****\n"
        s += "    ***************              *****  ***\n"
        s += "   ****                         *****  ******\n"
        s += "  **** " + "{0:^23}".format("Log Analyser Tool") + " *****      *****\n"
        s += "  **** " + "{0:^22}".format("V1.0.0") + " *****          ***\n"
        s += "  ****                       *****  ***       ***\n"
        s += "   ****                     *****   ****     ****\n"
        s += "    ***************************       **********\n"
        s += "     ************************           ****** \n"
        s += "       ********************\n"
        s += "\n"
        s += "  欢迎使用玖云平台日志分析工具，键入help/h/?查看帮助\n"
        PRINT(s)

    def showHelpHeader(self):
        s = "{0:-^160}".format(" 命令列表 ") + "\n\n"
        s += " %02s  %-40s %-30s %s\n" % ("", "命令", "描述", "参数说明")
        PRINT(s)
        return s

    def showHelpTail(self):
        s = "\n" + "-" * 160 + "\n" + \
            "PS: 命令(简写)   [] 必选   {} 可选   () 选择   '' 关键字，可直接使用\n"
        PRINT(s)   
        return s

    def showHelpBody(self, tagCmd):
        s = ""
        cnt = 0
        for regCmd in self.getCmdList():
            # 是否使能
            if not regCmd[0]:
                continue

            # 是否有数据
            if regCmd[1][0]:
                cmdStr = ""
                fullName = ""
                sortName = ""
                for j, cmd in enumerate(regCmd[1]):
                    if j == 0:
                        fullName = cmd
                    else:
                        sortName += "%s/" % cmd
                else:
                    cmdStr = "{0:<6}".format(sortName[:-1]) + " - " + fullName + "):"
                cnt += 1
                if tagCmd == "" :
                    ppos = 0
                    npos = 0
                    # 带有\n的参数描述对齐换行
                    for i, x in enumerate(regCmd[4]):
                        npos = regCmd[4].find('\n', ppos + 1)
                        if npos == -1:
                            break
                        if i == 0:
                            s += " %02d. %-40s %-30s %s\n" % (cnt, cmdStr[0:-2], regCmd[3], regCmd[4][ppos:npos])
                        else:
                            s += " " * 79 + "%s\n" % (regCmd[4][ppos + 1:npos])   
                        ppos = npos
                    if i == 0:
                        s += " %02d. %-40s %-30s %s\n" % (cnt, cmdStr[0:-2], regCmd[3], regCmd[4])
                    else:
                        s += " " * 79 + regCmd[4][ppos + 1:] + "\n"
                elif tagCmd != "" and tagCmd in regCmd[1]:
                    s += "  %-40s %-30s %s\n" % (cmdStr[0:-2], regCmd[3], regCmd[4])
                    break
            # 没数据就打印分隔符
            else:
                if tagCmd == "":
                    s += "-" * 160 + "\n"
        PRINT(s)
        return s

