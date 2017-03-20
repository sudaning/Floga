# -*- coding: utf-8 -*-
import os
import time
import sys
from datetime import datetime
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

from base.base import PRINT, INPUT, getColor

if PY2:
    from analyzer import LogAnalyzer
else:
    from analyzer.analyzer import LogAnalyzer

# FS日志分析器
class FsLogAnalyzer(LogAnalyzer):

    __sessLogInfoDict = {}# 按照会话归类的日志信息
                          # {会话UUID：{log:{文件索引:{行数:日志}},
                          #            callNumber:呼叫号码,
                          #            result:{分析结果},
                          #            keyInfo:[(文件索引,行数,状态类型,(状态迁移信息))]}
                          # }
    __ignoreLinesDict = {}# 忽略的行{文件索引:{行数:日志}}
    
    ANALYZER_TYPE_FS = 'fs'

    # 会话类字典key
    SESS_FS_CALLNUMBER_DK = "callNumber"

    # 抽取出的关键信息分类
    SIGN_FLAG_CHAN = "chan proc"
    SIGN_CHAN_CALLING = 'calling'
    SIGN_CHAN_PROCEDDING = 'proceeding'
    SIGN_CHAN_COMPLETE = 'completing'
    SIGN_CHAN_TERMINATED = 'terminated'

    SIGN_FLAG_CALL = "channel sm"
    SIGN_CALL_HANGUP = 'HANGUP'

    SIGN_FLAG_CS = "core sm"
    SIGN_FLAG_RTP = "rtp"
    SIGN_FLAG_CALLNUMBER = "callnumber"
    SIGN_FLAG_HANGUP = "hangup_reason"
    SIGN_FLAG_R_BYE = 'recv_bye'
    SIGN_FLAG_S_BYE = "send_bye"
    SIGN_FLAG_CANCEL = 'cancel'
    SIGN_FLAG_R_INVITE = "recv_invite"

    # SIP信令
    SIP_INVITE = 'INVITE'
    SIP_CANCEL = 'CANCEL'
    SIP_BYE = 'BYE'

    # 匹配模式
    MATCH_MOD_NORMAL = "normal"
    MATCH_MOD_EXTEND = "extend"
    MATCH_MOD_DETAILS = "details"

    # 输出文件
    OUTPUT_POSTFIX_LOG = ".log"
    OUTPUT_POSTFIX_RESULT = ".result"
    OUTPUT_POSTFIX_DETAILS = ".details"

    def __init__(self):
        self.__sessLogInfoDict = {}
        self.__ignoreLinesDict = {}
        if PY2:
            return LogAnalyzer.__init__(self, self.ANALYZER_TYPE_FS)
        else:
            return super(FsLogAnalyzer, self).__init__(self.ANALYZER_TYPE_FS)
    
    def getSessLogInfoDict(self):
        """获取会话信息字典
        参数列表:
            无
        返回值：
            会话信息字典
            例如：
            {UUID：{log:{文件索引:{行数:日志}}, callNumber:呼叫号码, result:分析结果, keyInfo:(文件索引,行数,状态类型,(状态迁移信息))}}
        异常：
            无
        """
        return self.__sessLogInfoDict

    def getIgnoreLinesDict(self):
        """获取忽略的行字典
        在解析过程中，有些无法满足正则条件的日志行，无法解析其数据，则会填入此字典中
        参数列表:
            无
        返回值：
            忽略的行字典
            例如：
            {文件索引:{行数:日志}}
        异常：
            无
        """
        return self.__ignoreLinesDict

    def load(self, path, rl=False):
        """加载FS的日志
        参数列表:
            path:日志路径
            rl:是否重新加载
        返回值：
            成功标志和错误信息 元组(bool, str)
        异常：
            无
        """
        if PY2:
            return LogAnalyzer.load(self, path, rl)
        else:
            return super(FsLogAnalyzer, self).load(path, rl)

    def clear(self):
        """清理FS的日志
        参数列表:
            无
        返回值：
            成功标志和错误信息 元组(bool, str)
        异常：
            无
        """
        self.__sessLogInfoDict = {}
        self.__ignoreLinesDict = {}
        
        return super(FsLogAnalyzer, self).clear()
        
    def getSessInfo(self, UUID = "", key = ""):
        """清理FS的日志
        参数列表:
            UUID:会话的UUID
            key:内部的字典名
        返回值：
            成功标志和错误信息 元组(bool, str)
        异常：
            无
        """
        sessDict = self.getSessLogInfoDict()
        if UUID:
            if sessDict.get(UUID, False):
                return UUID, sessDict[UUID].get(key, False)
            else:
                return UUID, None
        else:
            return [(UUID, sessDict[UUID].get(key, False)) for UUID in sessDict.keys()]

    def getLogDict(self, UUID = ""):
        """获取日志字典
        参数列表:
            UUID:会话的UUID
        返回值：
            日志字典 参照__sessLogInfoDict定义
        异常：
            无
        """
        return self.getSessInfo(UUID, self.SESS_LOG_DK)

    def getCallNumber(self, UUID = ""):
        """获取呼叫号码
        参数列表:
            UUID:会话的UUID
        返回值：
            呼叫号码 str
        异常：
            无
        """
        return self.getSessInfo(UUID, self.SESS_FS_CALLNUMBER_DK)

    def getResultDict(self, UUID = ""):
        """获取结果字典
        参数列表:
            UUID:会话的UUID
        返回值：
            结果字典 {'conclusion':"", 'details':{}, 'note':""}
        异常：
            无
        """
        return self.getSessInfo(UUID, self.SESS_RESULT_DK)

    def getkeyInfoList(self, UUID = ""):
        """获取关键信息列表
        参数列表:
            UUID:会话的UUID
        返回值：
            关键信息 [(文件索引,行数,状态类型,(信息)),]
        异常：
            无
        """
        return self.getSessInfo(UUID, self.SESS_KEYINFO_DK)

    def getSignInfo(self, flag, context):
        """信令的收发方向(用于上层显示输出)
        参数列表:
            flag:keyInfoList中元组的‘状态类型’字段
            context:keyInfoList中元组的‘信息’字段
        返回值：
            元组(FromModule, ToModule, Sign)
        异常：
            无
        """
        if flag in [self.SIGN_FLAG_CHAN]:
            if context[0] in [self.SIGN_CHAN_CALLING]:
                return self.MOD_FS, self.MOD_OUTSIDE, self.SIP_INVITE
            elif context[0] in [self.SIGN_CHAN_PROCEDDING]:
                return self.MOD_OUTSIDE, self.MOD_FS, context[1]
            elif context[0] in [self.SIGN_CHAN_COMPLETE]:
                return self.MOD_OUTSIDE, self.MOD_FS, context[1]
            elif context[0] in [self.SIGN_CHAN_TERMINATED]:
                return self.MOD_OUTSIDE, self.MOD_FS, context[1]
        elif flag in [self.SIGN_FLAG_R_BYE]:
            return self.MOD_OUTSIDE, self.MOD_FS, self.SIP_BYE
        elif flag in [self.SIGN_FLAG_CANCEL]:
            return self.MOD_FS, self.MOD_OUTSIDE, self.SIP_CANCEL
        elif flag in [self.SIGN_FLAG_S_BYE]:
            return self.MOD_FS, self.MOD_OUTSIDE, self.SIP_BYE
        else:
            pass
        return '', '', ''

    # 按照会话，收集日志信息
    def __sessCollect(self):
        """按照UUID收集会话日志
        FS的日志，左边打印的就是会话UUID信息(36位数字或字母以‘-’连接的字符串，形如4541eb63-e5b0-49f0-8d2c-31e06078013f)
        函数读取日志的每一行，按照UUID进行会话归类，建立本地UUID为key的字典，再以文件索引和行数作为key为字典，value为日志内容。
        最后包含一些关键信息，如呼叫号码、分析结果、关键信息供分析器内部逻辑使用
        参数列表:
            无
        返回值：
            成功解析的会话日志字典和无法解析的会话日志字典 dict,dict
        异常：
            无
        """
        ignoreLinesDict = {}
        sessLogInfoDict = {}
        fileLen = len(self.getLines()) 
        process = 0
        for f, lines in enumerate(self.getLines()):
            process = self.printProc(process, fileLen)
            for i, line in enumerate(lines):
                # 例如：4541eb63-e5b0-49f0-8d2c-31e06078013f 2016-03-21 17:41:14.701532 [DEBUG] switch_core_state_machine.c:40 sofia/external/6010@10.0.7.152:5080 Standard INIT
                # 找到第一个空格，左边就是会话ID，右边就是日志信息
                pos = line.find(' ')
                line_len = len(line)
                # 若没有找到空格，则不记录（UUID都是36长度的，若不是，则不记录）
                if pos is -1 or pos < 36 or line[0:pos].count('-') != 4:
                    if f not in ignoreLinesDict:
                        ignoreLinesDict[f] = {}
                    else:
                        ignoreLinesDict[f][i] = line
                    continue

                # 拆分出UUID和日志信息
                sessUUID, sessLog = line[0:pos], line[pos + 1:-1]

                # 按照UUID归类存放日志信息
                if sessUUID in sessLogInfoDict:
                    if f not in sessLogInfoDict[sessUUID][self.SESS_LOG_DK]:
                        sessLogInfoDict[sessUUID][self.SESS_LOG_DK][f] = {i:sessLog}
                        if sessLogInfoDict[sessUUID][self.SESS_START_TIME_DK] is None:
                            sessLogInfoDict[sessUUID][self.SESS_START_TIME_DK] = self.getLogTime(sessLog)
                    else:
                        sessLogInfoDict[sessUUID][self.SESS_LOG_DK][f][i] = sessLog
                        if sessLogInfoDict[sessUUID][self.SESS_START_TIME_DK] is None:
                            sessLogInfoDict[sessUUID][self.SESS_START_TIME_DK] = self.getLogTime(sessLog)
                else:
                    sessLogInfoDict[sessUUID] = {self.SESS_LOG_DK:{f:{i:sessLog}}, self.SESS_FS_CALLNUMBER_DK:"", \
                        self.SESS_RESULT_DK:{self.SESS_RESULT_CONCLUSION_DK:"", self.SESS_RESULT_DETAILS_DK:{}, self.SESS_RESULT_NOTE_DK:""}, \
                        self.SESS_KEYINFO_DK:[], self.SESS_START_TIME_DK:self.getLogTime(sessLog)}
            else:
                self.__sessLogInfoDict = sessLogInfoDict
                self.__ignoreLinesDict = ignoreLinesDict

        for sessUUID in sessLogInfoDict.keys():
            if sessLogInfoDict[sessUUID][self.SESS_START_TIME_DK] is None:
                print(sessUUID, "\nis not get time")

        return sessLogInfoDict, ignoreLinesDict

    # 获取会话中的呼叫号码
    def __getCallNumber(self):
        """获取呼叫号码
        在建立了会话日志字典之后，分析每路会话，以正则的方式匹配提取其中的号码段，最后写入此路会话的字典信息callNumber中。
        号码的提取样例为(sofia/external/6010@10.0.7.152:5080)，其中的6010为号码
        参数列表:
            无
        返回值：
            无
        异常：
            无
        """
        sessLogInfoDict = self.getSessLogInfoDict()
        # 例如 2016-03-21 17:41:14.701532 [DEBUG] switch_core_state_machine.c:473 (sofia/external/6010@10.0.7.152:5080) Running State Change CS_INIT
        sessLen = len(sessLogInfoDict) 
        process = 0
        for sessUUID in sessLogInfoDict.keys():
            process = self.printProc(process, sessLen, widgetType = "percent")
            for f in sessLogInfoDict[sessUUID][self.SESS_LOG_DK].keys():
                flag = False
                for l in sessLogInfoDict[sessUUID][self.SESS_LOG_DK][f].keys():
                    # 取一行日志
                    sessLog = sessLogInfoDict[sessUUID][self.SESS_LOG_DK][f][l]
                    # 进行正则匹配，以"(sofia/external/"作为开头关键字，以")"作为结尾，"@"作为分隔，提取其中的号码
                    # 默认按照此行日志取号码
                    res = self.reMatch("New Channel sofia\/(.*)\/(\d*)\@(.*?) \[", sessLog, 3)
                    if res:
                        sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] = res[1]
                        flag = True

                    # 若有号码变换，需要取变换的号码
                    res = self.reMatch("Dialplan: sofia\/(.*)\/(.*) Action transfer\((\d*) XML default\)", sessLog, 3)
                    if res:
                        sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] = res[2]
                        flag = True
                        break

                    res = self.reMatch("<(\d*)>->(\d*) in context", sessLog, 2)
                    if res:
                        sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] = res[1]
                        flag = True
                        break

                if flag:
                    break
            # 没有找到号码，可能是日志文件的格式发生了变化
            else:
                #print "Not find the call number. UUID:%s" % sessUUID
                pass
        else:
            pass


    # 会话关键信息收集
    def __sessKeyInfoCollect(self):
        """会话关键信息收集
        在建立了会话日志字典之后，分析每路会话，以正则的方式匹配其中的状态转移和收取消息日志。
        例如：
        State Change CS_CONSUME_MEDIA -> CS_EXECUTE 为核心层状态机迁移 -- CS类
        Callstate Change ACTIVE -> HANGUP 为呼叫层状态机迁移 -- call类
        entering state [proceeding][180] 为收响应消息的处理 -- channel类
        AUDIO RTP [sofia/external/6797@10.0.7.152:5080] 10.0.7.176 port 24776 -> 192.168.0.178 port 7076 codec: 18 ms: 20 -- RTP信息类
        Hangup sofia/external/1920@10.0.7.152:5080 [CS_CONSUME_MEDIA] [INCOMPATIBLE_DESTINATION] -- 挂断原因类
        提取这些信息，并保存在会话字典的keyInfo中，其中以元祖的形式存放(文件索引,行号,匹配标志,提取的结果)
        参数列表:
            无
        返回值：
            无
        异常：
            无
        """
        sessLogInfoDict = self.getSessLogInfoDict()
        # 需要匹配的正则表达式
        reExpInfo = [
                ("State Change (.*) -> (.*)", 2, [], self.SIGN_FLAG_CS), # 状态转移类的日志
                ("entering state \[(.*)\]\[(.*)\]", 2, [], self.SIGN_FLAG_CHAN), # 收到消息类的日志
                ("Callstate Change (.*) -> (.*)", 2, [], self.SIGN_FLAG_CALL), # 呼叫状态类的日志
                ("receiving invite from (.*) version", 1, [], self.SIGN_FLAG_R_INVITE),
                ("AUDIO RTP \[(.*)\] (.*) port (\d+) -> (.*) port (\d+) codec: (\d+) ms: (\d+)", 7, [0], self.SIGN_FLAG_RTP), # RTP通道信息
                ("Flipping CID from \"(.*)\" \<(.*)\> to \"(.*)\" \<(.*)\>", 4, [], self.SIGN_FLAG_CALLNUMBER), # 呼叫号码
                ("952 Hangup (.*) \[(.*)\] \[(.*)\]", 3, [0], self.SIGN_FLAG_R_BYE),
                ("Hangup (.*) \[(.*)\] \[(.*)\]", 3, [0], self.SIGN_FLAG_HANGUP),
                ("Sending BYE to(.*)", 1, [0], self.SIGN_FLAG_S_BYE),
                ("Sending CANCEL to(.*)", 1, [0], self.SIGN_FLAG_CANCEL),
            ]
        sessLen = len(sessLogInfoDict) 
        process = 0
        for sessUUID in sessLogInfoDict.keys():
            process = self.printProc(process, sessLen, widgetType = "percent", begin=0, end=50)
            keyInfoList = []
            logFileDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
            fileList = sorted(logFileDict.items(), key=lambda logFileDict:logFileDict[0])
            for f, logDict in fileList:
                logList = sorted(logDict.items(), key=lambda logDict:logDict[0])
                for line, log in logList:
                    for reExpr, expLen, dropPos, flag in reExpInfo:
                        res = self.reMatch(reExpr, log, expLen)
                        if res:
                            l = list(res)
                            for dPos in [x for x in sorted(dropPos, reverse=True) if dropPos and x < len(res)]:
                                try:
                                    del l[dPos]
                                except Exception as Err:
                                    s = str(Err, reExpInfo[i], res)
                                    PRINT(s)
                                    raise
                            res = tuple(l)
                            keyInfoList.append((f, line, flag, res))
                            break       
            else:
                sessLogInfoDict[sessUUID][self.SESS_KEYINFO_DK] = keyInfoList

    def __match(self, keyInfoList, flag, param1 = "", param2 = "", f = -1, l = -1, mod="normal"):
        l = [(i, x) for i, x in enumerate(keyInfoList) if x[2] == flag and \
                ((len(x[3]) >= 1 and param1.strip() == x[3][0].strip()) if param1 != "" else True) and \
                ((len(x[3]) >= 2 and param2.strip() == x[3][1].strip()) if param2 != "" else True) and \
                (x[0] >= f if f != -1 else True) and \
                (x[1] >= l if l != -1 else True)]
        if mod in [self.MATCH_MOD_NORMAL]:
            return any(l)
        elif mod in [self.MATCH_MOD_EXTEND]:
            return (l[0][1][0], l[0][1][1], l[0][0]) if any(l) else False
        elif mod in [self.MATCH_MOD_DETAILS]:
            return l[0][1][3] if any(l) else False
        else:
            return False

    def __matchCsStateChange(self, keyInfoList, fromState, toState):
        """CS状态变迁匹配
        参数列表:
            keyInfoList:关键信息列表
            fromState:迁移前的状态
            toState:迁移到的状态
        返回值：
            成功或失败 bool
        异常：
            无
        """
        return self.__match(keyInfoList, self.SIGN_FLAG_CS, fromState, toState)

    def __matchCallStateChange(self, keyInfoList, fromState, toState):
        """call状态变迁匹配
        参数列表:
            keyInfoList:关键信息列表
            fromState:迁移前的状态
            toState:迁移到的状态
        返回值：
            成功或失败 bool
        异常：
            无
        """
        return self.__match(keyInfoList, self.SIGN_FLAG_CALL, fromState, toState)

    def __fuzzyMatchChannelStateCode(self, keyInfoList, fuzzyCode):
        """通道状态码模糊匹配
        模糊码以X代表一个任意数字位，例如4XX，则为匹配4开头应答码
        参数列表:
            keyInfoList:关键信息列表
            fuzzyCode:模糊状态码
        返回值：
            匹配到的值
        异常：
            无
        """
        codeList = []
        for x in keyInfoList:
            if x[2] == self.SIGN_FLAG_CHAN:
                reExpr = "(" + fuzzyCode.replace("X","\\d").replace("x", "\\d") + ")"
                res = self.reMatch(reExpr, x[3][1], 1)
                res and codeList.append(x[3])
        return codeList

    def __matchChannelStateCode(self, keyInfoList, code):
        """通道状态码匹配
        精确匹配状态码
        参数列表:
            keyInfoList:关键信息列表
            code:状态码
        返回值：
            成功或失败 bool
        异常：
            无
        """
        return self.__match(keyInfoList, self.SIGN_FLAG_CHAN, param2 = code)

    def __matchChannelStateDesc(self, keyInfoList, desc):
        """通道状态描述匹配
        匹配状态描述
        参数列表:
            keyInfoList:关键信息列表
            desc:描述
        返回值：
            成功或失败 bool
        异常：
            无
        """
        return self.__match(keyInfoList, self.SIGN_FLAG_CHAN, param1 = desc)

    # 分析会话过程
    def __sessAnalysis(self):
        """会话分析
        分析每路会话的状态变迁过程。首先确定有哪些状态在变迁，然后建立状态迁移标准模板，去匹配其中的过程
        参数列表:
            无
        返回值：
            无
        异常：
            无
        """
        sessLogInfoDict = self.getSessLogInfoDict()
        sessLen = len(sessLogInfoDict) 
        process = 0
        for sessUUID in sessLogInfoDict.keys():
            process = self.printProc(process, sessLen, widgetType = "percent", begin=50, end=100)
            keyInfoList = sessLogInfoDict[sessUUID][self.SESS_KEYINFO_DK]
            #if sessUUID == "4befcdab-a4cc-4d6a-979f-bbff65d729b0":
            #    print("\n")
            #    for k in keyInfoList:
            #        print(k)
            conclusion = ""
            note = ""
            detailsDict = {
                "CS_NEW__CS_INIT": self.__matchCsStateChange(keyInfoList, "CS_NEW", "CS_INIT"),
                "CS_INIT__CS_ROUTING": self.__matchCsStateChange(keyInfoList, "CS_INIT", "CS_ROUTING"),
                "CS_ROUTING__CS_CONSUME_MEDIA": self.__matchCsStateChange(keyInfoList, "CS_ROUTING", "CS_CONSUME_MEDIA"),
                "CS_CONSUME_MEDIA__CS_EXECUTE": self.__matchCsStateChange(keyInfoList, "CS_CONSUME_MEDIA", "CS_EXECUTE"),

                "DOWN__RINGING": self.__matchCallStateChange(keyInfoList, "DOWN", "RINGING"),
                "DOWN__EARLY": self.__matchCallStateChange(keyInfoList, "DOWN", "EARLY"),
                "DOWN__ACTIVE": self.__matchCallStateChange(keyInfoList, "DOWN", "ACTIVE"),
                "EARLY__RINGING": self.__matchCallStateChange(keyInfoList, "EARLY", "RINGING"),
                "EARLY__ACTIVE": self.__matchCallStateChange(keyInfoList, "EARLY", "ACTIVE"),
                "RINGING__ACTIVE": self.__matchCallStateChange(keyInfoList, "RINGING", "ACTIVE"),
                "DOWN__HANGUP": self.__matchCallStateChange(keyInfoList, "DOWN", "HANGUP"),
                "EARLY__HANGUP": self.__matchCallStateChange(keyInfoList, "EARLY", "HANGUP"),
                "RINGING__HANGUP": self.__matchCallStateChange(keyInfoList, "RINGING", "HANGUP"),
                "ACTIVE__HANGUP": self.__matchCallStateChange(keyInfoList, "ACTIVE", "HANGUP"),

                "calling_0": self.__matchChannelStateDesc(keyInfoList, "calling"),
                "proceeding_180": self.__matchChannelStateCode(keyInfoList, "180"),
                "proceeding_183": self.__matchChannelStateCode(keyInfoList, "183"),
                "completing_200": self.__matchChannelStateDesc(keyInfoList, "completing"),
                "completed_200": self.__matchChannelStateDesc(keyInfoList, "completed"),
                "ready_200": self.__matchChannelStateDesc(keyInfoList, "ready"),
                "terminated_list": self.__fuzzyMatchChannelStateCode(keyInfoList, "4xx") + \
                    self.__fuzzyMatchChannelStateCode(keyInfoList, "5xx") + \
                    self.__fuzzyMatchChannelStateCode(keyInfoList, "6xx"),
                }

            # 标志性处理类的状态
            case_calling_invite = {"CS_INIT__CS_ROUTING":True, "CS_ROUTING__CS_CONSUME_MEDIA":True, "calling_0":True,}
            case_ringing_180 = {"proceeding_180":True,}
            case_ringing_183 = {"proceeding_183":True,}
            case_ringinged_180 = {"DOWN__RINGING":True,}
            case_ringinged_183 = {"DOWN__EARLY":True,}
            case_ringing_183_180 = {"DOWN__EARLY":True, "proceeding_183":True, "EARLY__RINGING":True, "proceeding_180":True,}
            case_answer_invite = {"DOWN__ACTIVE":True, "completing_200":True, "ready_200":True,}
            case_answerd_invite = {"DOWN__ACTIVE":True, "completed_200":True, "ready_200":True,}
            case_answer_180 = {"RINGING__ACTIVE":True, "completing_200":True, "ready_200":True,}
            case_answerd_180 = {"RINGING__ACTIVE":True, "completed_200":True, "ready_200":True,}
            case_answer_183 = {"EARLY__ACTIVE":True, "completing_200":True, "ready_200":True,}
            case_answerd_183 = {"EARLY__ACTIVE":True, "completed_200":True, "ready_200":True,}
            case_hangup_invite = {"DOWN__HANGUP":True,}
            case_hangup_180 = {"RINGING__HANGUP":True,}
            case_hangup_183 = {"EARLY__HANGUP":True,}
            case_hangup_acitve = {"ACTIVE__HANGUP":True,}

            case_r_183 = {"proceeding_183":True,}

            # invite->
            if self.caseMatch(detailsDict, case_calling_invite) or self.__match(keyInfoList, self.SIGN_FLAG_R_INVITE):
                conclusion = "OK"
                note = "[CALLING" + (self.__match(keyInfoList, self.SIGN_FLAG_R_INVITE) and "(R)" or "(S)")

                # invite-> 200<-
                if self.caseMatch(detailsDict, case_answer_invite):
                    note += " -> TALKING"
                    # invite-> 200<- bye<->
                    if self.caseMatch(detailsDict, case_hangup_acitve):
                        note += " -> HANGUP" + (self.__match(keyInfoList, self.SIGN_FLAG_S_BYE) and "(S)" or "(R)")
                # invite-> (bye-> or 错误应答<-)
                elif self.caseMatch(detailsDict, case_hangup_invite):
                    if self.caseMatch(detailsDict, case_r_183):
                        note += " -> RINGING(183)"
                    note += " -> HANGUP" + (self.__match(keyInfoList, self.SIGN_FLAG_S_BYE) and "(S)" or "(R)")
                else:
                    # invite-> (183<- or 180<-)
                    if self.caseMatch(detailsDict, case_ringing_180) or self.caseMatch(detailsDict, case_ringing_183) or self.caseMatch(detailsDict, case_ringing_183_180) or \
                        self.caseMatch(detailsDict, case_ringinged_180) or self.caseMatch(detailsDict, case_ringinged_183):
                        note += " -> RINGING"
                        # invite-> (183<- or 180<-) 200<-
                        if self.caseMatch(detailsDict, case_answer_180) or self.caseMatch(detailsDict, case_answerd_180) or \
                            self.caseMatch(detailsDict, case_answer_183) or self.caseMatch(detailsDict, case_answerd_183):
                            note += " -> TALKING"
                            # invite-> (183<- or 180<-) 200<- bye<->
                            if self.caseMatch(detailsDict, case_hangup_acitve):
                                note += " -> HANGUP" + (self.__match(keyInfoList, self.SIGN_FLAG_S_BYE) and "(S)" or "(R)")
                        # invite-> (183<- or 180<-) 错误应答<-
                        elif self.caseMatch(detailsDict, case_hangup_180) or self.caseMatch(detailsDict, case_hangup_183):
                            note += " -> HANGUP" + (self.__match(keyInfoList, self.SIGN_FLAG_S_BYE) and "(S)" or "(R)")
            
                # 判断挂断原因
                res = self.__match(keyInfoList, self.SIGN_FLAG_HANGUP, mod = self.MATCH_MOD_DETAILS)
                st, reason = res if res else ("", "")
                if reason:
                    note += "{[" + st + "]" + reason + "}"
                    if reason not in ["NORMAL_CLEARING", "MANAGER_REQUEST"]:
                        conclusion = "ERROR"
                else:
                    res = self.__match(keyInfoList, self.SIGN_FLAG_R_BYE, mod = self.MATCH_MOD_DETAILS)
                    st, reason = res if res else ("", "")
                    if reason:
                        note += "{[" + st + "]" + reason + "}"
                        if reason not in ["NORMAL_CLEARING", "MANAGER_REQUEST"]:
                            conclusion = "ERROR"

                if detailsDict["terminated_list"]:
                    conclusion = "ERROR"
                    note += "(recv %s)" % detailsDict["terminated_list"][0][1]

            else:
                conclusion = "WARNING"
                note += "[NOT COMPLETE"

            note += "]"
            sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_NOTE_DK] = note
            sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_DETAILS_DK] = detailsDict
            sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_CONCLUSION_DK] = conclusion
            # print "\n", sessLogInfoDict[sessUUID]["callNumber"], sessLogInfoDict[sessUUID]["result"]["conclusion"], note,#, "\n", keyInfoList, "\n",detailsDict, "\n"
                
    # 分析会话日志
    def __analysis(self):
        self.__sessKeyInfoCollect()
        self.__sessAnalysis()

    # 运行
    def run(self, mode = "Normal"):
        time1 = time.clock()
        s = "正在收集会话信息..."
        PRINT(s, end='')
        self.__sessCollect()
        time2 = time.clock()
        s = "OK (耗时：%.2f秒)" % (time2 - time1)
        PRINT(s, color='green')

        s = "正在提取号码..."
        PRINT(s, end='')
        self.__getCallNumber()
        time3 = time.clock()
        s = "OK (耗时：%.2f秒)" % (time3 - time2)
        PRINT(s, color='green')
        
        s = "正在分析会话过程..."
        PRINT(s, end='')
        self.__analysis()
        time4 = time.clock()
        s = "OK (耗时：%.2f秒)" % (time4 - time3)
        PRINT(s, color='green')
        
        return True, ""

    # 获取UUID列表
    def getSessUUIDList(self):
        sessLogInfoDict = self.getSessLogInfoDict()
        return sessLogInfoDict.keys()

    # 获取呼叫号码列表
    def getCallNumberList(self):
        sessLogInfoDict = self.getSessLogInfoDict()
        return [sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] for sessUUID in sessLogInfoDict.keys() if sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK]]


    # 显示UUID列表
    def showSessUUIDList(self):
        sessUUIDList = self.getSessUUIDList()
        self.printList(sessUUIDList, 4, "UUID列表:", "总数：%d" % len(sessUUIDList))
        
    # 显示呼叫号码列表
    def showCallNumberList(self):
        # 呼叫号码
        callNumberList = self.getCallNumberList()
        tmp = set(callNumberList)
        self.printList(tmp, 8, "呼叫号码列表:", "总数：%d" % len(tmp))

        # 重复的呼叫号码
        dupl = self.findDupl(callNumberList)
        len(dupl) and self.printList(dupl, 8, "重复的号码:", "总数：%d" % len(dupl))

    # ----------------------------------------------显示详细分析结果----------------------------------------------

    def __showDetailsHeader(self, sessUUID = "", callNumber = "", conclusion = ""):
        return ""

    def getDetails(self, sessUUID = "", targConclusion = "", mode = "normal"):
        sessLogInfoDict = self.getSessLogInfoDict()
        if not sessLogInfoDict.get(sessUUID, False):
            return ""

        conclusion = sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_CONCLUSION_DK]
        if targConclusion.upper() not in conclusion.upper():
            return ""

        logDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
        keyInfoList = sessLogInfoDict[sessUUID][self.SESS_KEYINFO_DK]
        if not logDict or not keyInfoList:
            return ""

        res = self.__match(keyInfoList, self.SIGN_FLAG_CALLNUMBER, mod = self.MATCH_MOD_DETAILS)
        disFrom, numberFrom, disTo, numberTo = res if res else ("","","","")
        
        callTime = "%s" % self.getLogTime(logDict.get(keyInfoList[0][0], {}).get(keyInfoList[0][1], ""))
        
        res = self.__match(keyInfoList, self.SIGN_FLAG_RTP, mod = self.MATCH_MOD_DETAILS)
        locIp, locPort, RmtIp, RmtPort, audioPayLoad, audioPTime = res if res else ("","","","","","")
        note = sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_NOTE_DK]
        s = ""
        if mode in ['normal']:
            s += "-" * 160 + "\n"
            s += "\n" + "{0:*^160}".format(" 基本信息 ") + "\n\n"
            s += "%-16s: %-s\n" % ("呼叫开始时间", callTime)
            s += "%-16s: %-s\n" % ("UUID", sessUUID)
            if numberFrom:
                s += "%-16s: %-s\n" % ("显示号码", numberFrom)
            s += "%-16s: %-s\n" % ("呼叫号码", numberTo or sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK])
        
        if locIp and RmtIp:
            s += "%-16s: %s:%s:%s -> %s:%s:%s (%s:%s %s:%s)\n" % ("媒体信息", "本端地址", locIp, locPort, "远端地址", RmtIp, RmtPort, "Payload", audioPayLoad, "ptime", audioPTime)
        
        res = self.__match(keyInfoList, self.SIGN_FLAG_HANGUP, mod = self.MATCH_MOD_DETAILS)
        reason = res[1] if res else ""
        if reason:
            res = self.__match(keyInfoList, self.SIGN_FLAG_CHAN, param1 = self.SIGN_CHAN_TERMINATED, mod = self.MATCH_MOD_DETAILS)
            s +=  "%-16s: %s\n" % ("挂断原因", res[1] if res else reason)
        else:
            res = self.__match(keyInfoList, self.SIGN_FLAG_R_BYE, mod = self.MATCH_MOD_DETAILS)
            reason = res[1] if res else ""
            if reason:
                res = self.__match(keyInfoList, self.SIGN_FLAG_CHAN, param1 = self.SIGN_CHAN_TERMINATED, mod = self.MATCH_MOD_DETAILS)
                s +=  "%-16s: %s\n" % ("挂断原因", res[1] if res else reason)

        signTimePrev = None
        signTimeThis = None
        
        if mode in ['normal']:
            s += "%-16s: %-s\n" % ("结果", conclusion)
            s += "%-16s: %-s\n" % ("消息流", self.showNote(note))
            s += "\n" + "{0:*^160}".format(" 消息交互详情 ") + "\n\n"
            s += "%-4s %-35s %-16s %-16s %s\n\n" % ("序号","信令时间", "源日志行号", "消息类型", "详情")
            l = []
            for i, k in enumerate(keyInfoList):
                
                signTime = "%s" % self.getLogTime(logDict.get(k[0], {}).get(k[1], ""))
                res = self.reMatch("(\\d{4})-(\\d{1,2})-(\\d{1,2}) (\\d{2}):(\\d{2}):(\\d{2}).(\\d{6})", signTime, 7)
                if res:
                    signTimePrev = signTimeThis
                    signTimeThis = datetime(int(res[0]), int(res[1]), int(res[2]), int(res[3]), int(res[4]), int(res[5]))
                    if signTimePrev and (signTimeThis - signTimePrev).seconds > 4:
                        s += "{0:^40}".format(" ↑ ") + "\n"
                        s += "%s \n" % getColor("{0:^40}".format("时差:" + str((signTimeThis - signTimePrev).seconds) + "s", color="red", need=True))
                        s += "{0:^40}".format(" ↓ ") + "\n"
                
                if k[0] not in l:
                    s += self.getPathEx(k[0]) + "\n"
                    l.append(k[0])
                
                s += "%02d.  %-35s %-16s %-16s %s\n" % (i + 1, signTime, str(k[1]), str(k[2]), str(k[3]))
            else:
                s += "\n"

        return s

    def __showDetailsBody(self, sessUUID = "", targConclusion = ""):
        s = self.getDetails(sessUUID, targConclusion)
        if s:
            PRINT(s)
        return s

    def __showDetailsTail(self, count, sessUUID = "", callNumber = "", conclusion = ""):
        s = "-" * 160 + "\n"
        s += "\n总数：%d" % count
        PRINT(s)
        return s

    def __showDetails(self, sessUUID = "", callNumber = "", conclusion = ""):
        sessLogInfoDict = self.getSessLogInfoDict()
        
        # 显示头
        self.__showDetailsHeader()
        
        # 显示Body
        count = 0
        if sessUUID:
            # 若输入了callNumber
            if (callNumber == sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] if callNumber else True) and \
                self.__showDetailsBody(sessUUID, conclusion):
                    count += 1
        else:
            total = len(sessLogInfoDict)
            flag = False
            sessList = sorted(sessLogInfoDict.items(), key=lambda sessLogInfoDict:sessLogInfoDict[1][self.SESS_START_TIME_DK])
            for i, (sessUUID, context) in enumerate(sessList):
                # 若输入了callNumber
                if (callNumber == context[self.SESS_FS_CALLNUMBER_DK] if callNumber else True) and \
                    self.__showDetailsBody(sessUUID, conclusion):
                        count += 1
                        continueRet, flag = self.inputContinue(i, count, total, flag, self.__showDetailsHeader)
                        if not continueRet:
                            break
        # 显示尾
        self.__showDetailsTail(count)
        return count


    # 按照UUID搜索日志，并显示详细分析信息
    def showDetails(self, sessUUID = "", callNumber = "", conclusion = ""):
        return self.__showDetails(sessUUID = sessUUID, callNumber = callNumber, conclusion = conclusion)

    # ----------------------------------------------显示分析结果----------------------------------------------

    def __showAnalysisResultHeader(self, targConclusion=""):
        s = "%-30s %-36s %-30s %-7s %-s\n" % ("呼叫开始时间", "UUID", "呼叫号码", "结果", "备注")
        PRINT(s)

    def __getAnalysisResultBody(self, sessUUID, targConclusion = "", show = True):
        sessLogInfoDict = self.getSessLogInfoDict()
        s = ""
        conclusion = ""
        if sessLogInfoDict.get(sessUUID, False):
            logDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
            keyInfoList = sessLogInfoDict[sessUUID][self.SESS_KEYINFO_DK]
            if not keyInfoList or not logDict:
                return s, conclusion
            callTime = "%s" % self.getLogTime(logDict.get(keyInfoList[0][0]).get(keyInfoList[0][1]))
            callNumber = sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK]
            conclusion = sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_CONCLUSION_DK]
            note = sessLogInfoDict[sessUUID][self.SESS_RESULT_DK][self.SESS_RESULT_NOTE_DK]
            if targConclusion.upper() in conclusion.upper():
                color = conclusion.upper() in ['ERROR'] and 'red' or \
                    conclusion.upper() in ['WARNING'] and 'yellow' or \
                    conclusion.upper() in ['OK'] and 'green'
                conclusion = getColor("{0:<7}".format(conclusion), color = color)
                s += "%-30s %-36s %-30s %-7s %-s\n" % (callTime, sessUUID, callNumber or getColor("{0:<20}".format("null"), color='gray', need=show), conclusion, note)
        return s, conclusion

    def __showAnalysisResultBody(self, sessUUID, targConclusion = ""):
        s, c = self.__getAnalysisResultBody(sessUUID, targConclusion)
        if s:
            PRINT(s)
        return s

    def __showAnalysisResultTail(self, count, targConclusion=""):
        s = "\n总数：%d" % count
        PRINT(s)
        
    def __showResult(self, sessUUID = "", callNumber = "", conclusion = ""):
        sessLogInfoDict = self.getSessLogInfoDict()
        # 显示头
        self.__showAnalysisResultHeader(conclusion)
        
        # 显示Body
        count = 0
        if sessUUID:
            # 若输入了callNumber则认为需要过滤
            if (callNumber == sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] if callNumber else True) \
                and self.__showAnalysisResultBody(sessUUID, conclusion):
                    count += 1
        else:
            total = len(sessLogInfoDict)
            flag = False
            sessList = sorted(sessLogInfoDict.items(), key=lambda sessLogInfoDict:sessLogInfoDict[1][self.SESS_START_TIME_DK])
            for i, (sessUUID, context) in enumerate(sessList):
                # 若输入了callNumber或UUID则认为需要过滤
                if (callNumber == context[self.SESS_FS_CALLNUMBER_DK] if callNumber else True) \
                    and self.__showAnalysisResultBody(sessUUID, conclusion):
                        count += 1
                        # 输出分段，提示是否继续显示内容
                        continueRet, flag = self.inputContinue(i, count, total, flag, self.__showAnalysisResultHeader, conclusion)
                        if not continueRet:
                            break
        # 显示尾
        self.__showAnalysisResultTail(count, conclusion)
        return count

    def showResult(self, sessUUID = "", callNumber = "", conclusion = ""):
        return self.__showResult(sessUUID = sessUUID, callNumber = callNumber, conclusion = conclusion)
    
    # ----------------------------------------------输出简单分析结果到文件----------------------------------------------

    def __getOutputResultHeader(self):
        s = "%-30s %-36s %-30s %-6s %s\n" % ("呼叫开始时间", "UUID", "呼叫号码", "结果", "备注")
        return s

    def __getOutputResultTail(self, warningCount, errorCount, okCount):
        s = "%s:%d\n%s:%d\n%s:%d\n%s:%d\n" % ("总计", errorCount + okCount + warningCount, "告警", warningCount, "失败", errorCount, "成功", okCount)
        return s

    def __outputReslut(self, outputPath, sessUUID = "", callNumber = "", conclusion = "", fileName = ""):
        sessLogInfoDict = self.getSessLogInfoDict()

        # 确定新的目录，以源日志文件名作为目录名
        if not fileName:
            #fileNames = "_".join([os.path.split(p)[-1] for p in self.getPath()])
            fileNames = sessUUID + callNumber + conclusion + "_tmp"
            fileName = "Result" + fileNames + self.OUTPUT_POSTFIX_RESULT
        
        context = ""
        warningCount, errorCount, okCount = 0, 0, 0
        # 输出到文件
        if sessUUID:
            if (callNumber == sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] if callNumber else True):
                s, c = self.__getAnalysisResultBody(sessUUID, conclusion, show=False)
                context += s
                if s and c.upper() in ['ERROR']:
                    errorCount += 1
                elif s and c.upper() in ['WARNING']:
                    warningCount += 1
                elif s and c.upper() in ['OK']:
                    okCount += 1
        else:    
            for sessUUID in sessLogInfoDict.keys():
                if (callNumber == sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK] if callNumber else True):
                    s, c = self.__getAnalysisResultBody(sessUUID, conclusion, show=False)
                    context += s
                    if s and c.upper() in ['ERROR']:
                        errorCount += 1
                    elif s and c.upper() in ['WARNING']:
                        warningCount += 1
                    elif s and c.upper() in ['OK']:
                        okCount += 1

        if context:
            context = self.__getOutputResultHeader() + context
            context += self.__getOutputResultTail(warningCount, errorCount, okCount)
            if self.outputEx(outputPath, fileName, context):
                return 1, outputPath, [fileName]
            else:
                return 0, outputPath, []
        else:
            return 0, outputPath, []

    # 输出简单分析结果到文件
    def outputReslut(self, outputPath, sessUUID = "", callNumber = "", conclusion = "", fileName = ""):
       return self.__outputReslut(outputPath, sessUUID = sessUUID, callNumber = callNumber, conclusion = conclusion, fileName = fileName)

    # ----------------------------------------------输出原始日志到文件----------------------------------------------

    def __getOutputHeader(self, logDict, callNumber, sessUUID):
        s = "呼叫号码：%s\nUUID:%s\n" % (callNumber, sessUUID)
        return s

    def __outputOriginLog(self, outputPath, sessUUID = "", callNumber = "", name = ""):
        sessLogInfoDict = self.getSessLogInfoDict()

        newPath = outputPath
        fileNameList = [] # 输出的文件列表

        # 如果存在UUID（只输出一个文件）
        if sessUUID:
            if sessLogInfoDict.get(sessUUID, False):
                logDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
                # 若输入了号码，则需要过滤号码
                c =  sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK]
                if (callNumber == c if callNumber else True):
                    fileName = name or ((callNumber or c) + "__" + sessUUID + self.OUTPUT_POSTFIX_LOG)
                    if self.output(logDict, newPath, fileName, self.__getOutputHeader(logDict, c, sessUUID)):
                        fileNameList.append(fileName)
        
        # 不存在UUID（可能输出多个文件）
        else:
            # 确定新的目录，若指定了文件名，则以指定的为准，否则以源日志文件名作为目录名
            if not name:
                #fileNames = "_".join([os.path.split(p)[-1] for p in self.getPath()])
                fileNames = sessUUID + callNumber + "_tmp"
                newPath = os.path.join(outputPath, fileNames)
            else:
                newPath = os.path.join(outputPath, name)

            # 创建新的目录，若存在则删除
            self.makeDir(newPath)
            for sessUUID in sessLogInfoDict.keys():
                logDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
                # 若输入了号码，则需要过滤号码
                c =  sessLogInfoDict[sessUUID][self.SESS_FS_CALLNUMBER_DK]
                if (callNumber == c if callNumber else True):
                    fileName = (callNumber or c) + "__" + sessUUID + self.OUTPUT_POSTFIX_LOG
                    if self.output(logDict, newPath, fileName, self.__getOutputHeader(logDict, c, sessUUID)):
                        fileNameList.append(fileName)
        return len(fileNameList), newPath, fileNameList

    def outputOriginLog(self, outputPath, sessUUID = "", callNumber = "", name = ""):
        return self.__outputOriginLog(outputPath, sessUUID = sessUUID, callNumber = callNumber, name = name)
    
    # ----------------------------------------------输出详细分析结果到文件----------------------------------------------

    def __outputDetails(self, outputPath, fileName = "", callNumber = "", sessUUID = "", targConclusion=""):
        fileNameList = []
        sessLogInfoDict = self.getSessLogInfoDict()
        newPath = outputPath
        if sessUUID:
            sessDict = sessLogInfoDict.get(sessUUID, False)
            if not sessDict:
                return len(fileNameList), newPath, fileNameList

            if sessDict[self.SESS_FS_CALLNUMBER_DK] == callNumber if callNumber else True:
                logDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
                newFileName = fileName or (sessDict[self.SESS_FS_CALLNUMBER_DK] + "__" + sessUUID + "__" + targConclusion + self.OUTPUT_POSTFIX_DETAILS)
                if self.outputEx(newPath, newFileName, self.getDetails(sessUUID, targConclusion)):
                    fileNameList.append(newFileName)
        else:
            if not callNumber:
                # 确定新的目录，以源日志文件名作为目录名
                if not fileName:
                    #orgLogFileNames = "_".join([os.path.split(p)[-1] for p in self.getPath()])
                    orgLogFileNames = callNumber + sessUUID + targConclusion + "_tmp"
                    newPath = os.path.join(outputPath, orgLogFileNames)
                else:
                    newPath = os.path.join(outputPath, fileName)

                # 创建新的目录
                if not self.makeDir(newPath):
                    return len(fileNameList), newPath, fileNameList

            for sessUUID in sessLogInfoDict.keys():
                sessDict = sessLogInfoDict[sessUUID]
                if sessDict[self.SESS_FS_CALLNUMBER_DK] == callNumber if callNumber else True:
                    logDict = sessLogInfoDict[sessUUID][self.SESS_LOG_DK]
                    newFileName = sessDict[self.SESS_FS_CALLNUMBER_DK] + "__" + sessUUID + "__" + targConclusion + self.OUTPUT_POSTFIX_DETAILS
                    if self.outputEx(newPath, newFileName, self.getDetails(sessUUID, targConclusion)):
                        fileNameList.append(newFileName)

        return len(fileNameList), newPath, fileNameList

    def outputDetails(self, outputPath, fileName = "", sessUUID = "", callNumber = "", conclusion = ""):
        return self.__outputDetails(outputPath, fileName = fileName, sessUUID = sessUUID, callNumber = callNumber, targConclusion = conclusion)
