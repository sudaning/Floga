# -*- coding: utf-8 -*-
import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY2:
    from base import getColor

    def INPUT(s, color = 'white'):
        s = getColor(s, color = color)
        print unicode(s, 'cp936'), 
        readline = sys.stdin.readline()[:-1]
        print("")
        return readline

    def PRINT(s, end='\n', color = 'white'):
        s = getColor(s, color = color)
        if end == '':
            print unicode(s, 'cp936'),
        else:
            print(unicode(s, 'cp936'))

    def WRITELINES(f, s):
        f.writelines(unicode(s, 'cp936'))


