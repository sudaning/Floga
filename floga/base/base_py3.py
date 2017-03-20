# -*- coding: utf-8 -*-
import sys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY3:
    from base.base import getColor

    def unicode(s, code):
        return s

    def INPUT(s, color = 'white'):
        s = getColor(s, color = color)
        return input(unicode(s, 'cp936'))

    def PRINT(s, end='\n', color = 'white'):
        s = getColor(s, color = color)
        print(unicode(s, 'cp936'), end=end)

    def WRITELINES(f, s):
        f.writelines(unicode(s, 'cp936'))
