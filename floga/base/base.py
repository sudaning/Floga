# -*- coding: utf-8 -*-
import sys
from platform import system as osys

PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

def getColor(s, color = 'white', need = True):
    if osys() in ['Linux'] and need:
        color_code = color.lower() == 'red' and 91 or \
            color.lower() == 'yellow' and 93 or \
            color.lower() == 'blue' and 94 or \
            color.lower() == 'green' and 92 or \
            color.lower() == 'purple' and 95 or \
            color.lower() == 'gray' and 90 or \
            97

        return '\033[0m\033[' + str(color_code) + 'm' + s + '\033[0m'
    else:
        return s

def getTerminalSize():
    import os
    env = os.environ
    def ioctl_GWINSZ(fd):
        try:
            import fcntl, termios, struct, os
            cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,
        '1234'))
        except:
            return
        return cr
    cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = ioctl_GWINSZ(fd)
            os.close(fd)
        except:
            pass
    if not cr:
        cr = (env.get('LINES', 25), env.get('COLUMNS', 80))

        ### Use get(key[, default]) instead of a try/catch
        #try:
        #    cr = (env['LINES'], env['COLUMNS'])
        #except:
        #    cr = (25, 80)
    return int(cr[1]), int(cr[0])

def getPathSeparator():
    if osys() in ['Linux']:
        return "/"
    elif osys() in ['Windows']:
        return "\\"
    else:
        return "\\"
        
if PY2:
    from base_py2 import INPUT, PRINT, WRITELINES
else:
    from base.base_py3 import INPUT, PRINT, WRITELINES

