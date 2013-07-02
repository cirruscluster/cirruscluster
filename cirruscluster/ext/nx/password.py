#!/usr/bin/env python
# ================================================================
# $Id: nxpasswd.py,v 1.2 2012/02/06 00:04:31 jlinoff Exp jlinoff $
#
# Implements the password scrambling algorithm used by NX in python as
# defined here:
#
# http://www.nomachine.com/ar/view.php?ar_id=AR01C00125
# https://gist.github.com/902387
#
# Usage:
#    ./nxpasswd.py <password>
# ================================================================
import os
import sys
import string
import time
import sys
import re

validCharList = [
         "!", "#", "$", "%", "&", "(", ")", "*", "+", "-",
         ".", "0", "1", "2", "3", "4", "5", "6", "7", "8",
         "9", ":", ";", "<", ">", "?", "@", "A", "B", "C",
         "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
         "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W",
         "X", "Y", "Z", "[", "]", "_", "a", "b", "c", "d",
         "e", "f", "g", "h", "i", "j", "k", "l", "m", "n",
         "o", "p", "q", "r", "s", "t", "u", "v", "w", "x",
         "y", "z", "{", "|", "}"
         ]

def encodePassword(p):
    sPass = ":"
    sTmp = ""

    if p in ['', None]:
        return ''

    for i in range(len(p)):
        sPass += '%d:' % (ord(p[i])+i+1)

    return sPass

def findCharInList(c):
    global validCharList
    for i in range(len(validCharList)):
        if validCharList[i] == c:
            return i
    return -1

def getRandomValidCharFromList():
    global validCharList
    lt = time.localtime()
    s = lt.tm_sec
    if os.getenv('NXPASSWD_NONRANDOM'):
        s = int(os.getenv('NXPASSWD_NONRANDOM'))
    return validCharList[s]

def URLEncode(url):
    url = url.replace('&','&amp;')
    url = url.replace('"','&quot;')
    url = url.replace("'",'&apos;')
    url = url.replace('<','&lt;')
    url = url.replace('>','&gt;')
    return url

def ScrambleString(s):
    global validCharList
    dummyString = "{{{{"
    sRet = ''
    
    if s in ['', None]:
        return ''
    
    s1 = encodePassword(s)
    
    if len(s1) < 32:
        sRet += dummyString
        
    sRet += s1[::-1]  # reverse string
    
    if len(sRet) < 32:
        sRet += dummyString

    ch = getRandomValidCharFromList()
    k = ord(ch) + len(sRet) - 2
    sRet = ch + sRet
    
    for i in range(1,len(sRet)):
        j = findCharInList(sRet[i])
        if j == -1:
            return sRet
        n = (j + k * (i+1)) % len(validCharList)
        sRet = sRet[:i] + validCharList[n] + sRet[i+1:]

    sRet += chr((ord(getRandomValidCharFromList())) + 2)
    sRet = URLEncode(sRet)
    return sRet



def URLDecode(url):
    url = url.replace('&amp;','&')
    url = url.replace('&quot;','"')
    url = url.replace('&apos;',"'")
    url = url.replace('&lt;','<')
    url = url.replace('&gt;','>')
    return url



def findCharInList(c):
    global validCharList
    for i in range(len(validCharList)):
        if validCharList[i] == c:
            return i
    return -1

def findK(ch0,i=5,chf=':'):
    global validCharList
    j = findCharInList(chf)
    for k in range(0,200):
        n = (j + k * (i+1)) % len(validCharList)
        m = validCharList[n]
        if m == ch0:
            return k
    return -1

def UnScrambleString(scramble):
    scramble=URLDecode(scramble)

    # Were dummy strings appended/prepended?
    # Need 3 tests to check.
    tests = []
    scramble=scramble[1:]
    scramble=scramble[:-1]
    tests.append([scramble,0])

    scramble=scramble[4:]
    tests.append([scramble,4])

    scramble=scramble[:-4]
    tests.append([scramble,4])
        
    for data in tests:
        scramble=data[0]
        i=data[1]
        k=findK(scramble[0],i+1)

        charset=''
        for ch in scramble:
            i += 1
            n = findCharInList(ch)
            for j in range(len(validCharList)):
                zn = (j + k * (i+1)) % len(validCharList)
                if n == zn:
                    ich = validCharList[j]
                    charset += ich
                    break

        charset = charset[::-1]
        ordvals = charset.split(':')
        passwd = ''
        i=0
        ok = True
        for ordval in ordvals:
            if len(ordval)>0:
                m = re.search('^[0-9]+$',ordval)
                if m:
                    j = int(ordval)-i-1
                    passwd += chr(j)
                    i += 1
                else:
                    ok = False
                    break

        if ok:
            return passwd

    return None


