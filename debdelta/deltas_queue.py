#!/usr/bin/python

#Copyright (c) 2018 A. Mennucci
#License: GNU GPL v2 

import os, sys, atexit, tempfile, subprocess
from os.path import join
from copy import copy
import time, string, shutil, pickle, lockfile, logging, logging.handlers

if sys.version_info.major == 2:
    string_types = (str, unicode)  # python2
    from urllib import quote as urllib_quote
else:
    string_types = (str, bytes)  # python3
    import urllib, urllib.parse
    from urllib.parse import quote as urllib_quote

import sqlite3 as dbapi

logger=logging.getLogger(__name__)

#http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
#from enum import Enum
class Enum(object):
    def __init__(self, *k):
        pass

def enum(*enums):
    d=dict([ (enums[k],k)    for k in range(len(enums)) ])
    return type('Enum', (object,), d)


