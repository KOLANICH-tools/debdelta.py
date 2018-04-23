#!/usr/bin/python

#Copyright (c) 2018 A. Mennucci
#License: GNU GPL v2 

import os, sys, atexit, tempfile, subprocess
from os.path import join
from copy import copy
import time, string, shutil, pickle, lockfile, logging, logging.handlers

if sys.version_info.major == 2:
    string_types = (str, unicode)  # python2
else:
    string_types = (str, bytes)  # python3

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

class SQL_history(object):
    dbname=None
    sql_connection=None
    fields=('id','distribution','package','architecture',
            'old_version','new_version','old_size','new_size',
            'delta','delta_size','delta_time','patch_time',
            'forensic','error','ctime')
    fields_enum=enum(*fields)

    schema=b"""
    create table deltas_history (
    id integer unique primary key autoincrement,
    distribution text, package text, architecture text,
    old_version text, new_version text, old_size integer, new_size integer,
    delta text,    delta_size integer, delta_time real, patch_time real,
    forensic text,    error text,    ctime integer
    ) ;
    CREATE INDEX IF NOT EXISTS deltas_history_package ON deltas_history ( package );
    CREATE INDEX IF NOT EXISTS deltas_history_old_version ON deltas_history ( old_version );
    CREATE INDEX IF NOT EXISTS deltas_history_new_version ON deltas_history ( new_version );
    CREATE INDEX IF NOT EXISTS deltas_history_ctime ON deltas_history ( ctime );
    """

    def __init__(self,dbname):
        assert type(dbname) in string_types
        if not os.path.exists(dbname) or 0 == os.path.getsize(dbname):
            r=subprocess.Popen(['sqlite3',dbname], stdin=subprocess.PIPE)
            r.stdin.write(self.schema)
            r.stdin.close()
            r.wait()
            assert 0 == r.returncode
        assert os.path.exists(dbname)
        self.dbname=dbname
        #
        self.sql_connection = self._connect()
    #
    def _connect(self):
        return dbapi.connect(self.dbname, isolation_level='DEFERRED')   # detect_types=dbapi.PARSE_DECLTYPES | dbapi.PARSE_COLNAMES)
    #
    def __del__(self):
        if self.sql_connection != None:
            self.sql_connection.close()
    #
    def add(self, distribution, package, architecture,
            old_version, new_version, old_size, new_size, 
            delta, delta_size, delta_time, patch_time,
            forensic, error=None, ctime=None):
        if ctime==None:
            ctime=int(time.time())
        with self.sql_connection:
            self.sql_connection.execute('INSERT INTO deltas_history VALUES (null, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',\
                                    (distribution, package, architecture, old_version, new_version,
                                     old_size, new_size, delta, delta_size,delta_time,patch_time,
                                     forensic, error, ctime))

if __name__ == '__main__' and len(sys.argv) > 1:
    if sys.argv[1] == 'create' :
        n=tempfile.NamedTemporaryFile(delete=False,suffix='.sql')
        print('Creating test sqlite3 database: %r' % n.name)
        s=SQL_history(n.name)
        print('Adding an entry in %r' % n.name)
        s.add('debian','pippo','amd64',
              '1.0','1.1','3400','3635',
              '/tmp/pippo.delta',1200,4.4,1.3,
              '/tmp/pippo.forensic')
        print('Adding a failed entry in %r' % n.name)
        s.add('debian','pippo','amd64',
              '1.0','1.1','3400','3635',
              None,None,None,None,None,
              'too-big')

