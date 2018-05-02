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
    def iterate_since(self, since):
        "returns a cursor onto the database since 'since' (in seconds from epoch)"
        cursor = self.sql_connection.cursor()
        cursor.execute('SELECT * FROM deltas_history WHERE ctime > ? ORDER BY ctime DESC ', (since,))
        return cursor


_html_top="""<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
  <link rel="StyleSheet" href="style.css" type="text/css">
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <title>debdeltas Server History Page</title>
</head>
<body>
"""

def html_one_day(db,W):
    s=SQL_history(db)
    if type(W) in string_types:
        W=open(W,'w').write
    W(_html_top)
    since=int(time.time()) - 24 * 3600
    W('Deltas created from '+time.ctime(since)+' to '+time.ctime()+'\n')
    F=list(SQL_history.fields)
    FE=SQL_history.fields_enum
    F[FE.architecture]='arch'
    del F[FE.forensic]
    F.insert(FE.delta_time,'percent')
    del F[FE.distribution]
    W('<table class="one_day_work"><tr>')
    for j in F:
        W('<th>' + j.replace('_',' ')+'</th>')
    W('</tr>\n')
    count=0
    for x in s.iterate_since(since):
        count+=1
        x=list(x)
        if x[FE.delta]:
            x[FE.delta]='<a href="/%s">delta</a>' % urllib_quote(x[FE.delta])
        if x[FE.new_size] and x[FE.delta_size] :
            percent=('%.1f%%' % (100. * x[FE.delta_size] / x[FE.new_size]) )
        else: percent='--'
        x[FE.ctime]=time.ctime(x[FE.ctime])
        del x[FE.forensic]
        x.insert(FE.delta_time,percent)
        del x[FE.distribution]
        x=[('%.3f' % j) if isinstance(j,float) else j for j in x]
        x=['' if (j == None) else j for j in x]
        W('<tr>')
        for j in x:
            W('<td>'+str(j)+'</td>')
        W('</tr>\n')
        if (count % 40)  == 0:
            W('<tr>')
            for j in F:
                W('<th>'+j.replace('_',' ')+'</th>')
            W('</tr>\n')
    W('</table></body></html>\n')


if __name__ == '__main__' and len(sys.argv) > 1:
    if sys.argv[1] == 'create_test' :
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
    elif sys.argv[1] == 'dump_one_day' :
        s=SQL_history(sys.argv[2])
        for x in s.cursor_today()():
            print(repr(x))
    elif sys.argv[1] == 'html_one_day' :
        W= sys.argv[3] if (len(sys.argv) > 3)  else sys.stdout.write
        html_one_day(sys.argv[2],W)
    else: raise ValueError('unknown command %r' % sys.argv[1])

