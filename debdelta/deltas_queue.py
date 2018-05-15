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

if dbapi != None:
    pass
    # ===== sqlite machinery
    #def convert_blob(s):
    #   return s #this is always a string
    #
    # Register the adapter
    #sqlite.register_adapter(StringType, adapt_blob)
    #
    # Register the converter
    #dbapi.register_converter("blob", convert_blob)
    #dbapi.register_converter("text", convert_blob)

class SQL_queue(object):
    dbname=None
    sql_connection=None
    sql_connection_add=None
    fields=('id','priority','old_name','new_name','delta','forensic','other_info','ctime')
    fields_enum=enum(*fields)

    schema="""
    create table deltas_queue (
    id integer unique primary key autoincrement,
    priority integer,
    old_name text,
    new_name text,
    delta text,
    forensic text,
    other_info text,
    ctime integer
    ) ;
    CREATE INDEX IF NOT EXISTS deltas_queue_priority ON deltas_queue ( priority );
    CREATE INDEX IF NOT EXISTS deltas_queue_delta ON deltas_queue ( delta ) ;
    CREATE INDEX IF NOT EXISTS deltas_queue_ctime ON deltas_queue ( ctime ) ;
    CREATE INDEX IF NOT EXISTS deltas_queue_priority_ctime ON deltas_queue ( priority, ctime ) ;
    """

    def __init__(self,dbname):
        assert type(dbname) in string_types
        if not os.path.exists(dbname):
            r=my_subprocess_Popen(['sqlite3',dbname], stdin=subprocess.PIPE)
            r.stdin.write(self.schema)
            r.stdin.close()
            r.wait()
            assert 0 == r.returncode
        assert os.path.exists(dbname)
        self.dbname=dbname
        self.sql_connection = self._connect()
        # will be created when needed
        self.sql_connection_add = None
    
    def _connect(self):
        return dbapi.connect(self.dbname, isolation_level='EXCLUSIVE')   # detect_types=dbapi.PARSE_DECLTYPES | dbapi.PARSE_COLNAMES)
    
    def __del__(self):
        if self.sql_connection != None:
            self.sql_connection.close()
        if self.sql_connection_add != None:
            self.sql_connection_add.close()

    def _get_connection_cursor(self):
        connection =  self.sql_connection
        cursor = connection.cursor()
        return connection, cursor
    
    def queue_add_begin(self):
        assert self.sql_connection_add == None
        self.sql_connection_add = self._connect()

    def queue_add(self, priority, old_name, new_name, delta, forensic, other_info='', ctime=None):
        if self.sql_connection_add == None:
            raise Exception(' should use queue_add_begin() before ')
        if ctime==None:
            ctime=int(time.time())
        with self.sql_connection_add as S:
            S.execute('INSERT INTO deltas_queue VALUES (null, ?, ?, ?, ?, ?, ?, ?)',\
                                    (priority, old_name, new_name, delta, forensic, other_info, ctime))
            S.commit()

    def queue_add_commit(self):
        self.sql_connection_add = None

    def queue_peek(self):
        conn,cursor = self._get_connection_cursor()
        cursor.execute('SELECT * FROM deltas_queue ORDER BY priority , ctime  LIMIT 1')
        return cursor.fetchone()
    
    def queue_get(self, id_):
        conn,cursor = self._get_connection_cursor()
        cursor.execute('SELECT * FROM deltas_queue WHERE id = ? ', (id_,))
        return cursor.fetchone()
    
    def queue_pop(self, id_=None):
        "pop one value, if 'id' is set that value"
        #http://stackoverflow.com/questions/15856976/transactions-with-python-sqlite3
        connection, cursor = self._get_connection_cursor()
        try:
            cursor.execute('begin exclusive transaction')
            if id_ == None:
                cursor.execute('SELECT * FROM deltas_queue ORDER BY priority , ctime LIMIT 1 ')
            else:
                cursor.execute('SELECT * FROM deltas_queue WHERE id = ? ', (id_,))
            x=cursor.fetchone()
            if x == None: #
                return None
            id_ = x[0]
            connection.execute('DELETE FROM deltas_queue where id = ? ', (id_,))
            connection.commit()
            #cursor.execute('commit transaction')
        except:
            connection.rollback() 
            #cursor.execute('rollback')
            raise
        return x

    def queue_del(self, id_):
        "delete queued item by 'id'"
        connection, cursor = self._get_connection_cursor()
        try:
            cursor.execute('DELETE FROM deltas_queue where id = ? ', (id_,))
            connection.commit() #cursor.executescript('commit transaction')
        except:
            connection.rollback() #cursor.executescript('rollback')
            raise
        return x
    
    def iterate(self):
        "returns a cursor onto the database"
        connection, cursor = self._get_connection_cursor()
        cursor.execute('SELECT * FROM deltas_queue ORDER BY priority , ctime')
        return cursor
    
    def queue_peek_delta(self, delta):
        conn,cursor = self._get_connection_cursor()
        cursor.execute('SELECT * FROM deltas_queue WHERE delta = ?', (delta, ))
        return cursor.fetchone()
        


_html_top="""<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
  <link rel="StyleSheet" href="style.css" type="text/css">
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <title>debdeltas Server History Page</title>
</head>
<body>
"""

def html(db,W):
    s=SQL_queue(db)
    if type(W) in string_types:
        W=open(W,'w').write
    W(_html_top)
    W('Queue state at '+time.ctime()+'\n')
    F=list(SQL_queue.fields)
    FE=SQL_queue.fields_enum
    W('<table class="queue"><tr>')
    for j in F:
        W('<th>' + j.replace('_',' ')+'</th>')
    W('</tr>\n')
    count=0
    for x in s.iterate():
        count+=1
        x=list(x)
        x=[('%.3f' % j) if isinstance(j,float) else j for j in x]
        x=[(j.split('/')[-1]) if (type(j) in string_types) else j for j in x]
        x=['' if (j == None) else j for j in x]
        x[FE.ctime]=time.ctime(x[FE.ctime])
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
    W('total %d elements in queue\n' % count)


if __name__ == '__main__' and len(sys.argv) > 1:
    if sys.argv[1] == 'html' :
        W= sys.argv[3] if (len(sys.argv) > 3)  else sys.stdout.write
        html(sys.argv[2],W)
    else: raise ValueError('unknown command %r' % sys.argv[1])
