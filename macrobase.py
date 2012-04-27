#!/usr/bin/env python
################################################################################
## NAME: macrobase
## DATE: 2011-02-04
## AUTHOR: Matt Reid
## WEBSITE: http://kontrollsoft.com
## EMAIL: mreid@kontrollsoft.com
## LICENSE: BSD http://www.opensource.org/licenses/bsd-license.php
################################################################################
from __future__ import division
from lxml import etree
from StringIO import StringIO
from ConfigParser import ConfigParser
import getpass
import socket
import commands
import sys
import os
import datetime
import logging
import MySQLdb
import getopt
from optparse import OptionParser

#hardcodes
code_version = "1.00.1.2"
d = datetime.datetime.now()
date = d.isoformat()
'''Check Python version for compatibility'''
ver = sys.version.split(' ')[0].split(".")
major=ver[:1]
minor=ver[1:2]
version="%s.%s"%(major[0],minor[0])

#currently not using subprocess so we can use 2.4+, otherwise we'd need 2.6+
if version < 2.4: 
    print "Please upgrade to python 2.4+"
    sys.exit(1)

def parseXML():
    f = open(xmlfile)
    xml = f.read()
    f.close()
    tree = etree.parse(StringIO(xml))
    context = etree.iterparse(StringIO(xml))
    events = []
    for action, e in context:
        if e.tag == "event":
            id = e.attrib["id"]
            name = e.attrib["name"]
            desc = e.attrib["desc"]
            solution = e.attrib["solution"] 
            links = e.attrib["links"] 
            cat = e.attrib["category"] 
            d = [id,name,desc,solution,links,cat]
            events.append(d)
    return events


def parseREPORT(file):
    f = open(file)
    xml = f.read()
    f.close()
    tree = etree.parse(StringIO(xml))
    context = etree.iterparse(StringIO(xml))
    events = []
    recommend = []
    entry = []
    for action, e in context:
        if e.tag == "alert":
            id = e.attrib["id"]
            name = e.attrib["name"]
            desc = e.attrib["desc"]
            solution = e.attrib["solution"] 
            links = e.attrib["links"] 
            cat = e.attrib["category"] 
            if e.attrib["recommend"]:
                recommend.append(e.attrib["recommend"])            
            if e.attrib["entry"]:
                entry.append(e.attrib["entry"])
            d = [id,name,desc,solution,links,cat,entry,recommend]
            events.append(d)
    return events

def find_event(i):
    events = parseXML()
    for each in events:        
        id = int(each[0].strip())
        if id == int(i):
            return each

def out_start():
    try:
        file = open("macrobase-%s-%s.xml"%(hostname,date), 'a')
        file.write("<macrobase version=\"%s\" datetime=\"%s\">\n"%(code_version,date))
        file.close()
    except:
        logger("Failed to write to log file. Check directory permissions.",'e')
        if not options.debugout:
            console("writing to logfile",1)
        sys.exit(1)

def out_end():
    try:
        file = open("macrobase-%s-%s.xml"%(hostname,date), 'a')
        file.write("</macrobase>\n")
        file.close() 
        outfile = "macrobase-%s-%s.xml"%(hostname,date)
        console("Your report is available at: %s"%(outfile),2)
        logger("Your report is available at: %s"%(outfile),'d')
        #report = parseREPORT(outfile) ## this is where we start the report conversion process from XML to whatever - NOT DONE
        #print report
    except:
        logger("Failed to write to log file. Check directory permissions.",'e')

def out(str):
    try:
        file = open("macrobase-%s-%s.xml"%(hostname,date), 'a')
        file.write(str+"\n")
        file.close()
    except:
        logger("Failed to write to log file. Check directory permissions.",'e')

def console(str,state):
    if not options.debugout:
        if state == 0:
            s = "OK"            
        elif state == 1:
            s = "FAILED"
        elif state == 2:
            print str
            return
        elif state == 3:
            print "running check: %s"%(str)
            return
        print str+" .. [%s]"%(s)

def writer(s):
    ss = str(s)
    logger(ss,'d')
    out(ss)
    return

def writerx(s):
    logger("entry=\"%s\""%(s),'d')
    out("entry=\"%s\""%(s))
    
def recommend(a,b):
    b = str(b)
    try:
        if b.isdigit() == True:
            c = "%s = %s"%(str(a),int(round(b,0)))
        else:
            c = "%s = %s"%(str(a),str(b)) 
    except:
        c = "%s = %s"%(str(a),str(b))

    logger("recommend=\"%s\""%(c),'d')    
    out("recommend=\"%s\""%(c))

def header():
    print code_version
    print '''macroBase
site: http://datastrangler.com
author: strangl3r
license: BSD
'''

def parse_options():
    usage = "usage: "
    parser = OptionParser(usage=usage)
    parser.add_option("-u", "--user", dest="mysql_user", default="root", help="MySQL user (default: root)")
    parser.add_option("-H", "--host", dest="mysql_host", default="127.0.0.1", help="MySQL host (default: <127.0.0.1>)")
    parser.add_option("-p", "--password", dest="mysql_password", default="", help="MySQL password (default: <none>)")
    parser.add_option("--ask-pass", action="store_true", dest="prompt_password", help="Prompt for password")
    parser.add_option("-P", "--port", dest="mysql_port", type="int", default="3306", help="TCP/IP port (default: 3306)")
    parser.add_option("-S", "--socket", dest="mysql_socket", default="/var/lib/mysql/mysql.sock", help="MySQL socket file. Do not combine with --host (default: /var/lib/mysql/mysql.sock)")
    parser.add_option("-c", "--config", dest="conf_file", default="", help="Read from MySQL configuration file. Overrides all other options")
    parser.add_option("-d", "--database", dest="mysql_database", default="mysql", help="Connect database name. Requires privilege to use. (default: <none>)")
    parser.add_option("-v", "--verbose", dest="debugout", action="store_true", help="Print debug messages to console at runtime. (default: <none>)")
    parser.add_option("-o", "--outfile", dest="outfile", default="macrobase.log", help="Output file for logging. (default: macrobase.log)")    
    parser.add_option("-x", "--xmlfile", dest="xmlfile", default="macrobase.xml", help="Input file that contains alert data. (default: macrobase.xml)")
    parser.add_option("--snmp-port", dest="snmp_port", default="161", help="SNMP host port. (default: 161)")
    parser.add_option("--snmp-host", dest="snmp_host", default="127.0.0.1", help="SNMP host address. (default: <address of mysql>)")
    parser.add_option("--snmp-rocommunity", dest="snmp_rocommunity", default="public", help="SNMP read only community value (default: public)")
    parser.add_option("--snmp-version", dest="snmp_version", default="1", help="SNMP version. [1,2,3] (default: 1)")
    return parser.parse_args()

def getconf():    
    try:
        config = ConfigParser()
        config.read([options.conf_file])
        headertxt = 'macrobase configuration'
        mysql_host = str(config.get(headertxt,'mysql-host'))
        mysql_user = str(config.get(headertxt,'mysql-user'))
        mysql_password = str(config.get(headertxt,'mysql-password'))
        mysql_database = str(config.get(headertxt,'mysql-database'))
        mysql_port = int(config.get(headertxt,'mysql-port'))
        mysql_socket = str(config.get(headertxt,'mysql-socket'))
        outfile = str(config.get(headertxt,'outfile'))
        xmlfile = str(config.get(headertxt,'xmlfile'))
        snmp_port = int(config.get(headertxt,'snmp-port'))
        snmp_host = str(config.get(headertxt,'snmp-host'))
        snmp_version = str(config.get(headertxt,'snmp-version'))
        snmp_rocommunity = str(config.get(headertxt,'snmp-rocommunity'))
        return mysql_host, mysql_user, mysql_password, mysql_database, mysql_port, mysql_socket, outfile, xmlfile, snmp_port, snmp_host, snmp_version, snmp_rocommunity
    except:
        console("Failed to parse config file options.",2)
        sys.exit(1)

def open_connection():
    if options.conf_file:
        try:
            mysql_host, mysql_user, mysql_password, mysql_database, mysql_port, mysql_socket, outfile, xmlfile, snmp_port, snmp_host, snmp_version, snmp_rocommunity = getconf()
            conn = MySQLdb.connect(
                host = mysql_host,
                user = mysql_user,
                passwd = mysql_password,
                port = mysql_port,
                db = mysql_database,
                unix_socket = mysql_socket)
        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            logger("Error %d: %s" % (e.args[0], e.args[1]),'e')
            sys.exit(1)
    else:
        if options.prompt_password:
            password=getpass.getpass()
        else:
            password=options.mysql_password
            try:
                conn = MySQLdb.connect(
                    host = options.mysql_host,
                    user = options.mysql_user,
                    passwd = password,
                    port = options.mysql_port,
                    db = options.mysql_database,
                    unix_socket = options.mysql_socket)                
            except MySQLdb.Error, e:
                print "Error %d: %s" % (e.args[0], e.args[1])
                logger("Error %d: %s" % (e.args[0], e.args[1]),'e')
                sys.exit(1)
    console("connection",0)
    return conn;

def get_snmp(snmp_request):
    '''once I find some code for pysnmp that actually doesn't suck balls...'''
    '''test for python snmp library, if not supported then use the following command method'''
    snmpwalk_binary = syscmd("which snmpwalk")
    if snmpwalk_binary != False:
        value = syscmd("%s -O qvU -v %s -c %s %s:%s %s"%(snmpwalk_binary,
                                                         snmp_version,
                                                         snmp_rocommunity,
                                                         snmp_host,
                                                         snmp_port,
                                                         snmp_request))
        logger("command: %s -O qvU -v %s -c %s %s:%s %s"%(snmpwalk_binary,
                                                          snmp_version,
                                                          snmp_rocommunity,
                                                          snmp_host,
                                                          snmp_port,
                                                          snmp_request),'d')
    else:
        logger("cannot find snmpwalk binary. please install and put the binary location into your $PATH",'e')
        console("cannot find snmpwalk binary. please install and put the binary location into your $PATH",2)
        return False
    
    return value

def get_var(name):
    value = get_single("show global variables like '%s'"%(name))
    try:
        return int(value)
    except:
        return str(value)

def get_status(name):
    value = get_single("show global status like '%s'"%(name))
    try:
        return int(value)
    except:
        return str(value)

def get_single(query):
    data = get_row(query)    
    try:
        if data is not None:
            return data["Value"]
        if data["Value"] == "NULL" or data["Value"] == "Null" or data["Value"] == "null":
            return 0    
        else:
            return 0
    except:
        return 0

def get_row(query):
    connection = conn
    cursor = connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(query)
    row = cursor.fetchone()
    cursor.close()
    return row

def get_rows(query):
    connection = conn
    cursor = connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    return rows

def logger(detail,level):
    if(level == "d"):
        log.debug("%s"% (detail))
    elif(level == "i"):
        log.info("%s"% (detail))
    elif(level == "w"):
        log.warn("%s"% (detail))
    elif(level == "e"):
        log.error("%s"% (detail))
    elif(level == "c"):
        log.critical("%s"% (detail))

def human(bytes):
    bytes = float(bytes)
    if bytes >= 1099511627776:
        terabytes = bytes / 1099511627776
        size = '%.0fT' % terabytes
    elif bytes >= 1073741824:
        gigabytes = bytes / 1073741824
        size = '%.0fG' % gigabytes
    elif bytes >= 1048576:
        megabytes = bytes / 1048576
        size = '%.0fM' % megabytes
    elif bytes >= 1024:
        kilobytes = bytes / 1024
        size = '%.0fK' % kilobytes
    else:
        size = '%.0fb' % bytes
    return size

def syscmd(command):
    logger("Running system command: %s"% (command),"d")    
    start = datetime.datetime.now()
    retcode, output = commands.getstatusoutput(command)
    end = datetime.datetime.now()
    timing = end - start
    logger("Total compute time: %s"%(timing),'d')

    if retcode != 0:
        logger("System command: %s code: %i [FAILED]"%(command,retcode),"c")
        console("System command: %s code: %i [FAILED]"%(command,retcode),2)
        return False
    else:
        logger("System command: [OK]","d")
        return output

def main():
    #simple test of system command execution    
    out = syscmd("date")
    console("testing SQL",0)
    if out != False:
        console("SQL execution",0)
        out_start()
        big_tables = get_var("big_tables")
        binlog_cache_size = get_var("binlog_cache_size")
        bulk_insert_buffer_size = get_var("bulk_insert_buffer_size")
        concurrent_insert = get_var("concurrent_insert")
        connect_timeout = get_var("connect_timeout")
        error_count = get_var("error_count")
        flush_time = get_var("flush_time")
        have_compress = get_var("have_compress")
        have_crypt = get_var("have_crypt")
        have_csv = get_var("have_csv")
        have_dynamic_loading = get_var("have_dynamic_loading")
        have_geometry = get_var("have_geometry")
        have_innodb = get_var("have_innodb")
        have_ndbcluster = get_var("have_ndbcluster")
        have_openssl = get_var("have_openssl")
        have_partitioning = get_var("have_partitioning")
        have_query_cache = get_var("have_query_cache")
        have_rtree_keys = get_var("have_rtree_keys")
        have_ssl = get_var("have_ssl")
        have_symlink = get_var("have_symlink")
        hostname = get_var("hostname")
        ignore_builtin_innodb = get_var("ignore_builtin_innodb")
        innodb_adaptive_hash_index = get_var("innodb_adaptive_hash_index")
        innodb_additional_mem_pool_size = get_var("innodb_additional_mem_pool_size")
        innodb_autoextend_increment = get_var("innodb_autoextend_increment")
        innodb_autoinc_lock_mode = get_var("innodb_autoinc_lock_mode")
        innodb_buffer_pool_size = get_var("innodb_buffer_pool_size")
        innodb_checksums = get_var("innodb_checksums")
        innodb_commit_concurrency = get_var("innodb_commit_concurrency")
        innodb_concurrency_tickets = get_var("innodb_concurrency_tickets")
        innodb_data_file_path = get_var("innodb_data_file_path")
        innodb_data_home_dir = get_var("innodb_data_home_dir")
        innodb_doublewrite = get_var("innodb_doublewrite")
        innodb_fast_shutdown = get_var("innodb_fast_shutdown")
        innodb_file_io_threads = get_var("innodb_file_io_threads")
        innodb_file_per_table = get_var("innodb_file_per_table")
        innodb_flush_log_at_trx_commit = get_var("innodb_flush_log_at_trx_commit")
        innodb_flush_method = get_var("innodb_flush_method")
        innodb_force_recovery = get_var("innodb_force_recovery")
        innodb_lock_wait_timeout = get_var("innodb_lock_wait_timeout")
        innodb_locks_unsafe_for_binlog = get_var("innodb_locks_unsafe_for_binlog")
        innodb_log_buffer_size = get_var("innodb_log_buffer_size")
        innodb_log_file_size = get_var("innodb_log_file_size")
        innodb_log_files_in_group = get_var("innodb_log_files_in_group")
        innodb_log_group_home_dir = get_var("innodb_log_group_home_dir")
        innodb_max_dirty_pages_pct = get_var("innodb_max_dirty_pages_pct")
        innodb_max_purge_lag = get_var("innodb_max_purge_lag")
        innodb_m= get_var("myisam_recover_options")        
        join_buffer_size = get_var("join_buffer_size")
        key_buffer_size = get_var("key_buffer_size")
        key_cache_block_size = get_var("key_cache_block_size")
        large_page_size = get_var("large_page_size")
        large_pages = get_var("large_pages")
        long_query_time = get_var("long_query_time")
        low_priority_updates = get_var("low_priority_updates")
        max_allowed_packet = get_var("max_allowed_packet")
        max_binlog_cache_size = get_var("max_binlog_cache_size")
        max_binlog_size = get_var("max_binlog_size")
        max_connect_errors = get_var("max_connect_errors")
        max_connections = get_var("max_connections")
        max_heap_table_size = get_var("max_heap_table_size")
        max_tmp_tables = get_var("max_tmp_tables")
        myisam_repair_threads = get_var("myisam_repair_threads")
        myisam_sort_buffer_size = get_var("myisam_sort_buffer_size")
        myisam_stats_method = get_var("myisam_stats_method")
        myisam_use_mmap = get_var("myisam_use_mmap")
        net_buffer_length = get_var("net_buffer_length")
        net_read_timeout = get_var("net_read_timeout")
        net_retry_count = get_var("net_retry_count")
        net_write_timeout = get_var("net_write_timeout")
        old_passwords = get_var("old_passwords")
        open_files_limit = get_var("open_files_limit")
        optimizer_prune_level = get_var("optimizer_prune_level")
        optimizer_search_depth = get_var("optimizer_search_depth")
        optimizer_switch = get_var("optimizer_switch")
        pid_file = get_var("pid_file")
        port = get_var("port")
        preload_buffer_size = get_var("preload_buffer_size")
        query_alloc_block_size = get_var("query_alloc_block_size")
        query_cache_limit = get_var("query_cache_limit")
        query_cache_min_res_unit = get_var("query_cache_min_res_unit")
        query_cache_size = get_var("query_cache_size")
        query_cache_type = get_var("query_cache_type")
        query_cache_wlock_invalidate = get_var("query_cache_wlock_invalidate")
        query_prealloc_size = get_var("query_prealloc_size")
        read_buffer_size = get_var("read_buffer_size")
        read_only = get_var("read_only")
        read_rnd_buffer_size = get_var("read_rnd_buffer_size")
        skip_external_locking = get_var("skip_external_locking")
        skip_name_resolve = get_var("skip_name_resolve")
        skip_networking = get_var("skip_networking")
        skip_show_database = get_var("skip_show_database")
        sort_buffer_size = get_var("sort_buffer_size")
        sync_binlog = get_var("sync_binlog")
        sync_frm = get_var("sync_frm")
        table_lock_wait_timeout = get_var("table_lock_wait_timeout")

        try:
            table_cache = get_var("table_cache")
            table_open_cache = False
        except:
            table_cache = False
            table_open_cache = get_var("table_open_cache")            

        table_type = get_var("table_type")
        thread_cache_size = get_var("thread_cache_size")
        thread_handling = get_var("thread_handling")
        thread_stack = get_var("thread_stack")
        timed_mutexes = get_var("timed_mutexes")
        tmp_table_size = get_var("tmp_table_size")
        tmpdir = get_var("tmpdir")
        transaction_alloc_block_size = get_var("transaction_alloc_block_size")
        transaction_prealloc_size = get_var("transaction_prealloc_size")
        tx_isolation = get_var("tx_isolation")
        version = get_var("version")
        wait_timeout = get_var("wait_timeout")
        warning_count = get_var("warning_count")

        ## Status Variables
        Aborted_clients = get_status("Aborted_clients")
        Aborted_connects = get_status("Aborted_connects")
        Binlog_cache_disk_use = get_status("Binlog_cache_disk_use")
        Binlog_cache_use = get_status("Binlog_cache_use")
        Bytes_received = get_status("Bytes_received")
        Bytes_sent = get_status("Bytes_sent")
        Com_commit = get_status("Com_commit")
        Com_delete = get_status("Com_delete")
        Com_delete_multi = get_status("Com_delete_multi")
        Com_insert = get_status("Com_insert")
        Com_select = get_status("Com_select")
        Com_update = get_status("Com_update")
        Com_update_multi = get_status("Com_update_multi")
        Connections = get_status("Connections")
        Created_tmp_disk_tables = get_status("Created_tmp_disk_tables")
        Created_tmp_files = get_status("Created_tmp_files")
        Created_tmp_tables = get_status("Created_tmp_tables")
        Handler_read_rnd = get_status("Handler_read_rnd")
        Handler_read_rnd_next = get_status("Handler_read_rnd_next")
        Innodb_buffer_pool_pages_data = get_status("Innodb_buffer_pool_pages_data")
        Innodb_buffer_pool_pages_dirty = get_status("Innodb_buffer_pool_pages_dirty")
        Innodb_buffer_pool_pages_flushed = get_status("Innodb_buffer_pool_pages_flushed")
        Innodb_buffer_pool_pages_free = get_status("Innodb_buffer_pool_pages_free")
        Innodb_buffer_pool_pages_misc = get_status("Innodb_buffer_pool_pages_misc")
        Innodb_buffer_pool_pages_total = get_status("Innodb_buffer_pool_pages_total")
        Innodb_buffer_pool_read_ahead_rnd = get_status("Innodb_buffer_pool_read_ahead_rnd")
        Innodb_buffer_pool_read_ahead_seq = get_status("Innodb_buffer_pool_read_ahead_seq")
        Innodb_buffer_pool_read_requests = get_status("Innodb_buffer_pool_read_requests")
        Innodb_buffer_pool_reads = get_status("Innodb_buffer_pool_reads")
        Innodb_buffer_pool_wait_free = get_status("Innodb_buffer_pool_wait_free")
        Innodb_buffer_pool_write_requests = get_status("Innodb_buffer_pool_write_requests")
        Innodb_data_fsyncs = get_status("Innodb_data_fsyncs")
        Innodb_data_pending_fsyncs = get_status("Innodb_data_pending_fsyncs")
        Innodb_data_pending_reads = get_status("Innodb_data_pending_reads")
        Innodb_data_pending_writes = get_status("Innodb_data_pending_writes")
        Innodb_data_read = get_status("Innodb_data_read")
        Innodb_data_reads = get_status("Innodb_data_reads")
        Innodb_data_writes = get_status("Innodb_data_writes")
        Innodb_data_written = get_status("Innodb_data_written")
        Innodb_dblwr_pages_written = get_status("Innodb_dblwr_pages_written")
        Innodb_dblwr_writes = get_status("Innodb_dblwr_writes")
        Innodb_log_waits = get_status("Innodb_log_waits")
        Innodb_log_write_requests = get_status("Innodb_log_write_requests")
        Innodb_log_writes = get_status("Innodb_log_writes")
        Innodb_os_log_fsyncs = get_status("Innodb_os_log_fsyncs")
        Innodb_os_log_pending_fsyncs = get_status("Innodb_os_log_pending_fsyncs")
        Innodb_os_log_pending_writes = get_status("Innodb_os_log_pending_writes")
        Innodb_os_log_written = get_status("Innodb_os_log_written")
        Innodb_page_size = get_status("Innodb_page_size")
        Innodb_pages_created = get_status("Innodb_pages_created")
        Innodb_pages_read = get_status("Innodb_pages_read")
        Innodb_pages_written = get_status("Innodb_pages_written")
        Innodb_row_lock_current_waits = get_status("Innodb_row_lock_current_waits")
        Innodb_row_lock_time = get_status("Innodb_row_lock_time")
        Innodb_row_lock_time_avg = get_status("Innodb_row_lock_time_avg")
        Innodb_row_lock_time_max = get_status("Innodb_row_lock_time_max")
        Innodb_row_lock_waits = get_status("Innodb_row_lock_waits")
        Innodb_rows_deleted = get_status("Innodb_rows_deleted")
        Innodb_rows_inserted = get_status("Innodb_rows_inserted")
        Innodb_rows_read = get_status("Innodb_rows_read")
        Innodb_rows_updated = get_status("Innodb_rows_updated")
        Key_blocks_not_flushed = get_status("Key_blocks_not_flushed")
        Key_blocks_unused = get_status("Key_blocks_unused")
        Key_blocks_used = get_status("Key_blocks_used")
        Key_read_requests = get_status("Key_read_requests")
        Key_reads = get_status("Key_reads")
        Key_write_requests = get_status("Key_write_requests")
        Key_writes = get_status("Key_writes")
        Max_used_connections = get_status("Max_used_connections")
        Open_files = get_status("Open_files")
        Open_tables = get_status("Open_tables")
        Opened_files = get_status("Opened_files")
        Opened_tables = get_status("Opened_tables")
        Qcache_free_blocks = get_status("Qcache_free_blocks")
        Qcache_free_memory = get_status("Qcache_free_memory")
        Qcache_hits = get_status("Qcache_hits")
        Qcache_inserts = get_status("Qcache_inserts")
        Qcache_lowmem_prunes = get_status("Qcache_lowmem_prunes")
        Qcache_not_cached = get_status("Qcache_not_cached")
        Qcache_queries_in_cache = get_status("Qcache_queries_in_cache")
        Qcache_total_blocks = get_status("Qcache_total_blocks")
        Queries = get_status("Queries")
        Questions = get_status("Questions")
        Select_full_join = get_status("Select_full_join")
        Select_full_range_join = get_status("Select_full_range_join")
        Select_range = get_status("Select_range")
        Select_range_check = get_status("Select_range_check")
        Select_scan = get_status("Select_scan")
        Slow_queries = get_status("Slow_queries")
        Sort_merge_passes = get_status("Sort_merge_passes")
        Sort_range = get_status("Sort_range")
        Sort_rows = get_status("Sort_rows")
        Sort_scan = get_status("Sort_scan")
        Table_locks_immediate = get_status("Table_locks_immediate")
        Table_locks_waited = get_status("Table_locks_waited")
        Threads_cached = get_status("Threads_cached")
        Threads_connected = get_status("Threads_connected")
        Threads_created = get_status("Threads_created")
        Threads_running = get_status("Threads_running")
        Uptime = get_status("Uptime")

        console("engine usage statistics",3)
        engine_data = get_row("select (data_size + index_size) / gb as total_size_gb , index_size / gb as index_size_gb , data_size / gb as data_size_gb , sum(innodb_index_size + innodb_data_size) / pow(1024,3) as innodb_total_size_gb , innodb_data_size / pow(1024,3) as innodb_data_size_gb , innodb_index_size / pow(1024,3) as innodb_index_size_gb , sum(myisam_index_size + myisam_data_size) / pow(1024,3) as myisam_total_size_gb , myisam_data_size / pow(1024,3) as myisam_data_size_gb , myisam_index_size / pow(1024,3) as myisam_index_size_gb , index_size / (data_size + index_size) * 100 as perc_index , data_size / (data_size + index_size) * 100 as perc_data , innodb_index_size / (innodb_data_size + innodb_index_size) * 100 as innodb_perc_index , innodb_data_size / (innodb_data_size + innodb_index_size) * 100 as innodb_perc_data , myisam_index_size / (myisam_data_size + myisam_index_size) * 100 as myisam_perc_index , myisam_data_size / (myisam_data_size + myisam_index_size) * 100 as myisam_perc_data , innodb_index_size / index_size * 100 as innodb_perc_total_index , innodb_data_size / data_size * 100 as innodb_perc_total_data , myisam_index_size / index_size * 100 as myisam_perc_total_index , myisam_data_size / data_size * 100 as myisam_perc_total_data from ( select sum(data_length) data_size , sum(index_length) index_size , sum(if(engine = 'innodb', data_length, 0)) as innodb_data_size , sum(if(engine = 'innodb', index_length, 0)) as innodb_index_size , sum(if(engine = 'myisam', data_length, 0)) as myisam_data_size , sum(if(engine = 'myisam', index_length, 0)) as myisam_index_size , pow(1024, 3) gb from information_schema.tables ) a")
        
        engine_total_size_gb = round(engine_data["total_size_gb"],4)
        engine_index_size_gb = round(engine_data["index_size_gb"],4)
        engine_data_size_gb = round(engine_data["data_size_gb"],4)
        engine_innodb_total_size_gb = round(engine_data["innodb_total_size_gb"],4)
        engine_innodb_data_size_gb = round(engine_data["innodb_data_size_gb"],4)
        engine_innodb_index_size_gb = round(engine_data["innodb_index_size_gb"],4)
        engine_myisam_total_size_gb = round(engine_data["myisam_total_size_gb"],4)
        engine_myisam_data_size_gb = round(engine_data["myisam_data_size_gb"],4)
        engine_myisam_index_size_gb = round(engine_data["myisam_index_size_gb"],4)
        engine_perc_index = round(engine_data["perc_index"],4)
        engine_perc_data = round(engine_data["perc_data"],4)
        engine_innodb_perc_index = round(engine_data["innodb_perc_index"],4)
        engine_innodb_perc_data = round(engine_data["innodb_perc_data"],4)
        engine_myisam_perc_index = round(engine_data["myisam_perc_index"],4)
        engine_myisam_perc_data = round(engine_data["myisam_perc_data"],4)
        engine_innodb_perc_total_index = round(engine_data["innodb_perc_total_index"],4)
        engine_innodb_perc_total_data = round(engine_data["innodb_perc_total_data"],4)
        engine_myisam_perc_total_index = round(engine_data["myisam_perc_total_index"],4)
        engine_myisam_perc_total_data = round(engine_data["myisam_perc_total_data"],4)

        writer("<alert id=\"0\"")
        writer("total_size_gb=\"%s\""%(engine_total_size_gb))
        writer("index_size_gb=\"%s\""%(engine_index_size_gb))
        writer("data_size_gb=\"%s\""%(engine_data_size_gb))
        writer("innodb_total_size_gb=\"%s\""%(engine_innodb_total_size_gb))
        writer("innodb_data_size_gb=\"%s\""%(engine_innodb_data_size_gb))
        writer("innodb_index_size_gb=\"%s\""%(engine_innodb_index_size_gb))
        writer("myisam_total_size_gb=\"%s\""%(engine_myisam_total_size_gb))
        writer("myisam_data_size_gb=\"%s\""%(engine_myisam_data_size_gb))
        writer("myisam_index_size_gb=\"%s\""%(engine_myisam_index_size_gb))
        writer("total_percentage_index=\"%s\""%(engine_perc_index))
        writer("total_percentage_data=\"%s\""%(engine_perc_data))
        writer("innodb_percentage_index=\"%s\""%(engine_innodb_perc_index))
        writer("innodb_percentage_data=\"%s\""%(engine_innodb_perc_data))
        writer("myisam_percentage_index=\"%s\""%(engine_myisam_perc_index))
        writer("myisam_percentage_data=\"%s\""%(engine_myisam_perc_data))
        writer("innodb_percentage_to_total_index=\"%s\""%(engine_innodb_perc_total_index))
        writer("innodb_percentage_to_total_data=\"%s\""%(engine_innodb_perc_total_data))
        writer("myisam_percentage_to_total_index=\"%s\""%(engine_myisam_perc_total_index))
        writer("myisam_percentage_to_total_data=\"%s\""%(engine_myisam_perc_total_data))        
        writer("/>")

        # OS memory 
        os_mem_total = int(get_snmp("UCD-SNMP-MIB::memTotalReal.0")) * 1024
        if os_mem_total == False:
            logger("UCD-SNMP-MIB::memTotalReal.0 failed, trying secondary option...",'d')
            console("UCD-SNMP-MIB::memTotalReal.0 failed, trying secondary option...",2)
            os_mem_total = int(get_snmp(".1.3.6.1.4.1.2021.4.5.0")) * 1024
            if os_mem_total == False:
                return 1            

        console("snmp results: os_mem_total = %s"%(human(os_mem_total)),2)
        mem_perthread_maxalloc = (read_buffer_size + read_rnd_buffer_size + sort_buffer_size + thread_stack + join_buffer_size + binlog_cache_size) * max_connections
        mem_global_maxalloc = innodb_buffer_pool_size + innodb_additional_mem_pool_size + innodb_log_buffer_size + key_buffer_size + query_cache_size

        console("aborted connections",3)
        if Aborted_connects > 999:
            e = find_event(1)
            writer("<alert id=\"1\"")            
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writer("/>")

        console("sync binlog value",3)
        if sync_binlog == 1:
            e = find_event(4)
            writer("<alert id=\"4\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writer("/>")

        try:
            connections_ratio = int(round(((Max_used_connections * 100)/max_connections),2))
            max_connect_R = int(round((Max_used_connections * 1.25)))
            if max_connect_R < 10:
                max_connect_R = 10

        except:
            connections_ratio = 1

        '''operator for later use, some future events are based on max_connections needing to change'''
        max_connections_state = False

        console("connection ratio balance",3)
        if connections_ratio > 85: 
            e = find_event(5) 
            writer("<alert id=\"5\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("Current max_connections = %s"%(max_connections))
            writerx("Current Threads_connected = %s"%(Threads_connected))
            writerx("Historic Max_used_connections = %s"%(Max_used_connections))
            writerx("The number of used connections is: %s percent of the maximum configured."%(connections_ratio))
            recommend("max_connections",max_connect_R)
            max_connections_state = True
            writer("/>")
            
        elif connections_ratio <= 10 and connections_ratio != 1:
            e = find_event(5)  
            writer("<alert id=\"5\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("Current max_connections = %s"%(max_connections))
            writerx("Current Threads_connected = %s"%(Threads_connected))
            writerx("Historic Max_used_connections = %s"%(Max_used_connections))
            writerx("The number of used connections is: %s percent of the maximum configured."%(connections_ratio))
            writerx("Currently using less than 10% of your max_connections. Lowering your max_connections can help avoid an over allocation of memory resources.")
            recommend("max_connections",max_connect_R)
            writer("/>")

        console("query cache status",3)
        if query_cache_size == 0:
            e = find_event(6)  
            writer("<alert id=\"6\"") 
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Query cache NOT enabled. Please enable.")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("query_cache_size","4M")
            writer("/>")
            
        else:
            try:
                Qratio = int(round(((query_cache_size - Qcache_free_memory) * 100) / query_cache_size))
            except:
                Qratio = 1

            query_cache_size_HR = human(int(query_cache_size))
            Qcache_free_memory_HR = human(int(Qcache_free_memory))

            if((Qcache_lowmem_prunes >= 50) and (((query_cache_size - Qcache_free_memory) / query_cache_size) >= .85)):
                query_cache_size_R = human(int((query_cache_size - Qcache_free_memory) * 1.25))
                e = find_event(6)
                writer("<alert id=\"6\"") 
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("Current Qcache_lowmem_prunes = %i"%(Qcache_lowmem_prunes))
                writerx("Current Qcache_free_memory = %s"%(Qcache_free_memory_HR))
                writerx("Current query_cache size = %s"%(query_cache_size_HR))
                writerx("Current query cache usage ratio = %i percentage"%(Qratio))
                writerx("Query cache recommended size = %s"%(query_cache_size_R))                
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                recommend("query_cache_size",query_cache_size_R)
                writer("/>")
    
            if (((query_cache_size - Qcache_free_memory) / query_cache_size) <= .25):
                query_cache_size_R = human(int((query_cache_size - Qcache_free_memory) * 1.25))
                e = find_event(7)
                writer("<alert id=\"7\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                writerx("Current Qcache_lowmem_prunes = %i"%(Qcache_lowmem_prunes))
                writerx("Current Qcache_free_memory = %s"%(Qcache_free_memory_HR))
                writerx("Current query_cache size = %s"%(query_cache_size_HR))
                writerx("Current query cache usage ratio = %i"%(Qratio))
                writerx("Query cache recommended size = %s"%(query_cache_size_R))
                recommend("query_cache_size",query_cache_size_R)
                writer("/>")
                
        
        #### MEMORY
        total_system_memory = os_mem_total
        effective_tmp_table_size = 0

        if max_heap_table_size >= tmp_table_size:
            effective_tmp_table_size = max_heap_table_size
        else:
            effective_tmp_table_size = tmp_table_size

        per_thread_buffers = ((read_buffer_size + read_rnd_buffer_size + sort_buffer_size + thread_stack + join_buffer_size + binlog_cache_size) * max_connections)
        per_thread_max_buffers = ((read_buffer_size + read_rnd_buffer_size + sort_buffer_size + thread_stack + join_buffer_size + binlog_cache_size) * Max_used_connections)
        global_buffers = (innodb_buffer_pool_size + innodb_additional_mem_pool_size + innodb_log_buffer_size + key_buffer_size + query_cache_size)
        max_memory = (global_buffers + per_thread_max_buffers)
        total_memory = (global_buffers + per_thread_buffers)    

        try:
            pct_of_sys_mem = int(round((total_memory * 100) / total_system_memory))
        except:
            pct_of_sys_mem = 0

        per_thread_buffers_HR = human(int(per_thread_buffers))
        per_thread_max_buffers_HR = human(int(per_thread_max_buffers))
        global_buffers_HR = human(int(global_buffers))
        max_memory_HR = human(int(max_memory))
        total_memory_HR = human(int(total_memory))
        total_system_memory_HR = human(int(total_system_memory))

        console("system memory allocation",3)
        if pct_of_sys_mem > 85:
            e = find_event(8)
            writer("<alert id=\"8\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Per-Thread buffers: %s"%(per_thread_buffers_HR))
            writerx("Per-Thread max allocated: %s"%(per_thread_max_buffers_HR))
            writerx("Global buffers: %s"%(global_buffers_HR))
            writerx("Max memory ever allocated: %s"%(max_memory_HR))
            writerx("Max memory possible by configuration: %s"%(total_memory_HR))
            writerx("Available system memory: %s"%(total_system_memory_HR))
            writerx("Memory allocation ratio to available system memory: %i percent"%(pct_of_sys_mem))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))            
            writer("/>")

        try:
            full_table_scans = (Handler_read_rnd_next/Com_select)
        except:
            full_tables_scans = 0

        console("read buffer state",3)
        if Com_select > 0:
            if full_table_scans >= 4000 and read_buffer_size >= 209715:
                read_buffer_sizeR = int(round(read_buffer_size * 1.5))

                e = find_event(9)
                writer("<alert id=\"9\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("You have a high ratio of sequential access requests to SELECTs.")
                writerx("You may benefit from raising the read_buffer_size and/or improving your use of indexes.")
                writerx("Current size is: %s"%(human(int(read_buffer_size))))
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                recommend("read_buffer_size",read_buffer_sizeR)
                writer("/>")

        try:            
            tmp_disk_tables = int(round(((Created_tmp_disk_tables*100)/Created_tmp_tables)))
        except:
            tmp_disk_tables = 0

        console("tmp table state",3)
        if tmp_table_size > max_heap_table_size:            
            max_heap_table_sizeR = human(int(tmp_table_size))
            e = find_event(10)
            writer("<alert id = \"10\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current max_heap_table_size  = %i "%(max_heap_table_size))
            writerx("Current tmp_table_size  =  %i"%(tmp_table_size))
            writerx("Of Created_tmp_tables temp tables, %i percent were created on disk"%(tmp_disk_tables))
            writerx("Effective in-memory tmp_table_size is limited to max_heap_table_size.")
            writerx("Increase the size of max_heap_table_size.")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("max_heap_table_size",max_heap_table_sizeR)
            writer("/>")
            
        elif tmp_disk_tables >=  25:
            tmp_table_sizeR = tmp_table_size * 2
            max_heap_table_sizeR = tmp_table_size * 2
            e = find_event(10)
            writer("<alert id = \"10\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Increase tmp_table_size, Current size is %i"%(tmp_table_size))
            writerx("Increase max_heap_table_size, Current size is %i"%(max_heap_table_size))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("tmp_table_size",tmp_table_sizeR)
            recommend("max_heap_table_size",max_heap_table_sizeR)
            writer("/>")

            
        console("innodb engine state",3)
        allowed_innodb_buffer_size = 0
        if have_innodb == "YES":
            if "InnoDB" in get_rows("select distinct(engine) from information_schema.tables"):
                innodb_have_data = True
                engine_innodb_size_index = get_single("select sum(INDEX_LENGTH) as Value from information_schema.tables where engine='innodb'")
                engine_innodb_size_data = get_single("select sum(DATA_LENGTH) as Value from information_schema.tables where engine='innodb'")
                needed_innodb_buffer_size = ((engine_innodb_size_index + engine_innodb_size_data)* 1.15)
                
                try:
                    innodb_recommend = human(int(((needed_innodb_buffer_size * 100) / 85)))
                except:
                    innodb_recommend = human(0)
                
                innodb_buffer_pool_sizeHR = human(int(innodb_buffer_pool_size))
                allowed_innodb_buffer_sizeHR = 0
                needed_innodb_buffer_sizeHR = human(int(needed_innodb_buffer_size))
                engine_innodb_size_indexHR = human(int(engine_innodb_size_index))
                engine_innodb_size_dataHR = human(int(engine_innodb_size_data))
                os_mem_totalHR = human(int(os_mem_total))
                innodb_percent_suggest = 0
        
                try:
                    innodb_percent = (engine_count_innodb/num_tables)
                except:
                    innodb_percent = 0

                if innodb_percent <=  .25:
                    innodb_percent_suggest = "25%"
                    allowed_innodb_buffer_size = os_mem_total * .25

                elif innodb_percent <= .5:
                    innodb_percent_suggest = "50%"
                    allowed_innodb_buffer_size = os_mem_total * .50

                elif innodb_percent <= .75:
                    innodb_percent_suggest = "75%"
                    allowed_innodb_buffer_size = os_mem_total * .625
            
                elif innodb_percent <= 1:
                    innodb_percent_suggest = "75%"
                    allowed_innodb_buffer_size = os_mem_total * .75

                if Innodb_buffer_pool_pages_free == 0:
                    Innodb_buffer_pool_pages_free = 1
            
                if Innodb_buffer_pool_pages_total == 0:
                    Innodb_buffer_pool_pages_total = 1

                try:
                    Innodb_buffer_pool_pages_ratio = int(round(Innodb_buffer_pool_pages_free/Innodb_buffer_pool_pages_total))
                except:
                    Innodb_buffer_pool_pages_ratio = 0

                innodb_percent = int(round((innodb_percent * 100),2))
                allowed_innodb_buffer_sizeHR = human(int(allowed_innodb_buffer_size))

                if innodb_buffer_pool_size < needed_innodb_buffer_size and innodb_buffer_pool_size < allowed_innodb_buffer_size:
                    e = find_event(11)
                    writer("<alert id = \"11\"")
                    writer("name=\"%s\""%(e[1]))
                    writer("category=\"%s\""%(e[5]))
                    writerx("Current number of InnoDB tables: "+str(engine_count_innodb))
                    writerx("Current number of total database tables: "+str(num_tables))
                    writerx("Current innodb aggregate index space: "+(engine_innodb_size_indexHR))
                    writerx("Current innodb aggregate data space: "+(engine_innodb_size_dataHR))
                    writerx("Current innodb_buffer_pool_size  =  "+(innodb_buffer_pool_sizeHR))
                    writerx("Total needed for innodb index+data space: "+(needed_innodb_buffer_sizeHR))
                    writerx("Percentage of InnoDB tables to total tables: "+str(innodb_percent+"%"))
                    writerx("Your % of InnoDB tables to total puts you in the "+str(innodb_percent_suggest)+" equation.")
                    writerx("Maximum size for innodb_buffer_pool_size ("+str(innodb_percent_suggest)+" of OS mem total): "+str(allowed_innodb_buffer_sizeHR))
                    writerx("Recommended size of innodb_buffer_pool size for 85% fill: "+str(innodb_recommend))
                    writerx("Innodb_buffer_pool_pages_free: "+str(Innodb_buffer_pool_pages_free))
                    writerx("Innodb_buffer_pool_pages_total: "+str(Innodb_buffer_pool_pages_total))
                    writerx("Current Innodb_buffer_pool_pages_ratio  =  "+str(Innodb_buffer_pool_pages_ratio)+" : 1")
                    writer("description=\"%s\""%(e[2]))
                    writer("links=\"%s\""%(e[4]))
                    writer("solution=\"%s\""%(e[3]))
                    recommend("innodb_buffer_pool_size",allowed_innodb_buffer_sizeHR)
                    writer("/>")
                    
                if innodb_buffer_pool_size > needed_innodb_buffer_size:
                    e = find_event(12)
                    writer("<alert id = \"12\"")
                    writer("name=\"%s\""%(e[1]))
                    writer("category=\"%s\""%(e[5]))
                    writerx("Current number of InnoDB tables: "+str(engine_count_innodb))
                    writerx("Current number of total database tables: "+str(num_tables))
                    writerx("Current innodb aggregate index space: "+(engine_innodb_size_indexHR))
                    writerx("Current innodb aggregate data space: "+(engine_innodb_size_dataHR))
                    writerx("Current innodb_buffer_pool_size  =  "+(innodb_buffer_pool_sizeHR))
                    writerx("Total needed for innodb index+data space: "+(needed_innodb_buffer_sizeHR))
                    writerx("Percentage of InnoDB tables to total tables: "+str(innodb_percent+"%"))
                    writerx("Your % of InnoDB tables to total puts you in the "+str(innodb_percent_suggest)+" equation.")
                    writerx("Maximum size for innodb_buffer_pool_size ("+str(innodb_percent_suggest)+" of OS mem total): "+str(allowed_innodb_buffer_sizeHR))
                    writerx("Recommended size of innodb_buffer_pool size for 85% fill: "+str(innodb_recommend))
                    writerx("Innodb_buffer_pool_pages_free: "+str(Innodb_buffer_pool_pages_free))
                    writerx("Innodb_buffer_pool_pages_total: "+str(Innodb_buffer_pool_pages_total))
                    writerx("Current Innodb_buffer_pool_pages_ratio  =  "+str(Innodb_buffer_pool_pages_ratio)+" : 1")                    
                    writer("description=\"%s\""%(e[2]))
                    writer("links=\"%s\""%(e[4]))
                    writer("solution=\"%s\""%(e[3]))                    
                    recommend("innodb_buffer_pool_size",allowed_innodb_buffer_sizeHR)
                    writer("/>")
            else:
                innodb_have_data = False
            
        console("key read values",3)
        if Key_reads == 0:
            e = find_event(13)
            writer("<alert id = \"13\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("No Key_reads. Use some indexes please.")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writer("/>")
            key_cache_miss_rate = 0
            key_buffer_ratio = 0
            key_buffer_ratioRND = 0
            
        else:
            try:
                key_cache_miss_rate = int(round(Key_read_requests/Key_reads))
            except:
                key_cache_miss_rate = 0

            if Key_blocks_unused > 0:
                key_blocks_total = (Key_blocks_used+Key_blocks_unused)
                
                try:
                    key_buffer_fill = (Key_blocks_used/key_blocks_total)
                except:
                    key_buffer_fill = 0

                key_buffer_ratio = int(round(key_buffer_fill*100))
                key_buffer_ratioRND = int(round(key_buffer_ratio))

            else:
                key_blocks_total = (Key_blocks_used+Key_blocks_unused)

                try:
                    key_buffer_fill  =  (Key_blocks_used / key_blocks_total)
                except:
                    key_buffer_fill = 0

                try:
                    key_buffer_ratio  =  (100 * (Key_blocks_used / key_blocks_total))
                except:
                    key_buffer_ratio = 0

                key_buffer_ratioRND  =  int(round(key_buffer_ratio))
                
            key_buffer_sizeHR  =  human(int(key_buffer_size))
            key_blocks_totalHR  =  human(int(key_blocks_total))

            if Key_blocks_used == 0:
                Key_blocks_used = 1
            if key_blocks_total == 0:
                key_blocks_total = 1

            try:
                key_recommend = human(int(((((Key_blocks_used * key_buffer_size) / key_blocks_total) * 100) / 95)))
            except:
                key_recommend = human(int((get_single("select sum(INDEX_LENGTH) from information_schema.tables where ENGINE='myisam'"))/2))
   
            if ((key_cache_miss_rate >=  1000) or (key_buffer_ratio <=  50)):
                key_buffer_sizeC  =  human(int(key_buffer_size / 2))
                e = find_event(13)
                writer("<alert id = \"13\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("Current Key_reads  =  "+str(Key_reads))
                writerx("Current Key_read_requests  =  "+str(Key_read_requests))
                writerx("Current Key_blocks_used  =  "+str(Key_blocks_used))
                writerx("Current Key_blocks_unused  =  "+str(Key_blocks_unused))
                writerx("Current key_blocks_total: "+str(key_blocks_total))
                writerx("Current buffer fill ratio  =  "+str(key_buffer_ratio)+"%")
                writerx("Current cache miss rate is 1:"+str(key_cache_miss_rate))
                writerx("Current key_buffer_size  =  "+str(key_buffer_sizeHR))
                writerx("Recommended key_buffer_size for 95% fill  =  "+str(key_recommend))
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                recommend("key_buffer_size",key_recommend)
                writer("/>")

            if ((Key_blocks_unused  ==  0) or (key_buffer_ratioRND >=  85)):
                key_buffer_sizeC = human(int(key_buffer_size * 2))
                e = find_event(14)
                writer("<alert id = \"14\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("Current Key_reads  =  "+str(Key_reads))
                writerx("Current Key_read_requests  =  "+str(Key_read_requests))
                writerx("Current Key_blocks_used  =  "+str(Key_blocks_used))
                writerx("Current Key_blocks_unused  =  "+str(Key_blocks_unused))
                writerx("Current key_blocks_total: "+str(key_blocks_total))
                writerx("Current buffer fill ratio  =  "+str(key_buffer_ratio)+"%")
                writerx("Current cache miss rate is 1:"+str(key_cache_miss_rate))
                writerx("Current key_buffer_size  =  "+str(key_buffer_sizeHR))
                writerx("Recommended key_buffer_size for 95% fill  =  "+str(key_recommend))
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                writerx("Increase the key_buffer_size (we want between 75-90% buffer fill ratio)")
                if key_cache_miss_rate >=  1000:
                    writerx("Your key_buffer_size miss rate is higher than 1:1000")
                    writerx("If you are getting a fill rate over 95% but have a miss rate of over 1:1000 then you probably want to look into optimizing your indexes. See Key_read_requests/Key_reads.")
                recommend("key_buffer_size",key_recommend)
                writer("/>")

        total_sorts = (Sort_scan+Sort_range)
        sort_buffer_size = (sort_buffer_size+8)
        read_rnd_buffer_size = (read_rnd_buffer_size+8)
        sort_buffer_sizeHR  =  human(int(sort_buffer_size))
        read_rnd_buffer_sizeHR  =  human(int(read_rnd_buffer_size))
        passes_per_sort  =  0
        
        if total_sorts == 0:
            passes_per_sort = 0

        if Sort_merge_passes != 0:
            try:
                passes_per_sort = (Sort_merge_passes/total_sorts)
            except:
                passes_per_sort = 0

        console("sort buffer state",3)
        if passes_per_sort >= 2:
            sort_buffer_size_R  =  human(int(sort_buffer_size * 2))
            read_rnd_buffer_size_R  =  human(int(read_rnd_buffer_size * 2))
            e = find_event(15)
            writer("<alert id = \"15\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current passes_per_sort  =  "+str(passes_per_sort))
            writerx("Current sort_buffer_size  =  "+str(sort_buffer_sizeHR))
            writerx("Current read_rnd_buffer_size  =  "+str(read_rnd_buffer_sizeHR))
            writerx("# Recommend: sort_buffer_size  =  "+str(sort_buffer_size_R))
            writerx("# Recommend: read_rnd_buffer_size  =  "+str(read_rnd_buffer_size_R))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3])) 
            recommend("sort_buffer_size",sort_buffer_size_R)
            recommend("read_rnd_buffer_size",read_rnd_buffer_sizeHR)
            writer("/>")
            
        if passes_per_sort < 2 and sort_buffer_size > 0:
            sort_buffer_size_R  =  human(int(sort_buffer_size / 2))
            read_rnd_buffer_size_R  =  human(int(read_rnd_buffer_size / 2))
            e = find_event(16)
            writer("<alert id = \"16\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current passes_per_sort  =  "+str(passes_per_sort))
            writerx("Current sort_buffer_size  =  "+str(sort_buffer_sizeHR))
            writerx("Current read_rnd_buffer_size  =  "+str(read_rnd_buffer_sizeHR))
            writerx("# Recommend: sort_buffer_size  =  "+str(sort_buffer_size_R))
            writerx("# Recommend: read_rnd_buffer_size  =  "+str(read_rnd_buffer_size_R))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("sort_buffer_size",sort_buffer_size_R)
            recommend("read_rnd_buffer_size",read_rnd_buffer_size_R)
            writer("/>")

        console("join buffer state",3)
        join_buffer_size = (join_buffer_size+4096)
        join_buffer_sizeHR = human(int(join_buffer_size))
        if Select_full_join > 0 or Select_range_check > 0:
            join_buffer_size_R  =  (join_buffer_size * 2)
            join_buffer_size_R_HR  =  human(int(join_buffer_size_R))
            e = find_event(17)
            writer("<alert id = \"17\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("You have had "+str(Select_range_check)+" joins without keys that check for key usage after each row.")
            writerx("Current join_buffer_size  =  "+str(join_buffer_sizeHR))
            writerx("Current Select_full_join  =  "+str(Select_full_join))
            writerx("Current Select_range_check  =  "+str(Select_range_check))
            writerx("You have had "+str(Select_full_join)+" queries where a join could not use an index properly.")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("# Recommend a starting point of "+str(join_buffer_size_R_HR))
            recommend("join_buffer_size",join_buffer_size_R_HR)
            writer("/>")
            
        if join_buffer_size > 4194304:
            join_buffer_size_R  =  4194303
            join_buffer_size_R  =  (join_buffer_size_R - 8192)
            join_buffer_size_R_HR  =  human(int(join_buffer_size_R))
            e = find_event(18)
            writer("<alert id = \"18\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current join_buffer_size  =  "+str(join_buffer_sizeHR))
            writerx("Current Select_full_join  =  "+str(Select_full_join))
            writerx("Current Select_range_check  =  "+str(Select_range_check))
            writerx("You have had "+str(Select_full_join)+" queries where a join could not use an index properly.")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("# Recommend a starting point of "+str(join_buffer_size_R_HR))
            recommend("join_buffer_size",join_buffer_size_R_HR)
            writer("/>")
            
        try:
            open_files_ratio  =  int(round((Open_files / open_files_limit) * 100))
        except:
            open_files_ratio = 0
        
        console("open files state",3)
        if open_files_ratio >=  75:
            open_files_limit_R  =  int(round(open_files_limit * 1.25))
            e = find_event(19)
            writer("<alert id = \"19\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current open_files_limit  =  "+str(open_files_limit))
            writerx("Current Open_files  =  "+str(Open_files))
            writerx("Current usage ration  =  "+str(open_files_ratio)+" %")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("# Recommend a setting of open_files_limit  =  "+str(open_files_limit_R))
            recommend("open_files_limit",open_files_limit_R)
            writer("/>")
            
        console("table locking values",3)
        immediate_locks_miss_rate  =  0
        if innodb_have_data == True:
            innodb_ratio  =  int(round((engine_count_innodb / num_tables) * 100))
        else:
            innodb_ratio = 0

        if ((Table_locks_immediate  ==  0 ) or (Table_locks_waited  ==  0 )):
            immediate_locks_miss_rate  =  .001
        else:
            if Table_locks_immediate > 0 and Table_locks_waited > 0:
                immediate_locks_miss_rate = int(round((Table_locks_immediate/Table_locks_waited),2))
            else:
                immediate_locks_miss_rate = 0
        
        if ((immediate_locks_miss_rate < 5000) and (innodb_ratio <=  66)):
            e = find_event(20)
            writer("<alert id = \"20\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current table lock wait ratio  =  "+str(immediate_locks_miss_rate)+":"+str(Questions))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("You may want to consider migrating your high-use tables to InnoDB as your table lock ratio is too high.")
            writerx("Your ratio of InnoDB tables to total tables  =  "+str(innodb_ratio)+"%")
            writer("/>")

        console("table cache state",3)
        table_cache_hit_rate  =  0
        table_cache_fill  =  0       
        mark = False
        if table_open_cache == True:
            table_cache = table_open_cache

        if ((Opened_tables !=  0) and (table_cache !=  0)):
            table_cache_hit_rate = int(round((Open_tables*100)/Opened_tables))
            table_cache_fill = int(round((Open_tables*100)/table_cache))

        elif((Opened_tables  ==  0) and (table_cache !=  0)):
            table_cache_hit_rate = 100
            table_cache_fill = ((Open_tables*100)/table_cache)

        if ((table_cache_hit_rate >=  95) or (table_cache_fill >=  95)):
            table_cache_R  =  int(round(Open_tables * 1.6))
            mark == True

        if ((table_cache_hit_rate <=  75) or (table_cache_fill <=  75)):
            table_cache_R  =  int(round(Open_tables * 1.6))
            mark == True

        if mark == True:
            e = find_event(22)
            writer("<alert id = \"22\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            writerx("Current table_cache value  =  "+str(table_cache)+"tables")
            writerx("Current Open_tables  =  "+str(Open_tables))
            writerx("Current table_cache_fill_ratio percentage is: "+str(table_cache_fill))
            writerx("Current table_cache_hit_rate percentage  is: "+str(table_cache_hit_rate))
            writerx("# Recommend table_cache = "+str(table_cache_R))
            recommend("table_cache",table_cache_R)
            writer("/>")
            
        Conn_global  =  len(get_rows("show full processlist"))
        if Threads_created > 1:
            Historic_threads_per_second = int(round(Threads_created/Uptime))
        else:
            Historic_threads_per_second = 0

        console("thread cache state",3)
        if Threads_cached == 0:
            thread_cache_size_R = max_connections
            e = find_event(23)
            writer("<alert id = \"23\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Thread_cache disabled. Please enable thread caching.")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("thread_cache_size",thread_cache_size_R)
            writer("/>")
        
        else:
            mark = False
            Thread_hit_ratio  =  round(100 - ((Threads_created / Connections) * 100),2)

            if Thread_hit_ratio > 95 and Thread_hit_ratio < 99:
                mark = False

            elif Thread_hit_ratio < 95 and Thread_hit_ratio > 85:
                mark = True
                thread_cache_R  =  int(round((thread_cache_size * 2)))

            elif Thread_hit_ratio < 85:
                mark = True
                thread_cache_R  =  int(round((thread_cache_size * 4)))

            if mark == True:                
                e = find_event(24)
                writer("<alert id = \"24\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("Total Connections since start: "+str(Connections))
                writerx("Current thread_cache_size: "+str(thread_cache_size))
                writerx("Current Threads_cached: "+str(Threads_cached))
                writerx("Current Threads_connected: "+str(Threads_connected))
                writerx("Current Threads_created: "+str(Threads_created))
                writerx("Current Global connections: "+str(Conn_global))
                writerx("Historic Max_used_connections: "+str(Max_used_connections))
                writerx("Historic_threads_per_second: "+str(Historic_threads_per_second))
                writerx("Thread_hit_ratio: "+str(Thread_hit_ratio)+" %")
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))            
                writerx("# Recommend thread_cache_size  =  "+str(thread_cache_R))
                recommend("thread_cache_size",thread_cache_R) 
                writer("/>")            

        console("binlog cache state",3)
        mark = False
        note0 = ""
        if Binlog_cache_disk_use  ==  0:
                Binlog_cache_disk_use = 1
        if Binlog_cache_use  ==  0:
            Binlog_cache_use = 1
        
        if binlog_cache_size > 0:
            bcache_tmp_ratio  =  (Binlog_cache_disk_use / Binlog_cache_use)
            binlog_cache_size_HR  =  human(int(binlog_cache_size))
            binlog_total_usage  =  (Binlog_cache_disk_use + Binlog_cache_use)
            
            if bcache_tmp_ratio < 25:
                if Binlog_cache_disk_use > 1024:
                    binlog_cache_size_R  =  int(binlog_cache_size / 2)
                    node0 = "Your binlog_cache has less than 25% utilization."
                    mark == True

            elif bcache_tmp_ratio > 25 and bcache_tmp_ratio < 95:
                binlog_cache_size_R  =  int(binlog_cache_size * bcache_tmp_ratio)
                note0 = "Your binlog_cache_size exceeds 25% utilization"
                mark = True

            if mark == True:
                e = find_event(25)
                writer("<alert id = \"25\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("Current binlog_cache_size  =  "+str(binlog_cache_size_HR))
                writerx("Current binlog cache usage by transactions: "+str(Binlog_cache_use))
                writerx("Current tmp files created for binlog usage: "+str(Binlog_cache_disk_use))
                writerx("Out of binlog_total_usage writes, "+str(Binlog_cache_disk_use)+" have been to tmp disk files.")
                writerx("Your binlog_cache utilization ratio: "+str(bcache_tmp_ratio)+"%")
                writerx(note0)
                writerx("Your binlog_cache has failed to buffer %s transactions"%(str(Binlog_cache_disk_use)))
                writerx("# Recommend binlog_cache_size  =  "+str(binlog_cache_size_R))
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                recommend("binlog_cache_size",binlog_cache_size_R)
                writer("/>") 
                
        
        console("tmp table usage",3)
        tmp_disk_ratio  =  0
        if Created_tmp_tables  ==  0:
            tmp_disk_ratio = 0
        else:
            tmp_disk_ratio = int(round((Created_tmp_disk_tables/Created_tmp_tables)*100))

        max_heap_table_sizeHR = human(int(max_heap_table_size))
        tmp_table_sizeHR = human(int(tmp_table_size))
        tmp_per_sec  =  int(round(Created_tmp_tables/Uptime))
        heap_to_tmp  =  int(round((max_heap_table_size/tmp_table_size)*100))
        
        if tmp_disk_ratio >=  75:
            tmp_table_size_R  =  human(int(tmp_table_size * (((100 - tmp_disk_ratio)/100)+2)))
            e = find_event(26)
            writer("<alert id = \"26\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current max_tmp_tables  =  "+str(max_tmp_tables))
            writerx("Current max_heap_table_size  =  "+str(max_heap_table_sizeHR))
            writerx("Current tmp_table_size  =  "+str(tmp_table_sizeHR))
            writerx("Current Created_tmp_tables  =  "+str(Created_tmp_tables))
            writerx("Current Created_tmp_disk_tables  =  "+str(Created_tmp_disk_tables))
            writerx("Currently "+str(tmp_disk_ratio)+"% of tmp tables were created on disk")
            writerx("Ratio of tmp_table_size to in-memory allowance: "+str(heap_to_tmp)+"%")
            writerx("Average usage  =  "+str(tmp_per_sec)+" tmp tables/sec")
            writerx("# Recommend tmp_table_size  =  "+str(tmp_table_size_R))
            if max_tmp_tables > 32:
                writerx("If you consistently need more tmp tables you probably would be better off adding more RAM and putting tmpdir on RAMDISK")
                writerx("Note: Effective in-memory tmp_table_size is limited to max_heap_table_size.")                                   
                writerx("# Recommend default setting max_tmp_tables  =  32")
                
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("tmp_table_size",tmp_table_size_R)
            recommend("max_heap_table_size",tmp_table_size_R)            
            writer("/>")

        console("flush time value",3)
        if flush_time > 0:
            e = find_event(27)
            writer("<alert id = \"27\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("flush_time",0)
            writer("/>")

        console("secondary query cache check",3)
        if query_cache_type  ==  "OFF" or query_cache_size  ==  0:
            e = find_event(34)
            writer("<alert id = \"34\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current query_cache_type  =  "+str(query_cache_type))
            writerx("Current query_cache_size  =  "+str(query_cache_size))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("query_cache_size","4M")
            writer("/>")
            
        console("thread cache secondary check",3)
        if thread_cache_size  == 0:
            e = find_event(37)
            writer("<alert id = \"37\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Current thread_cache_size  =  "+str(thread_cache_size))
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("thread_cache_size",(max_connections * .5))
            writer("/>")


        console("tmp table secondary check",3)
        max_heap_table_size_HR  =  human(int(round(max_heap_table_size)))
        max_heap_table_size_R  =  (tmp_table_size * .8)
        tmp_table_size_R  =  human(int(max_heap_table_size_R * 1.2))
        tmp_disk_ratio  =  0
        
        if Created_tmp_tables == 0:
            tmp_disk_ratio = 0

        else:
            tmp_disk_ratio = int(round((Created_tmp_disk_tables/Created_tmp_tables)*100))
            
            max_heap_table_sizeHR = human(int(max_heap_table_size))
            tmp_table_sizeHR = human(int(tmp_table_size))
            tmp_per_sec  =  int(round(Created_tmp_tables/Uptime))
            heap_to_tmp  =  int(round((max_heap_table_size/tmp_table_size)*100))
        
            if heap_to_tmp < 75:
                e = find_event(100)
                writer("<alert id = \"100\"")
                writer("name=\"%s\""%(e[1]))
                writer("category=\"%s\""%(e[5]))
                writerx("Current max_heap_table_size  =  "+str(max_heap_table_sizeHR))
                writerx("Current tmp_table_size  =  "+str(tmp_table_sizeHR))
                writerx("Currently "+str(tmp_disk_ratio)+"% of tmp tables were created on disk")
                writerx("Ratio of tmp_table_size to in-memory allowance: "+str(heap_to_tmp)+"%")
                writer("description=\"%s\""%(e[2]))
                writer("links=\"%s\""%(e[4]))
                writer("solution=\"%s\""%(e[3]))
                recommend("tmp_table_size",tmp_table_size_R)
                recommend("max_heap_table_size",tmp_table_size_R)
                writer("/>")
                
        console("security checks",3)
        if old_passwords == "ON":
            e = find_event(48)
            writer("<alert id = \"48\"")
            writer("name=\"%s\""%(e[1]))
            writer("category=\"%s\""%(e[5]))
            writerx("Old password hashing is enabled!")
            writer("description=\"%s\""%(e[2]))
            writer("links=\"%s\""%(e[4]))
            writer("solution=\"%s\""%(e[3]))
            recommend("old_passwords","OFF")
            writer("/>")

        out_end()
        return 0

if __name__ == "__main__":
    header()
    conn = None 
    reuse_conn = True
    (options, args) = parse_options()

    #create log instance
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # debug console output
    c = logging.StreamHandler(sys.stdout)
    c.setLevel(logging.INFO)
    c.setFormatter(formatter)

    # debug logfile
    f = logging.FileHandler(options.outfile)
    f.setLevel(logging.DEBUG)
    f.setFormatter(formatter)

    if options.debugout:
        log.addHandler(c)

    log.addHandler(f)
    #end log creation

    # start mysql connection
    console("running with python: %s"%(major[0]+"."+minor[0]),2)
    if options.conf_file:
        mysql_host, mysql_user, mysql_password, mysql_database, mysql_port, mysql_socket, outfile, xmlfile, snmp_port, snmp_host, snmp_version, snmp_rocommunity = getconf()
    else:
        mysql_host = options.mysql_host
        mysql_user = options.mysql_user
        mysql_password = options.mysql_password
        mysql_database = options.mysql_database
        mysql_port = options.mysql_port
        mysql_socket = options.mysql_socket
        outfile = options.outfile
        xmlfile = options.xmlfile
        snmp_port = options.snmp_port
        snmp_host = options.snmp_host
        snmp_version = options.snmp_version
        snmp_rocommunity = options.snmp_rocommunity    

    console("--------------------------\nconnection settings\n--------------------------",2)
    console("mysql username: %s"%(mysql_user),2)
    console("mysql password: %s"%(mysql_password),2)
    console("mysql database: %s"%(mysql_database),2)    
    if not mysql_host and mysql_host != "127.0.0.1" and mysql_host != "localhost":
        mysql_host = "localhost"
        console("mysql socket: %s"%(mysql_socket),2)        
    else:
        hostname = mysql_host
        console("mysql port: %i"%(mysql_port),2)
    console("mysql hostname: %s"%(mysql_host),2)
    console("snmp version: %s"%(snmp_version),2)
    console("snmp community: %s"%(snmp_rocommunity),2)
    console("snmp host: %s"%(snmp_host),2)
    console("snmp port: %s"%(snmp_port),2)
    console("--------------------------",2)
            
    conn = open_connection()
    try:
        retval = main()
    except (KeyboardInterrupt, SystemExit):
        sys.exit(1)
