#!/usr/bin/env python

import httplib
from optparse import OptionParser
import sys 
import xml.dom.minidom

svc_types = {
    'FILESYSTEM': '0',
    'DIRECTORY': '1',
    'FILE': '2',
    'PROCESS': '3',
    'HOST': '4',
    'SYSTEM': '5',
    'FIFO': '6',
    'STATUS': '7',
} 

for (k, v) in svc_types.items(): svc_types[v] = k

warnings = []
errors = []
totsvcs = 0

def ok(message):
    print "OK: %s"%message
    sys.exit(0)

def warning(message):
    print "WARNING: %s"%message
    sys.exit(1)

def critical(message):
    print "CRITICAL: %s"%message
    sys.exit(2)

def unknown(message):
    print "UNKNOWN: %s"%message
    sys.exit(3)

def get_status(opts):
    if opts.ssl is True:
        HTTPClass = httplib.HTTPSConnection
    else:
        HTTPClass = httplib.HTTPConnection

    connection = HTTPClass(opts.host,opts.port)

    headers = {}

    if opts.username and opts.password:
        import base64
        headers['Authorization'] = 'Basic ' + (base64.encodestring(opts.username + ':' + opts.password)).strip()
    
    try:
        connection.request('GET','/_status?format=xml',headers=headers)
        response = connection.getresponse()
        if not response.status == 200:
            critical('Monit HTTP response: %i:%s'%(response.status, response.reason))
        return response.read()
    except Exception, e:
        critical('Exception: %s'%str(e))

def getText(node,elementname):
    result = []
    for node in node.getElementsByTagName(elementname): 
        if node.nodeType == node.TEXT_NODE:
            result.append(node.data)
        for subnode in node.childNodes:
            if subnode.nodeType in (subnode.TEXT_NODE, subnode.CDATA_SECTION_NODE):
                result.append(subnode.data)
    return ''.join(result)

def process_service(opts,svcnode):
    #print svcnode.toprettyxml()
    global totsvcs
    svctype_num = svcnode.attributes.get('type').nodeValue
    svctype = svc_types.get(svctype_num,svctype_num)
    svcname = getText(svcnode, 'name')
    monitor = getText(svcnode, 'monitor')
    status_num = getText(svcnode, 'status')
    totsvcs += 1
    
    if not monitor == "1":
        warnings.append('%s %s is unmonitored'%(svctype, svcname))

    if not status_num == "0":
        status_message = getText(svcnode, 'status_message')
        errors.append('%s %s: %s'%(svctype,svcname,status_message))

def process_status(opts,status):
    dom = xml.dom.minidom.parseString(status)
    for svcnode in dom.getElementsByTagName('service'):
        process_service(opts,svcnode)

def main():
    p = OptionParser()
    p.add_option("-H","--host", dest="host", help="Hostname or IP address")
    p.add_option("-p","--port", dest="port", type="int", default=2812, help="Port (Default: %default)")
    p.add_option("-s","--ssl", dest="ssl", action="store_true", default=False, help="Use SSL")
    p.add_option("-u","--username", dest="username", help="Username")
    p.add_option("-P","--password", dest="password", help="Password")
    (opts, args) = p.parse_args()

    if not opts.host:
        print "\nUsage: %s -H <host> [<options>]\n"%sys.argv[0]
        print "For full usage instructions please invoke with -h option\n"
        sys.exit(1)

    process_status(opts,get_status(opts))
    
    if errors:
        critical('%s'%'; '.join(errors))

    if warnings:
        warning('%s'%'; '.join(warnings))

    ok('Total %i services monitored'%totsvcs)


if __name__ == '__main__':
    main()

