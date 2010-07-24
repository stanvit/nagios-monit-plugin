#!/usr/bin/env python

import httplib
from optparse import OptionParser
import sys 
import xml.etree.ElementTree
import re

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

xml_hacks = (
    (re.compile(r"<request>(.*?)</request>",flags=re.MULTILINE), (r"<request><![CDATA[\1]]></request>")),
)


warnings = []
errors = []
totsvcs = 0

svc_includere = None
svc_excludere = None
opts = None

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

def get_status():
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

def process_ystem(service):
    system = service.find('system')

def process_service(service):
    global totsvcs
    svctype_num = service.get('type')
    #if svctype_num == "5": process_system(service)
    svctype = svc_types.get(svctype_num,svctype_num)
    svcname = service.find('name').text
    if svc_excludere and re.match(svc_excludere,svcname): return
    if svc_includere and not re.match(svc_includere,svcname): return
    monitor = service.find('monitor').text
    status_num = service.find('status').text
    totsvcs += 1
    
    if not monitor == "1":
        warnings.append('%s %s is unmonitored'%(svctype, svcname))
    
    if not status_num == "0":
        status_message = service.find('status_message').text
        errors.append('%s %s: %s'%(svctype,svcname,status_message))

def process_status(status):
    for regex, replacement in xml_hacks:
        status = re.sub(regex, replacement,status)
    #from xml.dom import minidom
    #print xml.dom.minidom.parseString(status).toprettyxml()
    #print status
    tree = xml.etree.ElementTree.fromstring(status)
    for service in  tree.findall('service'):
        process_service(service)

def main():
    global opts, svc_includere, svc_excludere
    p = OptionParser()
    p.add_option("-H","--host", dest="host", help="Hostname or IP address")
    p.add_option("-p","--port", dest="port", type="int", default=2812, help="Port (Default: %default)")
    p.add_option("-s","--ssl", dest="ssl", action="store_true", default=False, help="Use SSL")
    p.add_option("-u","--username", dest="username", help="Username")
    p.add_option("-P","--password", dest="password", help="Password")
    p.add_option("-i","--include", dest="svc_include", help="Regular expression for service(s) to include into monitoring")
    p.add_option("-e","--exclude", dest="svc_exclude", help="Regular expression for service(s) to exclude from monitoring")
    (opts, args) = p.parse_args()

    if not opts.host:
        print "\nUsage: %s -H <host> [<options>]\n"%sys.argv[0]
        print "For full usage instructions please invoke with -h option\n"
        sys.exit(1)

    if opts.svc_include: svc_includere = re.compile(opts.svc_include)
    if opts.svc_exclude: svc_excludere = re.compile(opts.svc_exclude)

    process_status(get_status())
    
    if errors:
        critical('%s'%'; '.join(errors))

    if warnings:
        warning('%s'%'; '.join(warnings))

    ok('Total %i services are monitored'%totsvcs)


if __name__ == '__main__':
    main()

