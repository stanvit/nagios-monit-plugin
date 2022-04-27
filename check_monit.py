#!/usr/bin/env python

from __future__ import print_function

VERSION="%prog 1.5"

try:
    import http.client as httplib
except ImportError:
    import httplib
from optparse import OptionParser
import sys
import os
import xml.etree.ElementTree
import re

mon_state = {
    'not'     : 0x0,
    'yes'     : 0x1,
    'init'    : 0x2,
    'waiting' : 0x4
}

svc_types = {
    'FILESYSTEM': '0',
    'DIRECTORY': '1',
    'FILE': '2',
    'PROCESS': '3',
    'HOST': '4',
    'SYSTEM': '5',
    'FIFO': '6',
    'PROGRAM': '7',
    'NET': '8',
}

## https://nagios-plugins.org/doc/guidelines.html#AEN200
svctype_metrics = {
    'PROCESS': (
        (('memory/percent',), 'mem_pct', '%'),
        (('memory/kilobyte',), 'mem', 'KB'),
        (('cpu/percent',), 'cpu', '%'),
    ),
    'FILESYSTEM': (
        (('block/percent',), 'block_pct', '%'),
        (('inode/percent',), 'inode_pct', '%'),
    ),
    'FILE': (
        (('size',), 'size', 'B'),
    ),
    'NET': (
        (('link/download/packets/total',), 'in_pkt', 'c'),
        (('link/download/bytes/total',), 'in_bytes', 'Bc'),
        (('link/download/errors/total',), 'in_err', 'c'),
        (('link/upload/packets/total',), 'out_pkt', 'c'),
        (('link/upload/bytes/total',), 'out_bytes', 'Bc'),
        (('link/upload/errors/total',), 'out_err', 'c'),
    ),
}

for (k, v) in list(svc_types.items()): svc_types[v] = k

xml_hacks = (
    (re.compile(r"<request>(?!<!\[CDATA\[)(?P<request>.*?)</request>",
                flags=re.MULTILINE),
     r"<request><![CDATA[\g<request>]]></request>"),
)

system_info = []

warnings = []
errors = []
oks = []

services_monitored = []
perfdata = []
output = []

perfdata_string = ''
output_string = ''

svc_includere = None
svc_excludere = None
svc_perfdata = None
types_perfdata = []
program_output = None
opts = None

def ok(message):
    print("OK: %s%s%s"%(message,output_string,perfdata_string))
    sys.exit(0)

def warning(message):
    print("WARNING: %s%s%s"%(message,output_string,perfdata_string))
    sys.exit(1)

def critical(message):
    print("CRITICAL: %s%s%s"%(message,output_string,perfdata_string))
    sys.exit(2)

def unknown(message):
    print("UNKNOWN: %s%s%s"%(message,output_string,perfdata_string))
    sys.exit(3)

def debug_print(text):
    if opts.debug:
        print(text)

def get_status():
    if opts.ssl is True:
        if opts.ignore_cert:
            import ssl
            try:
                # Python 2.7.10+
                ssl._create_default_https_context = ssl._create_unverified_context
            except AttributeError:
                # Python < 2.7.9
                pass
        HTTPClass = httplib.HTTPSConnection
    else:
        HTTPClass = httplib.HTTPConnection

    connection = HTTPClass(opts.host,opts.port)

    headers = {}

    if opts.username and opts.password:
        import base64
        headers['Authorization'] = 'Basic ' + base64.b64encode(
            ('%s:%s' % (opts.username, opts.password)).encode('ascii')
        ).decode('ascii')

    try:
        connection.request('GET','/_status?format=xml',headers=headers)
        response = connection.getresponse()
        if not response.status == 200:
            critical('Monit HTTP response: %i:%s'%(response.status, response.reason))
        return response.read().decode('utf8')
    except Exception as e:
        critical('Exception: %s'%str(e))

def find_existing_prefix(element, prefixes):
    for prefix in prefixes:
        if element.find(prefix) != None:
            return prefix
    return None

def process_system_load(service):
    prefix = find_existing_prefix(service, ["system/load", "load"])
    if prefix is None:
        debug_print("Can't find load info for performance data")
        return

    avg01 = service.find('%s/avg01'%prefix).text
    avg05 = service.find('%s/avg05'%prefix).text
    avg15 = service.find('%s/avg15'%prefix).text
    perfdata.append('load=%s;%s;%s'%(avg01,avg05,avg15))

def process_system_cpu(service):
    prefix = find_existing_prefix(service, ["system/cpu", "cpu"])
    if prefix is None:
        debug_print("Can't find CPU info for performance data")
        return

    cpu_u = service.find('%s/user'%prefix).text
    cpu_s = service.find('%s/system'%prefix).text
    cpu_w = service.find('%s/wait'%prefix).text
    if opts.uom:
        perfdata.append('cpu_u=%s%% cpu_s=%s%% cpu_w=%s%%'%(cpu_u,cpu_s,cpu_w))
    else:
        perfdata.append('cpu_u=%s cpu_s=%s cpu_w=%s'%(cpu_u,cpu_s,cpu_w))

def process_system_mem(service):
    prefix = find_existing_prefix(service, ["system/memory", "memory"])
    if prefix is None:
        debug_print("Can't find memory info for performance data")
        return

    kb = service.find('%s/kilobyte'%prefix).text
    pct = service.find('%s/percent'%prefix).text
    if opts.uom:
        perfdata.append('mem=%s mem_pct=%s%%'%(kb,pct))
    else:
        perfdata.append('mem=%s mem_pct=%s'%(kb,pct))

def process_system_swap(service):
    prefix = find_existing_prefix(service, ["system/swap", "swap"])
    if prefix is None:
        debug_print("Can't find swap info for performance data")
        return

    kb = service.find('%s/kilobyte'%prefix).text
    pct = service.find('%s/percent'%prefix).text
    if opts.uom:
        perfdata.append('swap=%s swap_pct=%s%%'%(kb,pct))
    else:
        perfdata.append('swap=%s swap_pct=%s'%(kb,pct))

def process_perfdata_svc(service, paths_metrics, name):
    for paths, metric, uom in paths_metrics:
        for path in paths:
            element = service.find(path)
            if element != None:
                if opts.uom:
                    perfdata.append("%s_%s=%s%s" % (name, metric, element.text, uom))
                else:
                    perfdata.append("%s_%s=%s" % (name, metric, element.text))
                break

def process_program_output(service, name):
    out = service.find('program/output').text
    if out is not None:
        out = out.replace('\n','\n%s: ' % name)
        output.append("%s: %s" % (name, out))

def process_service(service):
    svctype_num = service.get('type')
    if svctype_num == svc_types['SYSTEM']:
        if opts.process_la:
            process_system_load(service)
        if opts.process_cpu:
            process_system_cpu(service)
        if opts.process_mem:
            process_system_mem(service)
            process_system_swap(service)
    svctype = svc_types.get(svctype_num, svctype_num)
    svcname = service.find('name').text
    if svctype_num == svc_types['PROGRAM']:
        if program_output and re.match(program_output, svcname):
            process_program_output(service, svcname)
    if svctype_num in types_perfdata or (svc_perfdata and re.match(svc_perfdata, svcname)):
        metrics = svctype_metrics.get(svctype, None)
        if metrics:
            process_perfdata_svc(service, metrics, svcname)
    if svc_excludere and re.match(svc_excludere, svcname):
        return
    if svc_includere and not re.match(svc_includere,svcname):
        return
    try:
        monitor = int(service.find('monitor').text)
    except error.ValueError:
        debug_print("Can't determine service status")
        return
    status_num = service.find('status').text
    services_monitored.append(svcname)

    if int(monitor) & mon_state['init']:
        debug_print("Initializing: %s %s" % (svctype, svcname))
        oks.append("%s %s" % (svctype, svcname))

    elif int(monitor) & mon_state['waiting']:
        debug_print("Waiting: %s %s" % (svctype, svcname))
        oks.append("%s %s" % (svctype, svcname))

    elif not int(monitor) & mon_state['yes']:
        debug_print("Unmonitored: %s %s" % (svctype, svcname))
        if maintenance:
            oks.append("%s %s" % (svctype, svcname))
        elif opts.reverse and not (opts.svc_warn and re.match(opts.svc_warn, svcname)):
            errors.append('%s %s is unmonitored'%(svctype, svcname))
        else:
            warnings.append('%s %s is unmonitored'%(svctype, svcname))

    elif not status_num == "0":
        debug_print("Failed: %s %s" % (svctype, svcname))
        try:
            msg = "%s %s: %s" % (svctype, svcname,
                                 service.find('status_message').text)
        except AttributeError:
            msg = "%s %s" % (svctype, svcname)
        if opts.reverse or (opts.svc_warn and re.match(opts.svc_warn, svcname)):
            warnings.append(msg)
        else:
            errors.append(msg)
    else:
        oks.append("%s %s" % (svctype, svcname))

def process_monit_response(response):
    """Processes (hopefelly) XML response from monit"""
    for regex, replacement in xml_hacks:
        response = re.sub(regex, replacement, response)

    if opts.debug:
        print("="*80)
        print("| Monit response: ")
        print("="*80)
        print(response)
    tree = xml.etree.ElementTree.fromstring(response)
    for service in tree.findall('service'):
        process_service(service)
    for infokey in ['server/localhostname', 'server/version',
        'platform/name', 'platform/machine', 'platform/release', 'platform/version']:
        infoval = tree.find(infokey)
        if infoval is not None: system_info.append('%s'%infoval.text)

def main():
    global opts, svc_includere, svc_excludere, svc_perfdata, types_perfdata, program_output, perfdata_string, output_string, maintenance
    p = OptionParser(usage="Usage: %prog -H <host> [<options>]", version=VERSION)
    p.add_option("-H","--host", dest="host", help="Hostname or IP address")
    p.add_option("-p","--port", dest="port", type="int", default=2812, help="Port (Default: %default)")
    p.add_option("-s","--ssl", dest="ssl", action="store_true", default=False, help="Use SSL")
    p.add_option("-k","--insecure", dest="ignore_cert", action="store_true", default=False, help="Skip SSL certificate verification")
    p.add_option("-u","--username", dest="username", help="Username")
    p.add_option("-P","--password", dest="password", help="Password")
    p.add_option("-w","--warn-only", dest="svc_warn", help="Regular expression for service(s) to warn only if failed")
    p.add_option("-i","--include", dest="svc_include", help="Regular expression for service(s) to include into monitoring")
    p.add_option("-e","--exclude", dest="svc_exclude", help="Regular expression for service(s) to exclude from monitoring")
    p.add_option("-S","--service-perfdata", dest="svc_perfdata", help="Regular expression for service(s) to show performance data for")
    p.add_option("-T","--types-perfdata", dest="types_perfdata", action="append", help="Service type(s) to show performance data for [%s], can be used multiple times" % ', '.join(svctype_metrics.keys()))
    p.add_option("-O","--program-output", dest="program_output", help="Regular expression for service(s) to show program output for")
    p.add_option("-d","--debug", dest="debug", action="store_true", default=False, help="Print all debugging info")
    p.add_option("-v","--verbose", dest="verbose", action="store_true", default=False, help="Verbose plugin response")
    p.add_option("-M","--memory", dest="process_mem", action="store_true", default=False, help="Display memory performance data")
    p.add_option("-C","--cpu", dest="process_cpu", action="store_true", default=False, help="Display cpu performance data")
    p.add_option("-L","--load", dest="process_la", action="store_true", default=False, help="Display load average performance data")
    p.add_option("-U","--uom", dest="uom", action="store_true", default=False, help="Display units of measure in performance data")
    p.add_option("-o", "--states-perfdata", dest="states_perfdata",
                 action="store_true", default=False,
                 help="Add the number of services in ok/warn/critical states"
                 " to perfdata")
    p.add_option("-m","--maintenance", dest="maintenance", default="/run/monit.maintenance", help="If this file exist ignore all Unmonitored [/run/monit.maintenance]")
    p.add_option("-R","--reverse", dest="reverse", action="store_true", default=False, help="Issue a Warning if a service is Failed and Critical if Unmonitored")
    (opts, args) = p.parse_args()

    if not opts.host:
        p.error("No <host> defined!")
        sys.exit(1)

    if opts.svc_include:
        svc_includere = re.compile(opts.svc_include)
    if opts.svc_exclude:
        svc_excludere = re.compile(opts.svc_exclude)
    if opts.svc_perfdata:
        svc_perfdata = re.compile(opts.svc_perfdata)
    if opts.types_perfdata:
        for i in opts.types_perfdata:
            if not i in svc_types:
                p.error("Service type %s is unknown" % i)
                sys.exit(1)
            if not i in svctype_metrics:
                p.error("Metrics for Service type %s are not supported" % i)
                sys.exit(1)
            types_perfdata.append(svc_types[i])
    if opts.program_output:
        program_output = re.compile(opts.program_output)

    if opts.maintenance and os.path.isfile(opts.maintenance):
        debug_print("Maintenance File: " + opts.maintenance)
        maintenance = True

    process_monit_response(get_status())
    if opts.states_perfdata:
        perfdata.append("state_ok=%i state_warning=%i state_critical=%i" % (
            len(oks), len(warnings), len(errors)))
    if perfdata:
        perfdata_string = ' | ' + ' '.join(perfdata)
    if output:
        output_string = '\n' + '\n'.join(output)
    if errors:
        critical('%s'%'; '.join(errors))

    if warnings:
        warning('%s'%'; '.join(warnings))

    if opts.verbose:
        ok('Total %i services are monitored: %s; %s'%(len(services_monitored),','.join(services_monitored), ' '.join(system_info)))
    else:
        ok('Total %i services are monitored'%(len(services_monitored)))

if __name__ == '__main__':
    main()
