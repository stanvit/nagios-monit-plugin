# Nagios Monit plugin

This Nagios plugin checks status of [Monit server](https://mmonit.com/monit/) using its XML status.

Unmonitored status causes plugin to return WARNING state, all other failures return CRITICAL state.

## Usage:
```
check_monit.py -H <host> [<options>]
```

## Command line options:
```
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -H HOST, --host=HOST  Hostname or IP address
  -p PORT, --port=PORT  Port (Default: 2812)
  -s, --ssl             Use SSL
  -k, --insecure        Skip SSL certificate verification
  -u USERNAME, --username=USERNAME
                        Username
  -P PASSWORD, --password=PASSWORD
                        Password
  -w SVC_WARN, --warn-only=SVC_WARN
                        Regular expression for service(s) to warn only if
                        failed
  -i SVC_INCLUDE, --include=SVC_INCLUDE
                        Regular expression for service(s) to include into
                        monitoring
  -e SVC_EXCLUDE, --exclude=SVC_EXCLUDE
                        Regular expression for service(s) to exclude from
                        monitoring
  -S SVC_PERFDATA, --service-perfdata=SVC_PERFDATA
                        Regular expression for service(s) to show performance
                        data for
  -T TYPES_PERFDATA, --types-perfdata=TYPES_PERFDATA
                        Service type(s) to show performance data for [PROCESS,
                        FILESYSTEM, FILE, NET], can be used multiple times
  -O PROGRAM_OUTPUT, --program-output=PROGRAM_OUTPUT
                        Regular expression for service(s) to show program
                        output for
  -d, --debug           Print all debugging info
  -v, --verbose         Verbose plugin response
  -M, --memory          Display memory performance data
  -C, --cpu             Display cpu performance data
  -L, --load            Display load average performance data
  -U, --uom             Display units of measure in performance data
  -o, --states-perfdata
                        Add the number of services in ok/warn/critical states
                        to perfdata
  -m MAINTENANCE, --maintenance=MAINTENANCE
                        If this file exist ignore all Unmonitored
                        [/run/monit.maintenance]
  -R, --reverse         Issue a Warning if a service is Failed and Critical if
                        Unmonitored
```

## Sample Nagios configuration

Nagios command definition looks like this:

```
define command{
        command_name    check_monit
        command_line    $USER1$/check_monit.py -H $HOSTADDRESS$ -p 1234 -s -u $USER3$ -P $USER4$
}
```

## License

See the [LICENSE](LICENSE.txt) file for license rights and limitations (MIT).
