
This Nagios plugin checks status of Monit server using its XML status.

Unmonitored status causes plugin to return WARNING state, all other failures return CRITICAL state.

Usage: check_monit.py -H <host> [<options>]

Options:
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
  -i SVC_INCLUDE, --include=SVC_INCLUDE
                        Regular expression for service(s) to include into
                        monitoring
  -e SVC_EXCLUDE, --exclude=SVC_EXCLUDE
                        Regular expression for service(s) to exclude from
                        monitoring
  -d, --debug           Print all debugging info
  -v, --verbose         Verbose plugin response
  -M, --memory          Display memory performance data
  -C, --cpu             Display cpu performance data
  -L, --load            Display load average performance data

Nagios command definition looks like this:

define command{
        command_name    check_monit
        command_line    $USER1$/check_monit.py -H $HOSTADDRESS$ -p 1234 -s -u $USER3$ -P $USER4$
}


