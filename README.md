# check_vulns
Check for known vulns. Compare with installed packages.

This script will allow you to see which vulnerabilities are known for the packages you have installed on your system.

Even though you keep your system updated, a vulnerability in a package/service may be known and still not fixed. This is why you want to keep an eye out for the still not fixed vulnerabilities.

## Usage

    $ python3 check_vulns.py [-h] [-c {on,off}] [-d {on,off}] [-e {local,remote,all}] [-s {open,resolved,all}] [-u {on,off}]

    -c  Show CVE/DSAs {on/off} - default is 'on'
    -d  Show description of vulnerability {on/off} - default is 'off'
    -e  Show scope of exploitation {none/local/remote/all} - default is 'all'
    -s  Show status of vulnerability {none/open/resolved/all} - default is 'all'
    -u  Show urgency of fixing vulnerability {on/off} - default is 'on'

If c,d and u are set to 'off' and e,s are set to 'none', all output will consist of is package name and version.

Play with the different options to best suit your needs.


