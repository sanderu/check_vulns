#!/usr/bin/python3

# Download all known vulns from:
#   https://security-tracker.debian.org/tracker/data/json
# if not already downloaded.
#
# Get list of installed packages on the system (or from remote systems)
#
# Check if there is a known vulnerability present in installed packages
# and alert

from argparse import ArgumentParser as argsparsing
from configparser import ConfigParser as confparsing
from json import load as jsonload
from os import path as ospath
from re import search as research
from subprocess import getoutput as run_shell_cmd
from sys import exit as sysexit
from urllib import request as urlrequest

vulnpkgs = ""
config_filename = "check_vulns.conf"


def get_debian_tracker_file(local_file):
    """Get the json file from https://security-tracker.debian.org/tracker/data/json"""

    URL = "https://security-tracker.debian.org/tracker/data/json"

    if ospath.isfile(local_file):
        return

    with urlrequest.urlopen(URL) as response, open(local_file, "wb") as outfile:
        datain = response.read()
        outfile.write(datain)
    return


def read_debian_tracker_file(local_file):
    """Populate vulnpkgs variable with tracker file contents"""

    with open(local_file, "r") as jsonfile:
        return jsonload(jsonfile)


def get_os_packages_installed(host):
    """Get package names and versions from installed packages on local or remote system"""

    pkgdict = {}

    if host == "localhost":
        # localhost aka same machine this script is running on:
        res = run_shell_cmd(
            "/usr/bin/dpkg-query -W -f='${binary:Package}\t${Version}\n'"
        )
        os_version = run_shell_cmd("/bin/cat /etc/os-release | /bin/grep 'VERSION='")
    else:
        # remote host aka other machine than where this script is running:
        res = run_shell_cmd(
            "ssh {} ".format(host)
            + '"'
            + "/usr/bin/dpkg-query -W -f='\${binary:Package}\\t\${Version}\\n'"
            + '"'
        )
        os_version = run_shell_cmd(
            "ssh {} ".format(host)
            + '"'
            + "/bin/cat /etc/os-release | /bin/grep 'VERSION='"
            + '"'
        )
        try:
            check_ssh_result = research("(^ssh: Could not resolve hostname).*$", res)
            if check_ssh_result.group(1):
                print(
                    "Host in configfile: {} could not be contacted. Pls fix access and try again.".format(
                        host
                    )
                )
                sysexit(2)
        except:
            pass

    print("\n================\nHost: {}\n================".format(host))

    rel = research('\((\w+)\)"', os_version)
    os_release = rel.group(1)

    for elem in res.split("\n"):
        out = research("^(\S+)\t(\S+)$", elem)
        pkg = out.group(1)
        ver = out.group(2)
        pkgdict[pkg] = ver

    return os_release, pkgdict


def _compare_chunks(a, b):
    """Compare two chunks of version numbers; they can have . - and + separating strings"""
    a_chunks = a.split(".")
    b_chunks = b.split(".")
    a_chunks = [x.split("-") for x in a_chunks]
    b_chunks = [x.split("-") for x in b_chunks]
    a_chunks = [x for y in a_chunks for x in y]
    b_chunks = [x for y in b_chunks for x in y]
    a_chunks = [x.split("+") for x in a_chunks]
    b_chunks = [x.split("+") for x in b_chunks]
    a_chunks = [x for y in a_chunks for x in y]
    b_chunks = [x for y in b_chunks for x in y]

    # remove none values
    a_chunks = [x for x in a_chunks if x]
    b_chunks = [x for x in b_chunks if x]

    for a_chunk, b_chunk in zip(a_chunks, b_chunks):
        if a_chunk == b_chunk:
            continue
        if a_chunk > b_chunk:
            return 1
        else:
            return -1
    return 0


def version_greater_or_equal(version_a, version_b):
    """Return True if version_a is greater or equal than version_b, considering versions may are like 2.3.4:3.3-5+b2"""
    # split version_a and version_b into chunks
    a_chunks = version_a.split(":")
    b_chunks = version_b.split(":")
    a_chunks = [x.split("~") for x in a_chunks]
    b_chunks = [x.split("~") for x in b_chunks]
    a_chunks = [x for y in a_chunks for x in y]
    b_chunks = [x for y in b_chunks for x in y]
    for chunk_a, chunk_b in zip(a_chunks, b_chunks):
        _cmp = _compare_chunks(chunk_a, chunk_b)
        if _cmp == 0:
            continue
        if _cmp == 1:
            return True
        else:
            return False

    return True


def match_os_vs_known_vulns(vulnpkgs, pkgdict, os_release, args):
    """Match the OS packages against known vulns"""

    sec_os_release = os_release + "-security"
    local_or_remote = ""
    vuln_description = ""

    for vuln_pkg_name, values1 in vulnpkgs.items():
        packagevulns = vulnpkgs[vuln_pkg_name]
        if vuln_pkg_name in pkgdict:
            """If we're here, the package is installed on system being checked"""
            for vuln_pkg_cve, values2 in packagevulns.items():

                try:
                    os_release_dict = packagevulns[vuln_pkg_cve]["releases"][os_release]
                except KeyError:
                    continue

                try:
                    vuln_repository = os_release_dict["repositories"][sec_os_release]
                except:
                    vuln_repository = os_release_dict["repositories"][os_release]

                if version_greater_or_equal(pkgdict[vuln_pkg_name], vuln_repository):
                    continue

                vuln_urgency = os_release_dict["urgency"]

                try:
                    vuln_description = packagevulns[vuln_pkg_cve]["description"]
                except:
                    vuln_description = "no description"

                try:
                    local_or_remote = packagevulns[vuln_pkg_cve]["scope"]
                except KeyError:
                    local_or_remote = "not disclosed"

                # This is where changes need to be to reflect users wants/need regarding output
                outstring = "Package:   {} - Fixed in version:  {} ".format(
                    vuln_pkg_name, vuln_repository
                )

                # Add CVE/DSA to output according to CVE/DSA argument (on, off)
                if args.c == "on":
                    outstring += "- CVE/(NO)DSA: {} ".format(vuln_pkg_cve)

                # Add to output according to Status argument (open, resolved, all)
                if args.s == "all":
                    outstring += "- Status: {} ".format(os_release_dict["status"])
                elif args.s == "open":
                    if os_release_dict["status"] == "open":
                        outstring += "- Status: {} ".format(os_release_dict["status"])
                    else:
                        break
                elif args.s == "resolved":
                    if os_release_dict["status"] == "resolved":
                        outstring += "- Status: {} ".format(os_release_dict["status"])
                    else:
                        break

                # Add to output according to Scope argument (local, remote, all)
                if args.e == "all":
                    outstring += "- Scope: {} ".format(local_or_remote)
                elif args.e == "local":
                    if local_or_remote == "local":
                        outstring += "- Scope: {} ".format(local_or_remote)
                    else:
                        break
                elif args.e == "remote":
                    if local_or_remote == "remote":
                        outstring += "- Scope: {} ".format(local_or_remote)
                    else:
                        break

                # Add to output if Urgency argument is on (on, off)
                if args.u == "on":
                    outstring += "- Urgency: {} ".format(vuln_urgency)

                # Add to output if Description argument is on (on, off)
                if args.d == "on":
                    outstring += "- Description: {} ".format(vuln_description)

                # Add to notice about keeping an eye out for updates to vulnerable package
                if args.o == "on":
                    if pkgdict[vuln_pkg_name] != vuln_repository:
                        outstring += (
                            "\n--> You need to watch for upgrades for: {} <--\n".format(
                                vuln_pkg_name
                            )
                        )
                    else:
                        outstring = ""

                if outstring:
                    print(outstring)


def main(argv):
    """Main program here"""

    config = confparsing()
    config.read(config_filename)

    parser = argsparsing(
        description=r"Script to find vulns that are known, but not yet patched. This will give you an overview of which packages are part of the attack surface."
    )
    parser.add_argument(
        "-c",
        type=str,
        default="on",
        choices=["on", "off"],
        help="Show CVE/DSA identification number of vulnerability.",
    )
    parser.add_argument(
        "-d",
        type=str,
        default="off",
        choices=["on", "off"],
        help="Show description of vulnerability.",
    )
    parser.add_argument(
        "-e",
        type=str,
        default="all",
        choices=["none", "local", "remote", "all"],
        help="Show local and/or remote exploitable vulns.",
    )
    parser.add_argument(
        "-s",
        type=str,
        default="all",
        choices=["none", "open", "resolved", "all"],
        help="Show open and/or resolved vulns.",
    )
    parser.add_argument(
        "-u", type=str, default="on", choices=["on", "off"], help="Show the urgency."
    )
    parser.add_argument(
        "-o",
        type=str,
        default="on",
        choices=["on", "off"],
        help="Show only packages if there is a difference in version - not taking status into account.",
    )
    args = parser.parse_args()

    # Get variables from config-file
    local_filename = config["config"]["temp_file"]
    list_of_hosts = config["config"]["hosts"].split(" ")

    get_debian_tracker_file(local_filename)
    vulnpkgs = read_debian_tracker_file(local_filename)

    # Check host by host for known vulns against the different packages
    # installed on the different hosts.
    for host_by_host in list_of_hosts:
        os_release, pkgdict = get_os_packages_installed(host_by_host)
        match_os_vs_known_vulns(vulnpkgs, pkgdict, os_release, args)


if __name__ == "__main__":
    main("")
