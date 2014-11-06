#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Detecting the WireLurker malware family on Mac OS X."""


__copyright__    = 'Copyright (c) 2014, Palo Alto Networks, Inc.'
__author__       = 'Claud Xiao'
__version__      = '1.0.0'


import os
import sys
import platform
import plistlib
import subprocess


MALICIOUS_FILES = [
    '/Users/Shared/run.sh',
    '/Library/LaunchDaemons/com.apple.machook_damon.plist',
    '/Library/LaunchDaemons/com.apple.globalupdate.plist',
    '/usr/bin/globalupdate/usr/local/machook/',
    '/usr/bin/WatchProc',
    '/usr/bin/itunesupdate',
    '/Library/LaunchDaemons/com.apple.watchproc.plist',
    '/Library/LaunchDaemons/com.apple.itunesupdate.plist',
    '/System/Library/LaunchDaemons/com.apple.appstore.plughelper.plist',
    '/System/Library/LaunchDaemons/com.apple.MailServiceAgentHelper.plist',
    '/System/Library/LaunchDaemons/com.apple.systemkeychain-helper.plist',
    '/System/Library/LaunchDaemons/com.apple.periodic-dd-mm-yy.plist',
    '/usr/bin/com.apple.MailServiceAgentHelper',
    '/usr/bin/com.apple.appstore.PluginHelper',
    '/usr/bin/periodicdate',
    '/usr/bin/systemkeychain-helper',
    '/usr/bin/stty5.11.pl',
]

SUSPICIOUS_FILES = [
    '/etc/manpath.d/',
    '/usr/local/ipcc/'
]


def scan_files(paths):
    for f in paths:
        sys.stderr.write('.')
        if os.path.exists(f):
            yield f
    print

def is_file_hidden(f):
    if not os.path.exists(f) or not os.path.isfile(f):
        return False

    if sys.version_info[0] >= 2 and sys.version_info[2] >= 7 and sys.version_info >= 3:
        return os.stat(f).st_flags.UF_HIDDEN

    else:
        try:
            proc = subprocess.Popen("ls -ldO '%s' | awk '{print $5}'" % f, shell=True, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT)
            output = proc.stdout.read()
            proc.communicate()
            return output.find('hidden') != -1

        except Exception as e:
            return False


def is_app_infected(root):
    try:
        pl = plistlib.readPlist(os.path.join(root, 'Contents', 'Info.plist'))
        be = pl['CFBundleExecutable']
        bundle_exec = os.path.join(root, 'Contents', 'MacOS', be)
        bundle_exec_ = bundle_exec + '_'
        if is_file_hidden(bundle_exec) and is_file_hidden(bundle_exec_):
            return True

        the_script = os.path.join(root, 'Contents', 'Resources', 'start.sh')
        the_pack = os.path.join(root, 'Contents', 'Resources', 'FontMap1.cfg')
        if is_file_hidden(the_script) and is_file_hidden(the_pack):
            return True

        return False

    except Exception:
        return False

def find_apps():
    for root, __, __ in os.walk('/Applications', followlinks=True):
        if root.lower().endswith('.app'):
            yield root

    for root, __, __ in os.walk(os.path.expanduser('~Applications'), followlinks=True):
        if root.lower().endswith('.app'):
            yield root

def scan_app():
    for root in find_apps():
        sys.stderr.write('.')
        if is_app_infected(root):
            yield root
    print

def main():
    print 'WireLurker Detector (version %s)' % __version__
    print __copyright__
    print ''

    if platform.system() != 'Darwin':
        print 'ERROR: The script should only be run in a Mac OS X system.'
        sys.exit(-1)

    print '[+] Scanning for known malicious files'
    for f in scan_files(MALICIOUS_FILES):
        mal_files = True
        print
        print '[!] Found malicious file: %s' % f
    else:
        mal_files = False
        print '[-] Nothing is found.'

    print '[+] Scanning for known suspicious files'
    for f in scan_files(SUSPICIOUS_FILES):
        sus_files = True
        print
        print '[!] Found suspicious file: %s' % f
    else:
        sus_files = False
        print '[-] Nothing is found.'

    print '[+] Scanning for infected applications (may take minutes)'
    for a in scan_app():
        infected_apps = True
        print
        print '[!] Found infected application: %s' % a
    else:
        infected_apps = False
        print '[-] Nothing is found.'

    if mal_files or sus_files or infected_apps:
        print "[!] WARNING: Your OS X system is highly suspicious of being infected by the WireLurker.\n" \
              "[!] You may need to delete all malicious or suspicious files and/or applications above.\n" \
              "[!] For more information about the WireLurker, please refer: \n"\
              "[!] http://researchcenter.paloaltonetworks.com/2014/11/wirelurker-new-era-os-x-ios-malware/"
        return 1
    else:
        print "[+] Your OS X system isn't infected by the WireLurker. Thank you!"
        return 0


if __name__ == '__main__':
    main()
