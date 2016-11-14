'''
Base template for creating scripts to interact with an LDAP server.
'''

# BEGIN PREFAB SETUP 

import sys
import logging
import argparse
import logging.handlers

from getpass import getpass

import wrapldap

# Set up logger, Log Level determined by --debug flag.
logger = logging.getLogger('template')
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(funcName)s: %(message)s')

# Syslog Logging Setup
syslog = logging.handlers.SysLogHandler(address = '/dev/log')
syslog.setLevel(logging.INFO)
syslog.setFormatter(formatter)
logger.addHandler(syslog)


def main():
    parser = argparse.ArgumentParser()  
    parser.add_argument('-v', '--version', action='version',
        version = '%(prog)s 0.9.3') 
    parser.add_argument('--debug', action='store_true',
        help='Display debug messages')
    parser.add_argument('--ldap-server', nargs=1, type=str, required=True, 
        help='Required. LDAP server to connect to.')
    parser.add_argument('--ldap-user', nargs='?', type=str,  
        default='admin', help='LDAP user you wish to connect as')
    parser.add_argument('--ssl', action='store_true', 
        help='Use SSL to connect to servers')
    parser.add_argument('--unattended', nargs=1, type=str,
        help='Specify a password file. Only useful for cronjobs on systems '
        'with limited access.')
    parser.add_argument('-q', '--quiet', action='store_true', 
        help='Suppress messages/logging to STDOUT')    
    args = parser.parse_args()
    if args.quiet:
        logger.debug('Quiet mode set, no STDOUT logging')
    else:
        # STDOUT Logging Setup
        logger.debug('No quiet flag set, creating STDOUT logger')
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        logger.addHandler(console)
        logger.debug('STDOUT logging created')
        if args.debug:
            console.setLevel(logging.DEBUG)
    if args.debug:
        logger.setLevel(logging.DEBUG)
        syslog.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    if args.unattended:
        with open('{}'.format(args.unattended[0]), 'r') as auth:
            auth = auth.read().strip('\n')
    else:
        auth = getpass('LDAP password for "{}": '.format(args.ldap_user))
    # Connect to LDAP 
    if args.ssl:
        wrap = wrapldap.WLDAP(args.ldap_server[0],args.ldap_user, auth, 'example.com', parent_log=logger.__dict__['name'])
        wrap.auth()
    else:
        wrap = wrapldap.WLDAP(args.ldap_server[0],args.ldap_user, auth, 'example.com', parent_log=logger.__dict__['name'], ssl=False)
        wrap.auth()
    # END SETUP, START CODING ON NEXT LINE

    # Leave at the end of script
    wrap.disconnect()

if __name__ == '__main__':
    main()