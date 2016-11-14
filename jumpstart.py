# -*- coding: utf-8 -*-'

'''
Script to kick start the ldap server for Example.com. This script will *NOT* do the following
1) Install LDAP 
2) Eneable Member Overlay
3) Create the database
4) Create admin credentials

Use ldapscripts to achieve those above.

This script *WILL* do the following

1) Create the Example.com domain
2) Create the Organizational Units "accounts" and "groups"
'''


import sys
import logging
import argparse
import logging.handlers

from getpass import getpass

import ldap

import wrapldap

# Set up logger

logger = logging.getLogger('jumpstart')
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(funcName)s: %(message)s')

# Syslog Logging Setup
syslog = logging.handlers.SysLogHandler(address = '/dev/log')
syslog.setLevel(logging.INFO)
syslog.setFormatter(formatter)
logger.addHandler(syslog)


def main():
    parser = argparse.ArgumentParser()  
    parser.add_argument('-v', '--version', action='version',
        version = '%(prog)s 0.9.0') 
    parser.add_argument('--debug', action='store_true',
        help='Display debug messages')
    parser.add_argument('--ldap-server', nargs=1, type=str, required=True, 
        help='Required. LDAP server to connect to.')
    parser.add_argument('--ldap-user', nargs='?', type=str,  
        default='admin', help='LDAP user you wish to connect as')
    parser.add_argument('--db-server', nargs=1, type=str, required=True, 
        help='Required. Database server you wish to connect to for source information.')
    parser.add_argument('--db-user', nargs='?', type=str, default='ldap_syncer', 
        help='Datbase user you wish to connect as.')
    parser.add_argument('--ssl', action='store_true', 
        help='Use SSL to connect to servers')
    parser.add_argument('--unattended', action='store_true', 
        help='Tell command to run without user input')
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
    # Try & connect to LDAP before doing anything. 
    if args.ssl:
        wrap = wrapldap.WLDAP(args.ldap_server[0],args.ldap_user, auth, 'example.com', parent_log=logger.__dict__['name'])
        wrap.auth()
    else:
        wrap = wrapldap.WLDAP(args.ldap_server[0],args.ldap_user, auth, 'example.com', parent_log=logger.__dict__['name'], ssl=False)
        wrap.auth()
    try:
        wrap.add_top_domain(description='Example.com network')
    except ldap.ALREADY_EXISTS:
        logger.info('dc=example,dc=com already exists. Skipping dc creation.')
    # Now we create the orginizational units 'accounts' and 'groups'
    wrap.add_ou('groups', description='Org unit for groups')
    wrap.add_ou('accounts', description='Org unit for accounts')
    # Always disconnect at the end
    wrap.disconnect()
    print '\nJumpstart complete!\n'

if __name__ == '__main__':
    main()
