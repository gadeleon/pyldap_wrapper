# -*- coding: utf-8 -*-'

'''
Some python-ldap commands abstracted and turned into functions
'''

import sys
import logging
import argparse
import logging.handlers

from urllib import quote
from getpass import getpass

import ldap
import ldap.modlist as modlist

# Set up logger

logger = logging.getLogger('template.wrapldap')



class WLDAP(object):
    def __init__(self, server, user, passwd, domain='example.com',library=True, parent_log='unnamed_logger', ssl=True):
        '''
        Wrapper for working with ldap.ldapobject.SimpleLDAPObject
        If not using as a library (ie running python wrapldap.py) make sure you
        instantiate the WLDAP object with library=False to receive logging.
        Ex: 
            if __name__ == '__main__':
                wrap = wrapldap.WLDAP('localhost', 'confluence', 'secret', 
                library=False, parent_log=logger.__dict__['name'])
        '''
        self.library = library
        if self.library:
            self.parent_log = parent_log
            self.logger = logging.getLogger('{}.wrapldap.WLDAP'.format(self.parent_log))           
        else:
            self.logger = logging.getLogger('wrapdap.WLDAP')
        self.logger.debug('Intantating WLDAP Class')        
        self.domain = domain
        self.ssl = ssl
        if self.ssl:
            self.logger.debug('SSL option detected, setting SSL')
            ldap.set_option( ldap.OPT_X_TLS_CACERTFILE, 
                '/etc/ssl/certs/ca-certificates.crt')
            self.uri = 'ldaps'
        else:
            self.logger.debug('No SSL option detected, connections are insecure')
            self.uri = 'ldap'

        self.dc = self._form_dc()
        self.server = server
        self.user = user 
        self.passwd = passwd
        # Attempt to auth as root of the domain, if it fails, we switch to 
        # LDAP root. once again, will use getpass() in prod
        self.ldapobject = ldap.initialize('{}://{}'.format(self.uri, self.server))
        self.ldapobject.protocol_version = ldap.VERSION3    


    def _form_dc(self, top_domain=''):
        if top_domain:
            dc = top_domain
        else:
            dc = self.domain
        dc = dc.split('.')
        dc = 'dc={},dc={}'.format(dc[0],dc[1])
        self.logger.debug('dc "{}" formed from {}'.format(dc, self.domain))
        return dc


    def _form_dn(self, cn='', ou='', dc='' ):
        # Handle exception for special characters, LDAP uses same value as 
        # URL Encoding, so we'll do the same
        special_characters = [' ', ',', '+', '#', '<', '>', ';', '"', '=']
        for c in special_characters:
            if c in cn:
                cutup = cn.split(c)
                cn = '{}{}{}'.format(cutup[0],'-',cutup[1])
        if dc:
            dc = 'dc={}'.format(dc)
        else:
            dc = self.dc
        if ou:
            dn = 'ou={},{}'.format(ou, dc)
            if cn:
                dn = 'cn={},{}'.format(cn,dn)
        elif cn:
            dn = 'cn={},{}'.format(cn,dc)
        else:
            dn = self.dc
        self.logger.debug('dn "{}" formed'.format(dn))
        return dn


    def auth(self, cn='',dc='', passwd=''):
        '''
        Returns a binded ldap object (extending an ldapobject may be a better
        alternative for v2 which has been initialized/authenticated allowing you
        use it to do things with ldap. Remember to run this first if you want to 
        use any other methods in this class!    
        '''
        dn = self._form_dn(cn='admin', dc=dc)
        self.logger.debug('Starting auth as "{}"'.format(dn))
        if not passwd:
            passwd = self.passwd
        self.ldapobject = ldap.initialize('{}://{}'.format(self.uri, self.server))
        try:
            self.ldapobject.simple_bind_s(dn,passwd)
            self.logger.debug('Bound to LDAP server: {} as "{}"'.format(self.server,
                dn))
            return self.ldapobject
        except ldap.INVALID_CREDENTIALS as e:
            msg = 'Login falied; invalid credentials: {}'.format(e)
            sys.stderr.write(msg+'\n')
            self.logger.error(msg)
            sys.exit(2)
        except ldap.LDAPError as e:
            msg = 'Error: There is no valid LDAP connection to server: {}. Check if the connection was initialized properly: {}'\
            .format(self.server, e)
            sys.stderr.write(msg+'\n')
            self.logger.error(msg)
            sys.exit(3)


    def disconnect(self):
        '''
        Unbinds from the ldap server. Remember to run this when you are done.
        '''
        try:
            self.ldapobject.unbind_s()
            self.logger.debug('Unbound from LDAP server: {}'.format(self.server))
        except AttributeError as e:
            msg = 'Error: Unable to disconnect from object {}. variable must'\
                ' be an LDAPObject'.format(str(self.ldapobject))
            sys.stderr.write(msg+'\n')
            self.logger.error(msg)


    def search_cn(self, cn, ou=''):
        '''
        Successful searches return a tuple of a search for cn in a domain 
        (optional: ou can be specified for more specific searches).  

        Unsuccessful searches (ie. no results) returns False
        
        Most cn's will be an email from ou=accounts or a groupName from 
        ou=groups. 
        
        ldap_search syntax: 
            basedn = where you start,
            ldap.SCOPE_SUBTREE = scope, can be SCOPE_[BASE, ONELEVEL, or SUBTREE]
                BASE - just query the basedn
                ONELEVEL - Look one level below the DN
                SUBTREE -- all the things of the basedn
            query = what you are looking for
            additional filter = pick the attribute you want to display (cn, ou, etc)
        '''
        basedn = self._form_dn(ou=ou)
        query = '(cn={})'.format(cn)
        self.logger.debug('Searching "{}" for {}'.format(basedn, query))
        r = self.ldapobject.search_s(basedn,ldap.SCOPE_SUBTREE,query)
        # Empty results have a comma in the tuple's output so python feels it's 
        # not empty and therefore true. 
        # This try block verifies if there's actually data inside        
        try:
            r[0][0]
            self.logger.debug('Success! Search yielded results')
            return r
        except IndexError:
            self.logger.debug('Empty! No results in search')
            return False        

    def is_search_cn_empty(self, search):
        '''
        Empty results have a comma in the tuple output so python feels it's 
        true. This try block verifies if there's actually data inside

        NOTE: This funcitionality was moved to search_cn. This method is 
        approaching deprecation but will remain for now.
        '''
        try:
            search[0][0]
            self.logger.debug('Success! Previous search yielded results')
            return True
        except IndexError:
            self.logger.debug('Empty! No results in previous search')
            return False

    def delete_cn(self, ou,cn):
        '''
        Deletes cn=foo,ou=baz,dc=domain,dc=com
        '''
        # Delete doesn't say anything regardless of whether the target exists or
        # not. It will delete nothing and say everything succeeded.         
        dn = self._form_dn(ou=ou,cn=cn)
        try:
            self.ldapobject.delete_s(dn)
        except ldap.NO_SUCH_OBJECT:
            msg = 'Error: could not find "{}" to delete'.format(dn)
            sys.stderr.write(msg+'\n')
            self.logger.error(msg)
            sys.exit(7)
        if self.search_cn(cn, ou=ou):
            msg = 'Error: "{}" not found. Deletion unsuccessful'.format(dn)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(9)
        else:
            self.logger.debug('"{}" successfully deleted'.format(dn))

    def delete_ou(self, ou):
        '''
        Deletes ou=foo,dc=domain,dc=com
        '''
        dn = self._form_dn(ou=ou)
        try:
            self.ldapobject.delete_s(dn)
        except ldap.NO_SUCH_OBJECT:
            msg = 'Error: could not find "{}" to delete'.format(dn)
            sys.stderr.write(msg+'\n')
            self.logger.error(msg)
            sys.exit(7)
        self.logger.debug('{} most likely deleted. Please verify'.format(dn))

    def add_top_domain(self, description=''):
        '''
        Create a top level domain object for LDAP database after the database has
        been created.

        The organization domain (ex: example.com), uses self.domain which
            can be specified during WLDAP instantiation
        '''
        # The only way to add a toplevel domain is by authing as LDAP's Root
        # We always unbind our current session and login as the default admin.
        try:
            self.logger.debug('Creating new top level domain object...')
        except ldap.LDAPError:
            self.logger.debug('There was no valid connection. Continuing...')
        dn = self._form_dc()
        if description:
            description = description
        else:
            description = raw_input('Enter description for top domain object: ')
        # Create dn based on details from domain    
        #   Form dict for modlist to parse for ldap
        attrs = {}
        attrs['objectclass'] = ['top','dcobject','organization']
        attrs['dc'] = self.domain.split('.')[0]
        attrs['o'] = self.domain
        attrs['description'] = description
        self.logger.debug(attrs)
        # Format into input for ldap server
        ldif = modlist.addModlist(attrs)
        self.ldapobject.add_s(dn, ldif)
        self.logger.debug('Success! Created top domain object with {}'\
            .format(attrs))
        self.logger.info('Created Top Level Ldap object: "{}"'.format(dn))

    def add_ou(self, ou, description=''):
        '''
        Create an organizational unit node underneath the domain object

        ou - name of the ou you wish to create
        '''
        dn = self._form_dn(ou=ou)
        # Form dict for modlist to parse for ldap
        if description:
            description = description
        else:
            description = raw_input('Enter description for organizationalunit object: ')
        attrs = {}
        attrs['objectclass'] = ['organizationalunit']
        attrs['ou'] = ou
        attrs['description'] = description
        # Format into input for ldap server
        self.logger.debug('Preparing the following to be added to LDAP in {}, {}'\
            .format(dn,attrs))
        ldif = modlist.addModlist(attrs)
        # Now we talk to the database
        try:
            self.ldapobject.add_s(dn, ldif)
            self.logger.debug('Success! Created organizationalunit object')
        except ldap.ALREADY_EXISTS:
            msg = 'Error: "{}" already exists.'.format(dn)
            sys.stderr.write(msg+'\n')
            self.logger.error(msg)
            sys.exit(8)

    def add_ugroup_cn(self, ou, group_name, description=''):
        '''
        Adds group to ldap database as part of ou specified as a 
        groupofuniquenames
        '''
        dn = self._form_dn(ou=ou, cn=group_name)
        if description:
            description = description
        else:
            description = raw_input('Input description for groupofuniquenames object "{}": '\
            .format(group_name))
        attrs={}
        attrs['objectclass'] = 'groupofuniquenames'
        attrs['uniquemember'] = ['']
        attrs['cn'] = group_name
        attrs['description'] = description
        self.logger.debug('Preparing the following to be added to LDAP in {}, {}'\
            .format(dn,attrs))
        ldif = modlist.addModlist(attrs)
        self.logger.debug('Checking if "{}" successfully added'.format(dn))
        try:
            self.ldapobject.add_s(dn, ldif)
        except ldap.ALREADY_EXISTS:
            msg = '"{}" already exists.'.format(dn)
            sys.stderr.write(msg+'\n')
            self.logger.warn(msg)
        # Verify group added
        if self.search_cn(group_name, ou=ou):
            self.logger.info('Success! Created groupofuniquenames object "{}"'\
                .format(dn))
        else:
            msg = 'Error: {} not found. Creation unsuccessful'.format(dn)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(8)

    def add_account_cn(self, ou, email, full_name, hashed_passwd):
        '''
        Adds a user/account to ldapdatabase as part ou specified as a 
        inetorgperson and simplesecurityobject. Email serves as cn.
        '''       
        dn = self._form_dn(ou=ou, cn=email)
        attrs = {}
        attrs['objectclass'] = ['inetorgperson', 'simplesecurityobject']
        attrs['cn'] = email
        attrs['displayName'] = full_name
        attrs['mail'] = email
        # Attempt to parse name into first/last
        try:
            self.logger.debug('Attempting to split full name "{}" into first/last'\
                .format(full_name))
            first, last = full_name.split(' ')
        except ValueError:
            if len(full_name.split(' ')) > 2:
                self.logger.debug('"{}" has more than two names, reparsing'\
                    .format(full_name))
                first = full_name.split(' ')[0]
                last = full_name.split(' ')[-1]
                self.logger.debug('Grabbed "{}" as first name, "{}" as last.'\
                    .format(first, last))
            else:
                self.logger.warn('Could not parse full name "{}", inserting "{}" as surname'\
                    .format(full_name, email))
                first = ''
                last = email
            if full_name == '':
                attrs['displayName'] = email
        attrs['givenName'] = first
        attrs['sn'] = last
        if hashed_passwd == None:
            self.logger.warn('Ldap user {} has no password set. User will NOT be added to ldap.'\
                .format(dn))
            return False
        else: 
            attrs['userPassword'] = hashed_passwd
        self.logger.debug('Preparing the following to be added to LDAP in {}, {}'\
            .format(dn,attrs))
        ldif = modlist.addModlist(attrs)
        try:
            self.ldapobject.add_s(dn, ldif)
            self.logger.debug('Success! Created account "{}"'.format(dn))
        except ldap.ALREADY_EXISTS:
            msg = 'Error: Account "{}" already exists.'.format(dn)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(4)
        if self.search_cn(email, ou=ou):
            self.logger.info('Success! Created account "{}"'.format(dn))
        else:
            msg = 'Error: {} not found. Creation unsuccessful'.format(dn)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(8)
        # Update password to SSHA now that it has been added:
        if not hashed_passwd.startswith('{SSHA}'):
            self.update_account_cn_password(email, hashed_passwd, user_ou=ou)
            self.logger.debug('Changed password for {} to {} variant'.format(email, '{SSHA}'))

    def get_users_from_accounts(self, group_ou='accounts'):
        '''
        Returns a list of the cns (inetorgperson) from the group_ou 
        organizationalunit
        '''
        basedn = self._form_dn(ou=group_ou)
        query = '(&(objectclass=inetorgperson)(cn=*))'
        r = self.ldapobject.search_s(basedn, ldap.SCOPE_SUBTREE, query, ['cn'])
        out = []
        for i in r:
            out.append(i[1]['cn'][0])
        return out


    def get_names_of_ugroups(self, group_ou='groups'):
        '''
        Returns a list of the cns (groupofuniquenames) from the group_ou 
        organizationalunit.
        '''
        basedn = self._form_dn(ou=group_ou)
        query = '(&(objectclass=groupofuniquenames)(cn=*))'
        r = self.ldapobject.search_s(basedn, ldap.SCOPE_SUBTREE, query, ['cn'])
        out = []
        for i in r:
            out.append(i[1]['cn'][0])
        return out


    def get_members_of_ugroup(self, group_name, group_ou='groups'):
        '''
        Returns a list of the cns (in this case uniquemembers) from a 
        groupofuniquenames.
        '''
        basedn = self._form_dn(ou=group_ou)
        query = '(&(objectclass=groupofuniquenames)(cn={}*))'.format(group_name)
        r = self.ldapobject.search_s(basedn,ldap.SCOPE_SUBTREE,query, ['uniquemember'])
        if r[0][1]['uniqueMember'] == ['']:
            self.logger.debug('No results found in group "{}"" under ou "{}"'\
                .format(group_name, group_ou))
            return []
        else:
            self.logger.debug('Results found in group "{}" under ou "{}"'\
                .format(group_name, group_ou))
            return r[0][1]['uniqueMember']

    def get_groups_member_belongs_to(self, email, user_ou='accounts'):
        '''
        Returns a list of stuff showing what groups a user account belings to.
        '''
        basedn = self.dc
        user_cn = self._form_dn(cn=email,ou=user_ou)
        query = '(&(objectclass=groupofuniquenames)(uniquemember={}))'\
            .format(user_cn)
        r = self.ldapobject.search_s(basedn, ldap.SCOPE_SUBTREE, query, ['cn'])
        out = []
        for i in r:
            out.append(i[1]['cn'][0])
        return out


    def get_user_password_from_account(self, email, user_ou='accounts'):
        '''
        Returns the SSHA hash of a user. 
        '''
        basedn = self._form_dn(ou=user_ou)
        #user_cn = self._form_dn(ou=user_ou, cn=email)
        query = '(cn={})'.format(email)
        r = self.ldapobject.search_s(basedn, ldap.SCOPE_SUBTREE, query, ['userpassword'])
        return r[0][1]['userPassword'][0]


    def get_user_attribute_from_account(self, email, attr, user_ou='accounts'):
        '''
        Returns the attribute attr of a user
        '''
        basedn = self._form_dn(ou=user_ou)
        query = '(cn={})'.format(email)
        r = self.ldapobject.search_s(basedn, ldap.SCOPE_SUBTREE, query, [attr])
        try:
            self.logger.debug('Located "{}"'.format(r[0][1][attr][0]))
            return r[0][1][attr][0]
        except KeyError:
            self.logger.warn('Warning: "{}" is not a valid attribute for {},' 
                ' returning empty string'.format(attr, email))
            return ''
        except IndexError:
            msg = 'Error: "{}" does not appear to be a valid email address.'\
                .format(email)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(12)


    def _1_is_account_in_ugroup(self, group_list, email, user_ou='accounts'):
        '''
        Returns True if user (eg. cn=foo,ou=baz-accounts,dc=example,dc=com) is a 
        member of the specificed group_name retrieved from get_members_of_ugroup. 
        Returns False if the query turns up empty.
        '''
        entry = self._form_dn(cn=email, ou=user_ou)
        if entry in group_list:
            self.logger.debug('{} found in group list'.format(entry))
            return True
        else:
            self.logger.debug('{} is not in group list'.format(entry))
            return False


    def _2_is_account_in_ugroup(self, group_name, email, user_ou='accounts', group_ou='groups'):
        '''
        This bool actually makes the query against the group you specify and 
        then returns True or False
        '''
        members = self.get_members_of_ugroup(group_name, group_ou=group_ou)
        entry = self._form_dn(cn=email, ou=user_ou)
        if entry in members:
            self.logger.debug('{} found in group list'.format(entry))
            return True
        else:
            self.logger.debug('{} is not in group list'.format(entry))
            return False


    def add_account_to_ugroup(self, group_name, email, user_ou='accounts', group_ou='groups'):
        '''
        Adds a user to a gnoupOfUniqueNames as a uniqueMember (eg. 
        cn=foo,ou=baz-accounts,dc=example,dc=com)

        Python-ldap is not the smartest when it comes to updating attributes. It
        effectively replaces the old attribute with what you specify so we have
        to pull the full list, make our changes, and then push it to the server.     

        ## V2: Make an 'add batch users'
        '''
        dn = self._form_dn(ou=group_ou, cn=group_name)
        old_members = self.get_members_of_ugroup(group_name, group_ou=group_ou)
        old_entry = {'uniquemember':old_members}
        new_cn = self._form_dn(ou=user_ou, cn=email)
        self.logger.debug('Adding "{}" to groupofuniquenames "{}"'.format(new_cn,
            group_name))
        new_members = list(old_members) + [new_cn]
        new_entry = {'uniquemember':new_members}
        ldif = modlist.modifyModlist(old_entry, new_entry)
        try:
            self.ldapobject.modify_s(dn,ldif)
        except ldap.TYPE_OR_VALUE_EXISTS:
            msg = 'Error: "{}" already exists in "{}"'.format(new_cn, dn)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(6)
        # Verify if addition Successful
        self.logger.debug('Testing if addition successful')
        if self._2_is_account_in_ugroup(group_name, email, group_ou=group_ou, user_ou=user_ou):
            self.logger.info('Addition succeeded, "{}" found in group "{}"'\
                .format(new_cn, dn))
        else:
            self.logger.info('Addition failed, "{}" not found in group "{}"'\
                .format(new_cn, dn))
            sys.exit(10)


    def delete_account_from_ugroup(self, group_name, email, user_ou='accounts', group_ou='groups'):
        '''
        Deltes a uniqueMember from a gnoupOfUniqueNames (eg. 
        cn=foo,ou=baz-accounts,dc=example,dc=com). 

        Nearly identical to self.add_account_to_ugroup except for one key difference. 
        '''
        dn = self._form_dn(ou=group_ou, cn=group_name)
        old_members = self.get_members_of_ugroup(group_name, group_ou=group_ou)
        old_entry = {'uniquemember':old_members}
        new_members = self._form_dn(ou=user_ou, cn=email)
        self.logger.debug('Deleting "{}" from groupofuniquenames "{}"'.format(new_members,
            group_name))
        target_cn = self._form_dn(cn=email, ou=user_ou)
        new_members = list(old_members)
        try:
            new_members.remove(target_cn)
        except ValueError:
            msg = 'Error: "{}" not found in group entries. Qutting.'.format(target_cn)
            self.logger.error(msg)
            sys.stderr.write(msg+'\n')
            sys.exit(5)
        new_entry = {'uniquemember':new_members}
        ldif = modlist.modifyModlist(old_entry, new_entry)
        self.ldapobject.modify_s(dn,ldif)
        # Verify if deletion Successful
        self.logger.debug('Testing if deletion successful')
        if self._2_is_account_in_ugroup(group_name, email, group_ou=group_ou, user_ou=user_ou):
            self.logger.info('Deletion failed, "{}" found in group "{}"'\
                .format(target_cn, dn))
        else:
            self.logger.info('Deletion succeeded, "{}" removed from group "{}"'\
                .format(target_cn, dn))

    def rename_account_rdn(self, email, new_email, user_ou='accounts'):
        dn = self._form_dn(ou=user_ou, cn=email)
        new_cn = 'cn={}'.format(new_email)
        # We want to delete the old CN upon modifying the RDN so we set True
        self.ldapobject.modrdn_s(dn,new_email, True)


    def update_account_cn_password(self, email, new_pass, user_ou='accounts'):
        '''
        Changes a cn's password attribute, does the SSHA for you.
        '''
        dn = self._form_dn(ou=user_ou, cn=email)
        # We use None as the old password since openldap doesn't verify
        # Old passwords.
        ## TODO: Wrap in Try/Catch block to see if old password needed.
        self.ldapobject.passwd_s(dn, None, new_pass)
        self.logger.debug('Updated password entry for account "{}"'\
            .format(email))


    def replace_account_cn_password(self, email, secret, user_ou='accounts'):
        '''
        Unlike update_account_cn_password, "replace" will directly modify 
        the userPassword attribute of a user without making a SSHA unless
        created by the user
        '''
        dn = self._form_dn(ou=user_ou, cn=email)
        old_passwd = self.get_user_password_from_account(email, user_ou)
        old_entry = {'userPassword':old_passwd}
        new_entry = {'userPassword':secret}
        ldif = modlist.modifyModlist(old_entry, new_entry)
        self.ldapobject.modify_s(dn, ldif)
        self.logger.debug('Replaced password entry for account "{}"'\
            .format(email))


    def add_account_attribute(self, email, attr, value, user_ou='accounts'):
        '''
        Adds an attribute for the specificed user, if value is empty, default
        to email
        '''
        if value == '':
            value = email
        dn = self._form_dn(ou=user_ou, cn=email)
        self.logger.debug('Adding {}:{} to {}'.format(attr, value, dn))        
        mod_attrs = [(ldap.MOD_ADD, attr, value)]
        self.ldapobject.modify_s(dn, mod_attrs)
        self.logger.info('Added {}:{} to {}'.format(attr, value, dn))


    def replace_account_attribute(self, email, attr, value, user_ou='accounts'):
        '''
        Replaces the attribute of the specified user.
        '''
        self.logger.debug('Replacing value of "{}"'.format(attr))
        dn = self._form_dn(ou=user_ou, cn=email)
        self.logger.debug('Retrieving old value of "{}"'.format(attr))
        old_entry = self.get_user_attribute_from_account(email, attr)
        self.logger.debug('Retrieved "{}" from "{}"'.format(old_entry, attr))
        old_entry = {attr:old_entry}
        self.logger.debug('Formed old entry "{}"'.format(old_entry))
        new_entry = {attr:value}
        ldif = modlist.modifyModlist(old_entry, new_entry)
        self.ldapobject.modify_s(dn, ldif)
        self.logger.debug('Replaced "{}" value, "{}", with "{}" '\
            .format(attr, old_entry[attr], value))


if __name__ == '__main__':
    # If not using as a library, build logger:
    # Set up logger, Log Level determined by --debug flag.
    logger = logging.getLogger('wrapldap')
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(funcName)s: %(message)s')
    # Syslog Logging Setup
    syslog = logging.handlers.SysLogHandler(address = '/dev/log')
    syslog.setLevel(logging.INFO)
    syslog.setFormatter(formatter)
    logger.addHandler(syslog)
    # STDOUT Logging Setup
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logger.addHandler(console)
    # Set up Option Arguments for debug
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version',
        version = '%(prog)s 0.9.3')
    parser.add_argument('--debug', action='store_true',
        help='Display debug messages')
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        console.setLevel(logging.DEBUG)
        syslog.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)   
    # Connect and disconnect
    from getpass import getpass
    wrap = WLDAP('localhost','admin', getpass('Enter LDAP admin password: '), 
        library=False)
    wrap.auth()
    wrap.disconnect()
