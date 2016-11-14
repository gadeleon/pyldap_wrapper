# Guide to Setup LDAP Server from start to finish.

##  Building the LDAP server

### Before Installaing

When you install slapd for the first time, ubuntu will create a default database with the dn `dc=nodomain` and ask you to create the password for `cn=admin,dc=nodomain`. It's dynamic slapd address will be `olcDatabase={1}`. You can change the dn/dc via `sudo dpkg-reconfigure` which is detailed below.


```
sudo apt-get update && sudo apt-get upgrade
# Make note of password you create for 'admin'
sudo apt-get install slapd
```

`example.db.ldif` creates a `dc=example,dc=com` database that does _not_ permit anonymous authentications. It's meant to be used as a backup in case the default database included with slapd is already in use. The `olcDatabase={<NUM>}` will vary depending on how many databases already exist.

### Install Dependencies

#### Update Server

`sudo apt-get update && sudo apt-get upgrade`

#### Get packages
Install the following packages via apt
```
sudo apt-get install ldapscripts python-dev libsasl2-dev libldap2-dev libssl-dev python-pip python-setuptools python-ldap
```

### Reconfigure or Create Database

#### Reconfiguring the Default Database

If you wish to you use the default database, then you need to use `sudo dpkg-reconfigure slapd` to get it ready for your data.

```
sudo dpkg-reconfigure slapd 
# Follow the prompts (the defaults are correct) until you reach "domain"
# and adjust it to "example.com" and change "organization" to "example"
```
#### Creating a Database

If you want to add a new database to the ldap installation, follow these instructions.


As mentioned above, `example.db.ldif` has all the parameters set to create the database. It just needs to be tweaked slightly before adding it to the ldap server.

We'll be creating a database with the domain `dc=example,dc=com` and the admin
dn will be `cn=admin,dc=example,dc=com`. We'll need to create the password for this admin account first. 

```
# Use slappasswd to generate a password hash for the LDAP admin
`slappasswd -s`. 
# You will prompted to enter the password you want twice. Copy the entire output
# including "{SSHA}".
vim example.db.ldif 
# Paste the output into variable `olcRootPW`. 
# Save and then create the database.
sudo ldapadd -Y EXTERNAL -H ldapi:/// -f example.db.ldif
````


### (Optional) Enable memberOf overlay

Once you have a database ready, you need to enable the memberOf overlay _BEFORE_ populating it with data! This will make it so LDAP updates users with the `memberOf` attribute whenever you add them to a group as a `uniqueMember`. 

The two files included, `memberof_config.ldif` and `refint.ldif`, will enable the overlay; however, they need to point to the correct `olcDatabase={<NUM>}`. 

#### Determine which `olcDatabase={<NUM>}`

If you are using the default slapd database, the value will always be `olcDatabase={1}`. If you obtained these ldif files from this repo, you should be set and can skip to setting the overlays as the ldif files are configured for the default database. If you wish to be thorough, you can follow the next few steps to make sure!

If you added `dc=example,dc=com` as second, third, fourth, etc. database, then you will need to determine which number to use for the two ldif files. 

```
sudo slapcat -n0 | less
# Push "/" on your keyboard to enter the search prompt and type "dc=example"
# You are looking for the line "olcSuffix: dc=example,dc=com"
# Once found, scroll up until you see the line "dn: olcDatabase={<NUM>}hdb,cn=config"
# Write down/copy the number
vim memberof_config.ldif
# Locate the line "dn: olcOverlay={0}memberof,olcDatabase={1}hdb,cn=config" 
# and change "olcDatabase={1}hdb" to the correct number.
vim refint.ldif
# Locate the line "dn: olcOverlay={1}refint,olcDatabase={1}hdb,cn=config" 
# and change "olcDatabase={1}hdb" to the correct number.
```

#### Setting the memberof overlay

Once you've pointed the ldif files to the correct database, simply add them via `ldapadd`

```
sudo ldapadd -Q -Y EXTERNAL -H ldapi:/// -f memberof_config.ldif
sudo ldapadd -Q -Y EXTERNAL -H ldapi:/// -f refint.ldif
```

### Using SSL

If you plan on using SSL for ldap sync (which is extremely likely), you'll need to modify a few variables in `wrapldap.py`.


To get SSL working for ldap communications, tweak the method `ldap.set_option( ldap.OPT_X_TLS_CACERTFILE, '/etc/ssl/certs/ca-certificates.crt')` and change the string `/etc/ssl/certs/ca-certificates.crt` to the appropriate directory.


### Install pyldap_wrapper

The `setup.py` script will install the pyldap_wrapper which can then be used later as a library for further scripts.

`sudo python setup.py install`

### First Time Data Population

Review this section if you have a blank database/have not done any construction of the LDAP forest.

#### Use jumpstart.py to Populate the Database

The `jumpstart.py` script will create all the organizationalUnits, groups, and do an initial population of members/memberships. You only need to enter the admin credentials of the LDAP server. Here are the option flags with brief explanation:

1. --ldap-server (IP or host name, no default, *required*)
2. --ldap-user (default is "admin")



`python jumpstart.py --ldap-server <IP/HOSTNAME> --ldap-user <USER> 


You will be prompted for the `cn=admin,dc=example,dc=com` password.


## Logging

You can enable syslog by removing the comments from `wrapldap.py` and `template_script.py` pointing it to a syslog server, and then running `sudo python setup.py install` NOTE: Installation may fail, to fix this run `sudo python setup.py clean` and then run `sudo python setup.py install`. 
