
'''
Setup script for wrapldap
'''

import sys

# Check if Python is 2.7 installed/invoked. 
major, minor, micro, releaselevel, serial = sys.version_info
if (major,minor) != (2,7):
    print 'Python %(maj)d.%(min)d detected; wrapldap requires Python 2.7. Exiting...' % {'maj':major, 'min':minor}
    sys.exit(101)

import os

from setuptools import setup

# Get working directory
wd = os.path.dirname(os.path.abspath(__file__))
os.chdir(wd)
sys.path.insert(1, wd)


# Set some metadata
name = 'wrapldap'
author = 'Gabriel Deleon'
email = 'notprivategabe@gmail.com'
version = '0.9.3'

description = 'Streamlined wrapper for python-ldap to manipulate an ldap server.'


try:
    reqs = open(os.path.join(os.path.dirname(__file__), 'requirements.txt')).read()
except (IOError, OSError):
    reqs =''


# Egg Metadata
setup(name=name,
      version=version,
      author=author,
      author_email=email,
      maintainer=author,
      maintainer_email=email,
      description=description,
      py_modules=['wrapldap']
)

