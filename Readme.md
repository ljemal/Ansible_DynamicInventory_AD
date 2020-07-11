# Overview

A dynamic inventory script for Ansible for use with on premise Active Directory servers.
It queries Active Directory using ldap3 for computer accounts and groups them according to filters in the config .ini file.


## Requirements
Install the dependencies required for script from requirements.txt

`pip install -f requirements.txt`

A service account with the neccessary privleges is required to communicate using ldap to AD.

## How to use

- Place the file : `ldap-ad.py` along with the config file : `ldap-ad.sample.ini` in the ansible inventory directory
- Change the `ldap-ad.py` file's permission to make it executable
- Create a new config file copying the `ldap-ad.sample.ini` file
- Modify config file to setup configuration details per you environment
- Test the inventory script with Ansible  using : `ansible-inventory --graph`


Example 1:

> python ldap-ad.py --list 
prints out a list of hosts to stdout

Example 2:

> python ldap-ad.py --host
prints the hostvars for a particular host

Example 3:
> python ldap-ad.py --file
prints the hosts in a group to file
