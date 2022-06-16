#!/usr/bin/env python

import os
import re
import ldap3
import json
import configparser
import argparse
import ssl
import logging


# Setup parser for CLI args

parser = argparse.ArgumentParser(
    description='Script to obtain host inventory from AD')
parser.add_argument('--list', action='store_true', help='prints a json of hosts with groups and variables')
parser.add_argument('--host', help='returns variables of given host')
parser.add_argument('--file', help='writes all hosts to a file > list.txt')
# parser.add_argument('--log', help='Set logging level :\t 1 - Debug\n2 - Info\n3 - Warning\n4 - Error\n5 - Critical\n By default set to warning')

args = parser.parse_args()
    
# Setup logging
logging.basicConfig(level = logging.WARNING,filename = 'log.txt',filemode = 'w', format='%(asctime)s -%(levelname)s -%(message)s', datefmt='%d-%b-%y %H:%M:%S')


class ADAnsibleInventory():
    
    domain = 'swglg01.local'

    def __init__(self):
        directory = os.path.dirname(os.path.abspath(__file__))
        configfile = directory + '/test.ini'
        config = configparser.ConfigParser()
        config.read(configfile)
        username = os.environ['LDAPUN']
        password = os.environ['LDAPPASS']
        basedn = config.get('ldap-ad', 'basedn')
        ldapuri = os.environ['LDAPURL']
        port = config.get('ldap-ad', 'port')
        adattributes = config.get('ldap-ad','attributes').split(",") # get attributes from config file and split by , to put into a list
        filegroup = config.get('ldap-ad','filegroup').split(",") # groups to print out hosts from inventory to file
#       ca_file = config.get('ldap-ad', 'ca_file') # There is no ca file
        groups = config.get('filters','groups').split(",")
        hostvars = config.get('filters','hostvars').split(",")

        adfilter = "(&(sAMAccountType=805306369))" # filters the query from AD based on account type: computer
        self.inventory = {"_meta": {"hostvars": {}}}
        # self.ad_connect_tls(ldapuri, username, password, port, ca_file)
        self.ad_connect(ldapuri, username, password, port)
        self.get_hosts(basedn, adfilter, adattributes) # Retrieves the server hosts based on the AD filter
        self.org_hosts(basedn) # organises the hosts
        self.group_hosts(groups, hostvars)

        # print(filegroup)
#   Check CLI arguments
        if args.list:
           print(json.dumps(self.inventory, sort_keys=True, indent=2))
        if args.file:
           self.write_hosts_file(args.file) # writes inventory list to file
        if args.host is not None:
            try:
                print(self.inventory['_meta']['hostvars'][args.host]) # prints the hosts into inventory
            except Exception:
                print('{}')
        

    # function to initiate TLS connection
    def ad_connect_tls(self, ldapuri, username, password, port, ca_file ): # connection uses ca file -> is it mandatory
        tls_configuration = ldap3.Tls(validate=ssl.CERT_NONE,
                                      ca_certs_file=None)
        server = ldap3.Server(ldapuri, use_ssl=True, tls=tls_configuration)
        conn = ldap3.Connection(server,
                                auto_bind=True,
                                user=username,
                                password=password,
                                authentication=ldap3.NTLM)
        self.conn = conn  # Var define conn to AD via LDAP

     # function to initiate conn non ssl/tls
    def ad_connect(self, ldapuri, username, password, port):
         server = ldap3.Server(ldapuri, port=port, get_info=ldap3.ALL) # Create AD server object with AD uri
         conn = ldap3.Connection(server,user=username,password=password, auto_bind=True)
         self.conn = conn



    # This function may be modified to filter out the required hosts essentially using an additional parameter
    # Performs an LDAP search on the AD -> Doc on search operation https://ldap3.readthedocs.io/searches.html
    # The response is saved in JSON
    # Stored in results var

    def get_hosts(self, basedn, adfilter, adattributes):
        self.conn.search(search_base=basedn,
                         search_filter=adfilter,
                         attributes=adattributes)
        self.conn.response_to_json
        self.results = self.conn.response

# the function finds the OU which the vm's belong to
# This is meant to be used where the AD OU's are catergorised as Unix>Test,Unix>Prod,Unix>DR,
# Further subgroups would look like Unix>Test>Prod>Melbourne
# If AD is as described above then the script would add into groups and subgroups accordingly

    def org_hosts(self, basedn):
        # Removes CN,OU, and DC and places into a list
        basedn_list = (re.sub(r"..=", "", basedn)).split(",")
        for computer in self.results:
            org_list = (re.sub(r"..=", "", computer['dn'])).split(",")
            # Remove hostname
            del org_list[0]
            # Removes all excess OUs and DC
            for count in range(0, (len(basedn_list)-1)):
                del org_list[-1]

            # Reverse list so top group is first
            org_list.reverse()

            org_range = range(0, (len(org_list)))
            for orgs in org_range:
                if computer['attributes']['cn']:
                    if orgs == org_range[-1]:
                        self.add_host(org_list[orgs],computer['attributes']['cn'].lower()+'.'+self.domain)
                    else:
                        self.add_group(group=org_list[orgs],children=org_list[orgs+1])

# New function to group hosts
# a classify method to filter the results based on computer attributes and add  into a group of that filter
# eg: filter by environment: test add into group test
# All hosts will have the hostvars -> managedby, description, veaStatus
#                                        

    def group_hosts(self, groups, hostvars):
        fix_hosts = {} # test purpose : to identify blank attributes
        for computer in self.results:
            blank_attributes = [] # test purpose : to identify blank attributes
            hostname = self.get_attribute(computer, 'cn')+'.'+self.domain
            for filter_attribute in groups:
                group = self.get_attribute(computer, filter_attribute) #
                if  (group is not None) and (hostname is not None):
                    self.add_host(group,hostname)
                else: # test purpose : to identify blank attributes
                    blank_attributes.append(filter_attribute) # test purpose : to identify blank attributes
            if hostvars is not None:
                for filter_hostvars in hostvars:
                    self.add_hostvars(hostname, filter_hostvars ,self.get_attribute(computer, filter_hostvars))

    # Add hostvars to the inventory object
    def add_hostvars(self, hostname, var, value):
        if hostname not in self.inventory['_meta']['hostvars'].keys():
            self.inventory['_meta']['hostvars'].update({hostname:{}})
        self.inventory['_meta']['hostvars'][hostname].update({var:value})

    # Add a host to the inventory object

    def add_host(self, group, host):
        host = (''.join(host)).lower()
        group = (''.join(group)).lower()
        if group not in self.inventory.keys():
            self.inventory[group] = {'hosts': [], 'children': []}
        self.inventory[group]['hosts'].append(host)

    # add a group to the inventory object
    def add_group(self, group, children):
        group = (''.join(group)).lower()
        children = (''.join(children)).lower()
        if group not in self.inventory.keys():
            self.inventory[group] = {'hosts': [], 'children': []}
        if children not in self.inventory[group]['children']:
            self.inventory[group]['children'].append(children)

    # Function to write inventory hosts to a file

    def write_hosts_file(self,filename):
        file = open(filename, 'w')
        # file.write(self.inventory[])
        # for group in filegroup:
        for host in self.inventory['pre_prod']['hosts']:
            # print (self.inventory[group]['hosts']) # Group var has been hardcoded
            file.write("%s\n"% host) #write hosts to file line by line
        file.close()

# Function will be used to get the value of any attribute in a computer returned by ldap
# Use the attribute without validation for syntax passed through config file
# Use exception handling to avoid the duplication of code

    def get_attribute(self, computer, attribute):

        result = None
        try:
            result = self.sanitise( (computer['attributes'][attribute]) )
        except KeyError as error:
            # print(error)
            logging.warning('Invalid attribute in config file: filters -> groups :')
            # logging.exception('Exception occured:')
            # print('Invalid attribute in config file: filters -> groups')
        except AttributeError as error:
            # print(error)
            logging.warning( ('Blank attribute returned for: %s in computer %s :',attribute,computer['attributes']['cn']))
            # logging.exception('Exception occured:')
            # print('Blank attribute returned for: %s in computer %s'%(attribute,computer['attributes']['cn']) )
        except:
            # print('Write exception onto file')
            logging.exception('An exception occured:')
            # logging.exception('Exception occured:')
        # else:
        #     if (result is None):
        #         raise Exception('Ldap query return blank list [] for attribute: '.format(attribute) )
        finally:
            return result

    def sanitise(self,string):
        # if string:
          return  string.rstrip().lower().replace("-","_")
        # result = None # If the attribute in ldap query return blank list []  result set to None  


if __name__ == '__main__':
    ADAnsibleInventory() 
