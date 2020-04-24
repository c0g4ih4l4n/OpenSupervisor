import argparse
import sys
import os
import requests
import pymongo
from pymongo import MongoClient
import urllib

# for debug
from pprint import pprint

# get all domain have no wildcard and subdomain bruteforce enabled

# dictionary and resolver
dictionary_list = {'all':'all.txt', 'top5000': '', 'top2000': ''}
resolver_file = ''
out_file = ''
PWD = ''

main_app = 'http://127.0.0.1:5000'
mongo_user = "admin_db"
mongo_password = "long@2020"

client = MongoClient('mongodb://%s:%s@192.168.33.10' % (username, urllib.parse.quote(password)))

db = client.ThesisDB
domain_collection = db.domain

# bruteforce
# domain wildcard use subfinder, if not use massdns
list_domain = get_list_domain_bruteforce()
list_subdomain = {}
for domain in list_domain:
	list_subdomain['domain'] = set()
	domain_dict_file = 'bruteforce_file.txt'
	out_file = 'result.txt'
	create_bruteforce_dict(domain, dictionary_list['all'], domain_dict_file)

	if is_tool('massdns'):
		massdns(domain, domain_dict_file, resolver_file)
	else:
		tools_used['massdns'] = False

	if is_tool('subfinder'):
		subfinder(domain, domain_dict_file)
	else:
		tools_used['subfinder'] = False

def get_list_domain_bruteforce():
	domain_all = domain_collection.find({'bruteforce': True})
	list_domain = [x['domain_name'] for x in domain_all]
	return list_domain

def massdns(domain, dictionary, resolver_file):
	out_file = str(uuid.uuid4())
	cmd = 'massdns -r %s -t A -o S -w "%s" %s' % (resolver_file, out_file, dictionary)
	os.system(cmd)
	with open(out_file, 'r') as file:
		lines = file.readlines()
	subdomains = [x.split()[0] for x in lines]
	list_subdomain['domain'].update(subdomains)
	return

def subfinder(domain, dictionary):
	out_file = str(uuid.uuid4())
	cmd = 'subfinder -d {} -nW -t 40 -o {} -b -w {}'.format(domain, out_file, dictionary)
	os.system(cmd)
	with open(out_file, 'r') as file:
		subdomains = file.readlines()
	subdomains = [x for x in subdomains]
	list_subdomain['domain'].update(subdomains)
	return

def create_bruteforce_dict(domain, dict_name, out_file):
	cmd = 'sed "s/$/.%s/" %s > %s/%s' % (domain, dict_name, PWD, out_file)
	os.system(cmd)

def process_out_file(out_file):
	# process outfile and write to db
