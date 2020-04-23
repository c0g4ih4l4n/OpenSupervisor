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
list_domain = get_list_domain_bruteforce()
for domain in list_domain:
	domain_dict_file = 'bruteforce_file.txt'
	out_file = 'result.txt'
	create_bruteforce_dict(domain, dictionary_list['all'], domain_dict_file)

	cmd = 'massdns -r %s -t A -o S -w "%s" %s' % (resolver_file, out_file, domain_dict_file)
	os.system(cmd)


def get_list_domain_bruteforce():
	domain_all = domain_collection.find({'bruteforce': True})
	list_domain = [x['domain_name'] for x in domain_all]
	return list_domain


if is_tool('massdns'):
	amass(domain)
else:
	tools_used['massdns'] = False

if is_tool('subfinder'):
	subfinder(domain, dictionary)
else:
	tools_used['subfinder'] = False

def create_bruteforce_dict(domain, dict_name, out_file):
	cmd = 'sed "s/$/.%s/" %s > %s/%s' % (domain, dict_name, PWD, out_file)
	os.system(cmd)

def process_out_file(out_file):
	# process outfile and write to db
