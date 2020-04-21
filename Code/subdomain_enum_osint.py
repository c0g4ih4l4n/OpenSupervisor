import argparse
import sys
import os
import requests
import pymongo
from pymongo import MongoClient
import urllib

# for debug
from pprint import pprint

# output only subdomain files
# add option to output with ip with domains.
# add draw graph

# scripts automate enum domain using amass, subfinder, findomain
main_app = 'http://127.0.0.1:5000'
mongo_user = "admin_db"
mongo_password = "long@2020"

client = MongoClient('mongodb://%s:%s@192.168.33.10' % (username, urllib.parse.quote(password)))

db = client.ThesisDB
domain_collection = db.domain
list_domain = get_list_domain()

for domain in list_domain:
	osint_update(domain)

def get_list_domain():
	domain_all = domain_collection.find({})
	list_domain = [x['domain_name'] for x in domain_all]
	return list_domain

def osint_update(domain):
	dictionary = ''
	out_file = args.out if args.out is not None else None
	tools_used = []
	if is_tool('amass'):
		amass(domain)
	else:
		tools_used['amass'] = False
	if is_tool('subfinder'):
		subfinder(domain, dictionary)
	else:
		tools_used['subfinder'] = False
	if is_tool('findomain'):
		findomain(domain)
	else:
		tools_used['findomain'] = False

	process_result(domain, out_file)
	import_to_database(domain, out_file)

def get_list_domain():
	list_domain_url = main_app + '/api/domains/list'
	res = requests.get(url=list_domain_url)
	data = res.json()
	domains = [item['domain_name'] for item in data]

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def amass(domain):
	cmd = 'amass enum -src -ip -min-for-recursive 2 -active -d {} -o amass.out'.format(domain)
	print ('Running>> ' + cmd)
	os.system(cmd)
	return

def subfinder(domain, dictionary):
	if dictionary != '':
		cmd = 'subfinder -b -d {} -nW -t 40 -w {} -o subfinder.out'.format(domain, dictionary)
	else:
		cmd = 'subfinder -d {} -nW -t 40 -o subfinder.out'.format(domain)
	print ('Running>> ' + cmd)
	os.system(cmd)
	return

# osint with certspotter and crtsh query
def certspotter(domain):
	cmd = '''curl -s "https://crt.sh/?q=%.$domain&output=json" | jq '.[].name_value' | sed 's/\"//g' | sed 's/\*\.//g' | grep -v $domain | sort -u > $PWD/hosts-crtsh.txt'''
	os.system(cmd)
	pass

def crt_sh(domain):
	cmd = '''curl -s https://certspotter.com/api/v0/certs\?domain\=$domain | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\*\.//g' | grep -v $domain | sort -u > $PWD/hosts-certspotter.txt'''
	os.system(cmd)
	pass

def findomain(domain):
	cmd = 'findomain -t {} -i -o'.format(domain)
	print ('Running>> ' + cmd)
	os.system(cmd)
	return

def process_result(domain, outFile):
	# process result
	cmd = "cat amass.out| awk -F ']' '{print $2}' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | awk -F ' ' '{print $1}'> amass_domain.out;"
	cmd += "cat {}.txt | awk -F ',' '{{print $1}}' > findomain_domain.out;".format(domain)
	cmd += 'cat amass_domain.out subfinder.out findomain_domain.out | sort -u > {};'.format(outFile)

	# clean file
	cmd += 'rm amass.out amass_domain.out subfinder.out {}.txt findomain_domain.out'.format(domain)
	print ('Running>> {};\nFinish! Result File: {}'.format(cmd, outFile))
	os.system(cmd)
	return

def import_to_database(domain, file):
	with open(outFile, 'r') as file:
		list_domain = file.readlines()

	subdomains = [i.strip() for i in list_domain]

	# insert to mongo
	domain_entity = domain_collection.find({'domain_name': domain});
	domain_entity['subdomains'] = subdomains
	domain_collection.updateOne({'domain_name': domain, {'$set': domain_entity}})
	return
