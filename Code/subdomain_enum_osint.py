import argparse
import sys
import os
import requests
import pymongo
from pymongo import MongoClient
import urllib
import uuid

# for debug
from pprint import pprint

# output only subdomain files
# add option to output with ip with domains.
# add draw graph

# scripts automate enum domain using amass, subfinder, findomain
main_app = 'http://127.0.0.1:5000'
mongo_user = "admin_db"
mongo_password = "long@2020"

slack_webhook = ''

client = MongoClient('mongodb://%s:%s@192.168.33.10' % (username, urllib.parse.quote(password)))

db = client.ThesisDB
domain_collection = db.domain
list_domain = get_list_domain()

# domains type set
list_subdomains_osint = set()

for domain in list_domain:
	osint_update(domain)

def get_list_domain():
	domain_all = domain_collection.find({})
	list_domain = [x['domain_name'] for x in domain_all]
	return list_domain

def osint_update(domain):
	dictionary = ''
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

	# cert tranparent logs
	certspotter(domain)
	crt_sh(domain)

	# list_subdomains_osint
	takeover_domain = domain_utils.find_subdomain_takeover(list_subdomains_osint)
	# save it to database
	# send notification with webhook
	# use slack webhook
	


	# resolve ip use massdns
	domains, ips = massdns_resolve_ip()
	import_to_database(domains, ips)

def get_list_domain():
	list_domain_url = main_app + '/api/domains/list'
	res = requests.get(url=list_domain_url)
	data = res.json()
	domains = [item['domain_name'] for item in data]

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def update_set_domains_file(filename, tool):
	with open(filename, 'r') as file:
		subdomains = file.readlines()
	if tool == 'amass':
		subdomains = [x.split()[1] for x in subdomains]
	elif tool == 'subfinder' or tool == 'findomain':
		subdomains = [x for x in subdomains]
	list_subdomains_osint.update(subdomains)
	os.remove(filename)
	return

# running tool
def amass(domain):
	uniq_filename = str(uuid.uuid4())
	cmd = 'amass enum -src -ip -min-for-recursive 2 -active -d {} -o {}'.format(domain, uniq_filename)
	os.system(cmd)
	update_set_domains_file(unique_filename, 'amass')
	return

def subfinder(domain, dictionary):
	uniq_filename = str(uuid.uuid4())
	cmd = 'subfinder -d {} -nW -t 40 -o {}'.format(domain, uniq_filename)
	os.system(cmd)
	update_set_domains_file(unique_filename, 'subfinder')
	return

def findomain(domain):
	uniq_filename = str(uuid.uuid4())
	cmd = 'findomain -t {} -u {}'.format(domain, uniq_filename)
	os.system(cmd)
	update_set_domains_file(uniq_filename)
	return

# osint with certspotter and crtsh query
# Cert tranparentcy
def certspotter(domain):
	url = 'https://crt.sh/?q=%.%s&output=json' % (domain)
	try:
		res = requests.get(url)
	except requests.exceptions.HTTPError as err:
		return
	domains_cert_revelant = res.json()[0]['dns_names']
	list_subdomains_osint.update(domains_cert_revelant)
	return

# crt.sh not working
def crt_sh(domain):
	url = 'https://crt.sh/?q=%25.{}&output=json'.format(domain)
	try:
		res = requests.get(url)
	except requests.exceptions.HTTPError as err:
		return

	domain_crt_sh = res.json()['name_value']
	list_subdomains_osint.update(domain_crt_sh)
	return

def import_to_database(domains, ips):
	domain_entity = domain_collection.find({'domain_name': domain});
	domain_entity['subdomains'] = subdomains
	domain_collection.updateOne({'domain_name': domain, {'$set': domain_entity}})
	return
