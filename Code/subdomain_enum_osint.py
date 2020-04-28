import argparse
import sys
import os
import requests
import pymongo
from pymongo import MongoClient
import urllib
import uuid
import tempfile
import domain_utils
import uuid
import re

# for debug
from pprint import pprint

# output only subdomain files
# add option to output with ip with domains.
# add draw graph

# scripts automate enum domain using amass, subfinder, findomain
main_app = 'http://127.0.0.1:5000'
mongo_user = "admin_db"
mongo_password = "long@2020"

resolver_file = 'materials/resolver.txt'

slack_webhook = ''

client = MongoClient('mongodb://%s:%s@192.168.33.10/ThesisDB' % (mongo_user, urllib.parse.quote(mongo_password)))

db = client.ThesisDB
domain_collection = db.domain


def get_list_domain():
	print ('[-] Getting List Domain')
	domain_all = domain_collection.find({})
	list_domain_extract = [x['domain_name'] for x in domain_all]
	return list_domain_extract

def osint_update(domain):
	dictionary = ''
	tools_used = []
	# if is_tool('amass'):
	# 	print ("[-] Running amass ..")
	# 	amass(domain)
	# 	tools_used.append('amass')
	# if is_tool('subfinder'):
	# 	print ("[-] Running subfinder ..")
	# 	subfinder(domain, dictionary)
	# 	tools_used.append('subfinder')
	# if is_tool('findomain'):
	# 	print ("[-] Running findomain ..")
	# 	findomain(domain)
	# 	tools_used.append('findomain')

	# cert tranparent logs
	print ("[-] Fetching certspotter ..")
	certspotter(domain)
	print ("[-] Fetching crtsh ..")
	crt_sh(domain)

	# list_subdomains_osint
	takeover_domain = domain_utils.find_subdomain_takeover_bug(list_subdomains_osint)
	# save it to database
	# send notification with webhook
	# use slack webhook
	


	# resolve ip use massdns
	subdomains, ips = domain_utils.massdns_resolve_ip(list_subdomains_osint, '', resolver_file)

	print ("[-] Updating DB ..")
	import_to_database(domain, subdomains, ips)

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
	f = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
	cmd = 'amass enum -src -ip -min-for-recursive 2 -active -d {} -o {}'.format(domain, f.name)
	os.system(cmd)
	update_set_domains_file(f.name, 'amass')
	return

def subfinder(domain, dictionary):
	f = tempfile.NamedTemporaryFile(mode='w+b', delete=False)
	cmd = 'subfinder -d {} -nW -t 40 -o {}'.format(domain, f.name)
	os.system(cmd)
	update_set_domains_file(f.name, 'subfinder')
	return

def findomain(domain):
	f_name = str(uuid.uuid4())
	cmd = 'findomain -t {} -u {}'.format(domain, '/tmp/' + f_name)
	os.system(cmd)
	update_set_domains_file ('/tmp/' + f_name, 'findomain')
	return

# osint with certspotter and crtsh query
# Cert tranparentcy
def certspotter(domain):
	url = 'https://certspotter.com/api/v0/certs\?domain={}'.format(domain)
	try:
		res = requests.get(url)
	except requests.exceptions.HTTPError:
		return
	if res.status_code != '200':
		return
	domains_cert_revelant = res.json()[0]['dns_names']
	list_subdomains_osint.update(domains_cert_revelant)
	return

# crt.sh not working
def crt_sh(domain):
	url = 'https://crt.sh/?q=%25.{}&output=json'.format(domain)
	try:
		res = requests.get(url)
	except requests.exceptions.HTTPError:
		return

	if len(res.json()) == 0:
		return

	domain_crt_sh = []
	for cert in res.json():
		domain_crt_sh.extend(cert['name_value'].split('\n'))

	list_subdomains_osint.update(domain_crt_sh)
	return

def insert_domain_to_db(parent_domain, domain):
	if parent_domain is None:
		domain_collection.insert({'domain_name': domain})
		return

	domain_entity = domain_collection.find({'domain_name': parent_domain})	
	if domain_entity is None:
		raise ValueError('Parent domain does not exists in DB...')

	domain_new_ent = {'domain_name': domain}
	domain_entity['subdomains'].append(domain_new_ent)
	domain_collection.update_one({'_id': domain['_id']}, {'$set': domain_entity})
	return

def import_to_database(domain, subdomains, ips):
	domain_entity = domain_collection.find({'domain_name': domain})
	if domain_entity is None:
		insert_domain_to_db(None, domain)
	domain_entity['subdomains'] = subdomains
	domain_collection.update_one({'_id': domain['_id']}, {'$set': domain_entity})
	ip_collection = db.ip
	return

if __name__ == '__main__':
	list_domain = get_list_domain()

	# domains type set
	list_subdomains_osint = set()

	for domain in list_domain:
		print ("[-] Running on {}.".format(domain))
		osint_update (domain)
		list_subdomains_osint.clear()