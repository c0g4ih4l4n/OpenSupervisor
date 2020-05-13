import nmap
from pymongo import MongoClient
import urllib
import billiard as multiprocessing
import json

import app

# get all ip
# pull script list with each service
# write custom script for doing some shits
# Http request smuggling
main_app = 'http://127.0.0.1:5000'
mongo_user = "admin_db"
mongo_password = "long@2020"

slack_webhook = ''

client = MongoClient('mongodb://%s:%s@192.168.33.10/ThesisDB' % (mongo_user, urllib.parse.quote(mongo_password)))

ip_clt = client.ip

# Detect web technology using whatweb or wappanalyzer
# some common are nginx/phpfpm
# apache solr
# Scan cve with that technology
# tor scan with nmap using proxychain, tor, nmap

scan_type_list = ['auth', 'broadcast', 'brute', 'default', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 'intrusive', 'malware', 'safe', 'version', 'vuln']
nm = nmap.PortScannerAsync()

def category_scan(ip, list_cat):
	args = '--script ' + ','.join(list_cat)
	nm.scan(ip, arguments=args, callback=category_scan_cb, sudo=False)
	return

def default_script_scan(ip):
	# get all port
	ip_entity = app.ip_clt.find_one({'ip': ip})

	if 'scan' in ip_entity:
		ports = ip_entity['scan'].keys()
	args = '-p' + ','.join(ports) + ' --script default -T4'
	print ('Argument: {}'.format(args))
	nm.scan(ip, arguments=args, callback=default_script_cb, sudo=False)
	return

def default_script_cb(host, scan_data):
	ip_entity = app.ip_clt.find_one({'ip': host})
	# scan_data = convert_key_to_string(host, scan_data)
	print ('Host: {}, Scan Data: {}'.format(host, scan_data))
	app.ip_clt.update({'_id': ip_entity['_id']}, 
	{'$set': scan_data
		# 'tcp_port': json.dumps(scan_data['scan'][host]['tcp']), 
		# 'hostnames': json.dumps(scan_data['scan'][host]['hostnames'][0]['name']),
		# 'state': json.dumps(scan_data['scan'][host]['status']['state'])
		# 'scaninfo': scan_data['nmap']['scaninfo']
	})
	return

def category_scan_cb(host, scan_data):
	pass

def convert_key_to_string(host, nmap_result):
	# scan -> host -> tcp
	print (nmap_result['scan'][host]['tcp'])
	new_d = {str(key): value for key, value in nmap_result['scan'][host]['tcp'].items()}
	nmap_result['scan'][host]['tcp'] = new_d
	return nmap_result

def regular_scan_port(ip):
	# Scan port
	nm.scan(ip, callback=regular_port_cb_result, sudo=False)

def regular_port_cb_result(host, scan_data):
	# update to DB
	print ('Host: {}, Scan data: {}'.format(host, scan_data))

	ip_entity = app.ip_clt.find_one({'ip': host})
	scan_data = convert_key_to_string(host, scan_data)
	app.ip_clt.update({'_id': ip_entity['_id']}, 
	{'$set': scan_data
		# 'tcp_port': json.dumps(scan_data['scan'][host]['tcp']), 
		# 'hostnames': json.dumps(scan_data['scan'][host]['hostnames'][0]['name']),
		# 'state': json.dumps(scan_data['scan'][host]['status']['state'])
		# 'scaninfo': scan_data['nmap']['scaninfo']
	})
	return 'Success'

def tor_network_scan_port(ip):
	return

def scan_all_port(ip_list):
	port_range = '1-65535'
	nm = nmap.PortScannerAsync()
	for ip in ip_list:
		nm.scan(ip, port_range, callback=all_port_cb, sudo=False)
	pass

def all_port_cb(host, scan_data):
	pass

def scan_service():
	pass

def os_detection():
	pass

def script_scan():
	pass

# use aquatone
def visualization():
	pass

def parse_result(host, scan_data):
	pass

def check_host_alive():
	pass