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


def get_port(ip):
	ip_entity = app.ip_clt.find_one({'ip': ip})

	if 'scan' in ip_entity:
		ports = ip_entity['scan'][ip]['tcp'].keys()

		return ports
	return []

def vuln_scan(ip):
	category_script_scan(ip, ['vuln'])
	return

def default_script_scan(ip):
	# get all port
	ports = get_port(ip)
	args = '-p{} --script default -T4'.format(','.join(ports))
	print ("Arguments: {}".format(args))
	nm.scan(ip, arguments=args, callback=script_cb, sudo=False)
	update_status_scan(ip, ['default'])
	return

def get_xml_result(ip):
	
	args = '-oX '

	return

def category_script_scan(ip, scan_type_list):
	ports = get_port(ip)

	if len(scan_type_list) == 0:
		scan_type_list = ['default']

	if len(ports) != 0:
		args = '-p{} --script {} -T4'.format(','.join(ports), ','.join(scan_type_list))
	else:
		args = '--script {} -T4'.format(','.join(scan_type_list))

	print ('Argument: {}'.format(args))
	nm.scan(ip, arguments=args, callback=script_cb, sudo=False)
	# update status of category scan
	update_status_scan(ip, scan_type_list)
	print ('Scan Done!')
	return

def script_cb(host, scan_data):
	if len(scan_data) == 0: 
		return
	
	if 'error' in scan_data['nmap']['scaninfo']:
		return
	update_db(host, scan_data)
	return

def category_scan_cb(host, scan_data):
	pass


def update_status_scan(ip, scan_type_list):
	ip_entity = app.ip_clt.find_one({'ip': ip})
	if 'status_scan' not in ip_entity:
		ip_entity['status_scan'] = {}

	for st in scan_type_list:
		ip_entity['status_scan'][st] = 1
	
	app.ip_clt.update({'_id': ip_entity['_id']}, {'$set': {'status_scan': ip_entity['status_scan']}})

	return

# some misunderstanding this situation
def update_db(host, scan_data):
	ip_entity = app.ip_clt.find_one({'ip': host})
	scan_data = convert_key_to_string(host, scan_data)

	old_port_data = ip_entity['scan'][host]['tcp']
	new_port_data = scan_data['scan'][host]['tcp']
	print ("NEW PORT DATA: {}".format(new_port_data))
	for port, service in new_port_data.items():
		print ("Port: {}, Service: {}".format(port, service))
		if port not in old_port_data.keys():
			continue

		if 'script' in service and 'script' in old_port_data[port]:
			new_port_data[port]['script'] = {**old_port_data[port]['script'], **new_port_data[port]['script']}
		elif 'script' in old_port_data[port]:
			service['script'] = old_port_data[port]['script']

		if old_port_data[port]['product'] != '':
			service['product'] = old_port_data[port]['product']
			service['version'] = old_port_data[port]['version']

	# if old scan have a port new scan doesn't have
	# fix with scan type (all, regular, script scan, scan type)
	for port, service in old_port_data.items():
		if port not in new_port_data.keys():
			new_port_data[port] = service

	# host scripts
	if 'hostscript' in ip_entity['scan'] and 'hostscript' not in scan_data['scan']:
		scan_data['scan']['hostscript'] = ip_entity['scan']['hostscript']

	if 'hostscript' in ip_entity['scan'] and 'hostscript' in scan_data['scan']:
		old_host_script = ip_entity['scan']['hostscript']
		new_host_script = scan_data['scan']['hostscript']

		new_host_script = {**old_host_script, **new_host_script}

		# update host script 
		# Pending
		# for script in old_host_script:
		# 	if script['id'] not in new_host_script:
		# 		pass

	scan_data['scan'][host]['tcp'] = new_port_data

	# loop through scan_data and update state port and script

	if len(scan_data) != 0:
		app.ip_clt.update({'_id': ip_entity['_id']}, 
		{'$set': scan_data
			# 'tcp_port': json.dumps(scan_data['scan'][host]['tcp']), 
			# 'hostnames': json.dumps(scan_data['scan'][host]['hostnames'][0]['name']),
			# 'state': json.dumps(scan_data['scan'][host]['status']['state'])
			# 'scaninfo': scan_data['nmap']['scaninfo']
		})

	return


def convert_key_to_string(host, nmap_result):
	# scan -> host -> tcp
	print (nmap_result)
	new_d = {str(key): value for key, value in nmap_result['scan'][host]['tcp'].items()}
	nmap_result['scan'][host]['tcp'] = new_d
	return nmap_result



# port scan
def regular_scan_port(ip):
	# Scan port
	nm.scan(ip, callback=regular_port_cb_result, sudo=False)

def regular_port_cb_result(host, scan_data):
	# update to DB
	print ('Host: {}, Scan data: {}'.format(host, scan_data))
	update_db(host, scan_data)
	return 'Success'

def full_port_scan(ip): 
	arguments = '-sV -p-'
	nm.scan(ip, callback=regular_port_cb_result, sudo=False)
	pass


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