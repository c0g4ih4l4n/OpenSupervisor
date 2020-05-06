import nmap
from pymongo import MongoClient
import urllib

# get all ip
# pull script list with each service
# write custom script for doing some shits
# Http request smuggling
main_app = 'http://127.0.0.1:5000'
mongo_user = "admin_db"
mongo_password = "long@2020"

slack_webhook = ''

client = MongoClient('mongodb://%s:%s@192.168.33.10' % (mongo_user, urllib.parse.quote(mongo_password)))

db = client.ThesisDB
ip_coletn = db.ip

# Detect web technology using whatweb or wappanalyzer
# some common are nginx/phpfpm
# apache solr
# Scan cve with that technology
# tor scan with nmap using proxychain, tor, nmap

categories = ['auth', 'broadcast', 'brute', 'default', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 'intrusive', 'malware', 'safe', 'version', 'vuln']

def regular_scan_port(ip):
	nm = nmap.PortScannerAsync()
	nm.scan(ip, callback=regular_port_cb, sudo=False)

def regular_port_cb(hosts, scan_data):

	return

def tor_network_scan_port(ip):

	return

def scan_all_port(ip_list):
	port_range = '1-65535'
	nm = nmap.PortScannerAsync()
	for ip in ip_list:
		nm.scan(ip, port_range, callback=all_port_cb, sudo=False)
	pass

def all_port_cb(hosts, scan_data):
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

def parse_result(hosts, scan_data):
	pass

def check_host_alive():
	
	pass