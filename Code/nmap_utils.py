import nmap

# get all ip
# pull script list with each service
# write custom script for doing some shits
# Http request smuggling

# Detect web technology using whatweb or wappanalyzer
# some common are nginx/phpfpm
# apache solr
# Scan cve with that technology


def scan_all_port(ip_list):
	port_range = '1-65535'
	nm = nmap.PortScannerAsync()
	for ip in ip_list:
		nmap.PortScanner(ip, port_range, callback=test, sudo=False)
		
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