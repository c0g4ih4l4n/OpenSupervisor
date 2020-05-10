import socket
import os
import dns.resolver
import tempfile
import whois


resolver_file = ''

def check_subdomain_wildcard(domain):
	domain1, domain2, domain3 = 'somethingnotexist', 'somethingrandomhopenotduplicate', 'randomize_domain'
	try:
		ip1, ip2, ip3 = socket.gethostbyname(domain1 + '.' + domain), socket.gethostbyname(domain2 + '.' + domain), socket.gethostbyname(domain3 + '.' + domain)
		if ip1 == ip2 and ip2 == ip3:
			return True
	except:
		pass

	return False

def resolve(domain, type='A'):
	if type in ['A', 'AAAA']:
		try:
			result = dns.resolver.query(domain, type)
		except:
			return None

	ip_list = []
	for ip in result:
		ip_list.append(ip.to_text())
	return ip_list

def find_subdomain_takeover_bug(domain_list):
	# parse domain_list to file
	f = tempfile.NamedTemporaryFile(mode='w+', delete=False)
	out_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
	for domain in domain_list:
		f.write(domain + '\n')
	f.close()

	cmd = 'subjack -w {} -t 100 -timeout 30 -o {} -ssl'.format(f.name, out_file.name)
	os.system(cmd)

	with open(out_file.name, 'r') as file:
		lines = file.readlines()
	subdomains_takeover = [x for x in lines]
	os.remove(f.name)
	os.remove(out_file.name)

	return subdomains_takeover

def massdns_resolve_ip(domain_list, dictionary, resolver_file):
	result = {}
	ips = set()
	f = tempfile.NamedTemporaryFile(mode='w+', delete=False)
	out_file = tempfile.NamedTemporaryFile(mode='w+', delete=False)
	for domain in domain_list:
		f.write(domain + '\n')
	f.close()
	cmd = 'massdns -r %s -t A -o S -w "%s" %s' % (resolver_file, out_file.name, f.name)
	os.system(cmd)

	with open(out_file.name, 'r') as file:
		lines = file.readlines()

	for res in lines: 
		result[res.split()[0]] = res.split()[2]
		ips.update(res.split()[2])

	return result,ips

def whois(query, type='domain'):
	data = whois.whois(query)

	return data