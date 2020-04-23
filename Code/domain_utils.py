import socket
import dns.resolver

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
		result = dns.resolver.query(domain, type)
	return result