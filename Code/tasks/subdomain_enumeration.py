import argparse
import sys
import os
import celery
import uuid
import tempfile

# for debug
from pprint import pprint

# output only subdomain files
# add option to output with ip with domains.

# scripts automate enum domain using amass, subfinder, findomain

@celery.task()
def enum_domain(domain):
	domain = args[0]
	logger = enum_domain.get_logger()
	logger.info("Running amass on %s" % domain)
	# get domain

	dictionary = '/home/te/tools/payloads/SecLists/Discovery/DNS/subdomains-top1million-5000.txt'

	(fd_outfile, out_file) = tempfile.mkstemp()
	(fd_amass, amass_out) = tempfile.mkstemp()
	(fd_subfinder, subfinder_out) = tempfile.mkstemp()
	(fd_findomain, findomain_out) = tempfile.mkstemp()
	# inputFile = args.file if args.file is not None else None
	# outFile = args.out if args.out is not None else None

	tools_used = []
	# amass(domain) if is_tool('amass') else tools_used['amass'] = True
	# subfinder(domain, dictionary) if is_tool('subfinder') else tools_used['subfinder'] = True
	# findomain(domain) if is_tool('findomain') else tools_used['domain'] = True
	if is_tool('amass'):
		amass(domain, amass_out)
	else:
		tools_used['amass'] = False

	if is_tool('subfinder'):
		subfinder(domain, dictionary, subfinder_out)
	else:
		tools_used['subfinder'] = False

	if is_tool('findomain'):
		findomain(domain, findomain_out)
	else:
		tools_used['findomain'] = False

	process_result(domain, out_file)

def is_tool(name):
    """Check whether `name` is on PATH and marked as executable."""
    from shutil import which
    return which(name) is not None

def amass(domain, out_file):
	cmd = 'amass enum -src -ip -min-for-recursive 2 -active -d {} -o {}'.format(domain, out_file)
	print ('Running>> ' + cmd)
	os.system(cmd)
	return

def subfinder(domain, dictionary, out_file):
	if dictionary is not None:
		cmd = 'subfinder -b -d {} -nW -t 40 -w {} -o {}'.format(domain, dictionary, out_file)
	else:
		cmd = 'subfinder -d {} -nW -t 40 -o subfinder.out'.format(domain)
	print ('Running>> ' + cmd)
	os.system(cmd)
	return

def findomain(domain, out_file):
	cmd = 'findomain -t {} -u {} -i'.format(domain, out_file)
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

