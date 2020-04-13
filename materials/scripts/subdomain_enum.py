import argparse
import sys
import os

# for debug
from pprint import pprint

# output only subdomain files
# add option to output with ip with domains.
# add draw graph

# scripts automate enum domain using amass, subfinder, findomain

parser = argparse.ArgumentParser(description='Find Subdomain')
parser.add_argument('-d', '--domain', type=str, help='Domain Name')
parser.add_argument('-o', '--out', type=str, help='Output File')
parser.add_argument('-D', '--dictionary', type=str, help='Dictionary File')
parser.add_argument('-f', '--file', type=str, help='Input File')
parser.add_argument("--nobruteforce", default=False, action="store_true" , help="No brute force")
args = parser.parse_args()

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
	if dictionary is not None:
		cmd = 'subfinder -b -d {} -nW -t 40 -w {} -o subfinder.out'.format(domain, dictionary)
	else:
		cmd = 'subfinder -d {} -nW -t 40 -o subfinder.out'.format(domain)
	print ('Running>> ' + cmd)
	os.system(cmd)
	return

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


if(len(sys.argv) <= 1 or args.domain == None):
	print(parser.print_help())
	exit(1)

domain = args.domain
dictionary = args.dictionary if args.dictionary is not None else None
inputFile = args.file if args.file is not None else None
outFile = args.out if args.out is not None else None

tools_used = []
# amass(domain) if is_tool('amass') else tools_used['amass'] = True
# subfinder(domain, dictionary) if is_tool('subfinder') else tools_used['subfinder'] = True
# findomain(domain) if is_tool('findomain') else tools_used['domain'] = True
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

process_result(domain, outFile)