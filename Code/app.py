# from werkzeug import secure_filename

from flask import *
from flask_restful import Resource, Api
from flask_pymongo import PyMongo
import pymongo

import socket
import urllib
import json
import db_utils
import time
import ip_utils
import nmap

from crontab import CronTab
from bson import json_util
import json
import domain_utils
from bson.json_util import dumps

import nmap_utils


from flask_celery import make_celery

import subdomain_enum_osint
import subdomain_enum_bruteforce
import billiard as multiprocessing



app = Flask(__name__)
app.config.from_object('config')

app.url_map.strict_slashes = False
app.secret_key = 'qweoi@#!ASDQWEJKLZXCJ'
app.config['UPLOAD_FOLDER'] = 'upload/'
app.config['MAX_CONTENT_PATH'] = 2048
app.config['SQLALCHEMY_DATABASE_URI'] = ''
app.config['CELERY_BROKER_URI'] = 'redis://localhost:6379/0'
# app.config['CELERY_BACKEND'] = 'redis://localhost:6379/0'
mongo_user = "admin_db"
mongo_password = "long@2020"

app.config["MONGO_URI"] = "mongodb://%s:%s@192.168.33.10:27017/ThesisDB" % (mongo_user, urllib.parse.quote(mongo_password))

mongo = PyMongo(app)

# client = MongoClient("mongodb://%s:%s@192.168.33.10:27017" % (mongo_user, mongo_password))  # host uri
# db = client.ThesisDB  # Select the database
db = mongo.db
dm_clt = mongo.db.domain
ip_clt = mongo.db.ip

api = Api(app)

todos = {}
celery = make_celery(app)





# Domain
class DomainListAPI(Resource):
	def get(self):
		headers = {'Content-Type': 'text/html'}
		domains = dm_clt.find()
		domains_json = db_utils.cursor_to_json(domains)
		return make_response(render_template('domain_dashboard.html', domains=domains_json), 200, headers)

	def post(self):
		domain_name = request.form['domain_name']
		org_name = request.form['org_name'] if request.form['org_name'] is not None else ""
		ip_list = domain_utils.resolve(domain_name)
		wild_card = domain_utils.check_subdomain_wildcard(domain_name)
		brute_force = True if request.form['brute_force'] == 1 else False
		whois_data = domain_utils.whois(domain_name)

		# insert ip to db
		for ip in ip_list:
			status = ip_utils.check_alive(ip)
			whois_data = ip_utils.whois(ip)
			# update to db
			
			db.getCollection('ip').update(
				{"ip": ip},
				{'$setOnInsert': {'ip': ip, "status": status, 'whois': whois_data} },
				upsert=True
			)
		
		new_domain = {"domain_name": domain_name, "org_name": org_name, "ips": ip_list, 'wild_card': wild_card, "brute_force": brute_force, 'whois_data': whois_data}
		dm_clt.insert(new_domain)
		return redirect(url_for('target_dashboard'))


class SubDomainAPI(Resource):
	def get(self, domain_name):
		headers = {}
		domain_entity = dm_clt.find_one({'domain_name': domain_name})
		return make_response(render_template('subdomain_dashboard.html', domain=domain_entity), 200, headers)

	def post(self, domain_name):
		if request.form['_method'] == 'PUT':
			domain = dm_clt.find_one({'domain_name': domain_name})
			domain['domain_name'] = request.form['domain_name']
			domain['org_name'] = request.form['org_name']
			domain['ips'] = domain_utils.resolve(request.form['domain_name'])
			domain['wild_card'] = domain_utils.check_subdomain_wildcard(request.form['domain_name'])
			dm_clt.update_one({'_id' : domain['_id']}, {'$set': domain})
			return redirect(url_for('target_dashboard'))
		elif request.form['_method'] == 'DELETE':
			if request.form['type'] == 'sub':
				domain_entity = dm_clt.find_one({'domain_name': domain_name})
				domain_entity['subdomains'] = [x for x in domain_entity['subdomains'] if x['domain_name'] != request.form['domain_name']]
				dm_clt.update_one({'_id' : domain_entity['_id']}, {'$set': domain_entity})
				return redirect(url_for('api.subdomain', domain_name=domain_name))
			else:
				dm_clt.remove({'domain_name': domain_name})
				return redirect(url_for('target_dashboard'))



# IP
class IPListAPI(Resource):
	def get(self):
		headers = {'Content-Type': 'text/html'}
		ips = ip_clt.find()
		ips_json = ip_utils.cursor_to_json(ips)
		return make_response(render_template('ip_dashboard.html', ips=ips_json), 200, headers)

	def post(self):
		domain_name = request.form['domain_name']
		org_name = request.form['org_name'] if request.form['org_name'] is not None else ""
		ip_list = domain_utils.resolve(domain_name)
		wild_card = domain_utils.check_subdomain_wildcard(domain_name)
		brute_force = True if request.form['brute_force'] == 1 else False
		whois_data = domain_utils.whois(domain_name)
		
		new_domain = {"domain_name": domain_name, "org_name": org_name, "ips": ip_list, 'wild_card': wild_card, "brute_force": brute_force, 'whois_data': whois_data}
		dm_clt.insert(new_domain)
		
		# Check alive ip
		for ip in ip_list:
			status = ip_utils.check_alive(ip)
			# update to db
			
			db.getCollection('ip').update(
				{"ip": ip},
				{'$setOnInsert': {'ip': ip, "status": status} },
				upsert=True
			)
		# update status to db
		return redirect(url_for('target_dashboard'))

class IPAPI(Resource):
	def get(self, ip):
		headers = {}
		ip_entity = ip_clt.find_one({'ip': ip})
		scan_type_list = ['auth', 'broadcast', 'brute', 'default', 'discovery', 'dos', 'exploit', 'external', 'fuzzer', 'intrusive', 'malware', 'safe', 'version', 'vuln']
		return make_response(render_template('ip_detail.html', ip=ip_entity, scan_type_list=scan_type_list), 200, headers)

	def post(self, domain_name):
		if request.form['_method'] == 'PUT':
			domain = dm_clt.find_one({'domain_name': domain_name})
			domain['domain_name'] = request.form['domain_name']
			domain['org_name'] = request.form['org_name']
			domain['ips'] = domain_utils.resolve(request.form['domain_name'])
			domain['wild_card'] = domain_utils.check_subdomain_wildcard(request.form['domain_name'])
			dm_clt.update_one({'_id' : domain['_id']}, {'$set': domain})
			return redirect(url_for('target_dashboard'))
		elif request.form['_method'] == 'DELETE':
			if request.form['type'] == 'sub':
				domain_entity = dm_clt.find_one({'domain_name': domain_name})
				domain_entity['subdomains'] = [x for x in domain_entity['subdomains'] if x['domain_name'] != request.form['domain_name']]
				dm_clt.update_one({'_id' : domain_entity['_id']}, {'$set': domain_entity})
				return redirect(url_for('api.subdomain', domain_name=domain_name))
			else:
				dm_clt.remove({'domain_name': domain_name})
				return redirect(url_for('target_dashboard'))


api.add_resource(DomainListAPI, '/targets', endpoint = 'api.domains')
api.add_resource(SubDomainAPI, '/targets/<string:domain_name>', endpoint = 'api.subdomain')

api.add_resource(IPListAPI, '/ips', endpoint = 'api.ips')
api.add_resource(IPAPI, '/ips/<string:ip>', endpoint = 'api.ip')

@app.route('/api/domains/list')
def domain_list():
	# headers = {'Content-Type': 'application/json'}
	domains = dm_clt.find()
	domains_json = db_utils.cursor_to_json(domains)
	return jsonify(domains_json)

@app.route('/domains/scan/<string:domain>')
def set_subdomain_scan_schedule(domain):
	schedule = request.form['schedule']
	my_jobs = CronTab(user='te')
	new_job = my_jobs.new(command='python3 /home/te/Projects/Thesis/Code/subdomain_enum.py')
	new_job.day.every(1)
	my_jobs.write()

@app.route('/')
def index():
	return redirect(url_for("domain_dashboard"))

@app.route('/dashboard')
def domain_dashboard():
	return redirect(url_for('api.domains'))




@app.route('/targets/')
def target_dashboard():
	return redirect(url_for(('api.domains')))

@app.route('/targets/create')
def create_domain():
	return render_template('domain_create.html')


@app.route('/targets/<string:domain_name>/edit')
def edit_domain(domain_name):
	# get domain entity for 
	domain_entity = dm_clt.find_one({'domain_name': domain_name})
	return render_template('targets_edit.html', edited_domain=domain_entity)


@app.route('/targets/<string:domain_name>/scan')
def subdomain_enumeration(domain_name):
	# push task to redis
	domain_entity = dm_clt.find_one({'domain_name': domain_name})

	# get current task and check
	task = subdomain_enum_worker.delay(domain_name)
	domain_entity['subdomain_enum_task_id'] = task.task_id
	dm_clt.update_one({'_id': domain_entity['_id']}, {'$set': domain_entity})
	return redirect(url_for('api.domains'))

@app.route('/targets/<string:domain_name>/brute_force_scan')
def subdomain_bruteforce(domain_name):
	# push task to redis
	domain_entity = dm_clt.find_one({'domain_name': domain_name})

	# get current task and check
	task = subdomain_bruteforce_worker.delay(domain_name)
	domain_entity['subdomain_enum_task_id'] = task.task_id
	dm_clt.update_one({'_id': domain_entity['_id']}, {'$set': domain_entity})
	return redirect(url_for('api.domains'))

@celery.task(name='app.subdomain_scan')
def subdomain_enum_worker(domain):
	subdomain_enum_osint.osint_update(domain)
	return

@celery.task(name='app.subdomain_bruteforce')
def subdomain_bruteforce_worker(domain):
	subdomain_enum_bruteforce.osint_update(domain)
	return










@app.route('/ips/create')
def create_ip():
	return render_template('ip_create.html')

@app.route('/ips/<string:ip>/edit')
def edit_ip():
	return


@app.route('/ips/<string:ip>/scan')
def ip_scan(ip):
	ip_scan_worker.delay(ip)
	return redirect(url_for('api.ips'))

@celery.task(name='app.ip_scan')
def ip_scan_worker(ip):
	print ('Start regular scan on {}'.format(ip))
	nmap_utils.regular_scan_port(ip)
	return





@app.route('/vuln-database')
def vuln_db_dashboard():
	return render_template('vuln-database.html')



@app.route('/google_hacking_dashboard')
def google_hacking_dashboard():
	return render_template('google_hacking_dashboard.html')














@app.route('/visualization/<string:domain>')
def visualization(domain):
	# screen shot with aquatone and rename file + change location
	pass

@app.route('/postscan/<string:ip>')
def port_scan(ip):
	# scan with 2 modules
	# portscan(ip)
	pass

@app.route('/servicescan/<string:ip>')
def service_scan(ip):
	# run scan with service scan

	# detect web technology with whatweb
	# use wappanalyzer
	pass

@app.route('/script_scan/<string:ip>')
def script_scan(ip):
	script_scan_worker.delay(ip)
	return redirect(request.referrer)


@app.route('/script_scan/<string:ip>')
def category_script_scan(ip):
	category_script_scan_worker.delay(ip)
	return redirect(request.referrer)


@celery.task(name='app.default_script_scan')
def script_scan_worker(ip):
	nmap_utils.default_script_scan(ip)
	return

@celery.task(name='app.default_script_scan')
def category_script_scan_worker(ip):
	nmap_utils.default_script_scan(ip)
	return


@app.route('/brute-force-credentials/<string:domain>')
def brute_credentials(domain):
	# brute force with brutespray
	pass


@app.route('/test', methods=['POST', 'GET'])
def test():
	host = '128.199.152.172'
	ip_entity = ip_clt.find_one({'ip': host})
	return str(ip_entity)
	# return 'Running.'


if __name__ == '__main__':
	app.debug = True
	app.run()