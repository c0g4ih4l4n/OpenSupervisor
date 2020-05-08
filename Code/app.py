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

from crontab import CronTab
from bson import json_util
import json
import domain_utils
from bson.json_util import dumps

import nmap_utils


from flask_celery import make_celery

import subdomain_enum_osint
import subdomain_enum_bruteforce


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
dm_clt = mongo.db.domain

api = Api(app)

todos = {}
celery = make_celery(app)






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
		
		new_domain = {"domain_name": domain_name, "org_name": org_name, "ips": ip_list, 'wild_card': wild_card, "brute_force": brute_force}
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







api.add_resource(DomainListAPI, '/targets', endpoint = 'api.domains')
api.add_resource(SubDomainAPI, '/targets/<string:domain_name>', endpoint = 'api.subdomain')

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

@app.route('/targets/<string:domain_name>/scan')
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





@app.route('/ip_scan/<string:ip>', endpoint='ip_scan')
def ip_scan(ip):

	pass


@app.route('/visualization/<string:domain>')
def visualization(domain):
	# screen shot with aquatone and rename file + change location
	pass

@app.route('/postscan/<string:ip>')
def portscan(ip):
	# scan with 2 modules
	portscan(ip)
	pass

@celery.task(name='app.ip_scan')
def ip_scan(domain):
	subdomain_enum_osint.osint_update(domain)
	return

@app.route('/servicescan/<string:ip>')
def service_scan(ip):
	# run scan with service scan

	# detect web technology with whatweb
	# use wappanalyzer
	pass

@app.route('/scriptscan/<string:ip>')
def script_scan(ip):

	pass

@app.route('/brute-force-credentials/<string:domain>')
def brute_credentials(domain):
	# brute force with brutespray
	pass

if __name__ == '__main__':
	app.debug = True
	app.run()