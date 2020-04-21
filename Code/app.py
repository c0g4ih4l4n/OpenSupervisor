# from werkzeug import secure_filename

import socket
from flask import *

from flask import *
from flask_restful import Resource, Api
from flask import jsonify
from flask_pymongo import PyMongo
import pymongo
import urllib
import json
import db_utils
from crontab import CronTab
from bson import json_util
import json
import domain_utils

app = Flask(__name__)
app.url_map.strict_slashes = False
app.secret_key = 'qweoi@#!ASDQWEJKLZXCJ'
app.config['UPLOAD_FOLDER'] = 'upload/'
app.config['MAX_CONTENT_PATH'] = 2048
app.config['SQLALCHEMY_DATABASE_URI'] = ''
mongo_user = "admin_db"
mongo_password = "long@2020"

app.config["MONGO_URI"] = "mongodb://%s:%s@192.168.33.10:27017/ThesisDB" % (mongo_user, urllib.parse.quote(mongo_password))

mongo = PyMongo(app)

# client = MongoClient("mongodb://%s:%s@192.168.33.10:27017" % (mongo_user, mongo_password))  # host uri
# db = client.ThesisDB  # Select the database
domain_collection = mongo.db.domain

api = Api(app)

todos = {}

class DomainList(Resource):
	def get(self):
		headers = {'Content-Type': 'text/html'}
		domains = domain_collection.find()
		domains_json = db_utils.cursor_to_json(domains)
		return make_response(render_template('domain_dashboard.html', domains=domains_json), 200, headers)

	def post(self):
		domain_name = request.form['domain_name']
		org_name = request.form['org_name'] if request.form['org_name'] is not None else ""
		ip_list = domain_utils.resolve(domain_name)
		wild_card = domain_utils.check_subdomain_wildcard(domain_name)
		new_domain = {"domain_name": domain_name, "org_name": org_name, "ips": ip_list, 'wild_card': wild_card}
		domain_collection.insert(new_domain)
		return 'OK', 201

class Domain(Resource):
	def get(self, domain_id):
		domains = domain_collection.find({'id': domain_id})
		return domain_collection.find({'id': domain_id})

	def put(self, domain_id):
		domain = domain_collection.find({'id': domain_id})
		domain['domain_name'] = request.form['domain_name']
		domain['org_name'] = request.form['org_name']
		domain['ip_list'] = domain_utils.resolve(domain_name)
		domain['wild_card'] = domain_utils.check_subdomain_wildcard(domain_name)
		domain_collection.update_one({'_id' : domain._id, {'$set': domain}})
		return 'OK', 200

	def delete(self, domain_id):
		domain_collection.remove({'_id': domain_id})
		return

api.add_resource(DomainList, '/domains', endpoint = 'domains')
api.add_resource(Domain, '/domain/<int:domain_id>', endpoint = 'domain')

@app.route('/api/domains/list')
def domain_list():
	# headers = {'Content-Type': 'application/json'}
	domains = domain_collection.find()
	domains_json = db_utils.cursor_to_json(domains)
	return jsonify(domains_json)

@app.route('/domains/create')
def create_domain():
	return render_template('domain_create.html')

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
def dashboard():
	return render_template("domain_dashboard.html")

if __name__ == '__main__':
	app.debug = True
	app.run()

@app.route('/visualization/<string:domain>')
def visualization(domain):
	# screen shot with aquatone and rename file + change location

	pass

@app.route('/postscan/<string:ip>')
def portscan(ip):
	# scan with 2 modules
	pass

@app.route('/servicescan/<string:ip>')
def servicescan(ip):
	# run scan with service scan

	# detect web technology with whatweb
	# use wappanalyzer
	pass

@app.route('/brute-force-credentials/<string:domain>')
def brute_credentials(domain):
	# brute force with brutespray
	pass