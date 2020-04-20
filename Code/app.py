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
		domains = domain_collection.find()
		response = db_utils.cursor_to_json(domains)
		return response

	def post(self):
		domain_name = request.form['domain_name']
		org_name = request.form['org_name'] if request.form['org_name'] is not None else ""
		ip = socket.gethostbyname(domain_name)
		new_domain = {"domain_name": domain_name, "org_name": org_name, "ip": ip}
		domain_collection.insert(new_domain)
		return 'OK', 201

class Domain(Resource):
	def get(self, domain_id):
		domains = domain_collection.find({'id': domain_id})
		return domain_collection.find({'id': domain_id})

	def put(self, domain_id):
		return

	def delete(self, domain_id):
		return

class ToDoSimple(Resource):
	def get(self, todo_id):
		return {todo_id: todos[todo_id]}

	def put(self, todo_id):
		todos[todo_id] = request.form['data']
		return {todo_id: todos[todo_id]}

api.add_resource(ToDoSimple, '/<string:todo_id>')
api.add_resource(DomainList, '/domains', endpoint = 'domains')
api.add_resource(Domain, '/domain/<int:domain_id>', endpoint = 'domain')

@app.route('/domains/create')
def create_domain():
	return render_template('domain_create.html')

@app.route('/')
def index():
	return redirect(url_for("domain_dashboard"))

@app.route('/dashboard')
def dashboard():
	return render_template("domain_dashboard.html")

@app.route('/domains')
def domain_dashboard():
	return

if __name__ == '__main__':
	app.debug = True
	app.run()