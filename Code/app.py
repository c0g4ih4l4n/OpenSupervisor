# from werkzeug import secure_filename

from flask import *

from flask import *
from flask_restful import Resource, Api
from flask import jsonify
from flask_pymongo import PyMongo


app = Flask(__name__)
app.secret_key = 'qweoi@#!ASDQWEJKLZXCJ'
app.config['UPLOAD_FOLDER'] = 'upload/'
app.config['MAX_CONTENT_PATH'] = 2048
app.config['SQLALCHEMY_DATABASE_URI'] = ''

mongo_user = 'admin_db'
mongo_password = 'long@2020'

app.config["MONGO_URI"] = "mongodb://%s:%s@192.168.33.10:27017" % (mongo_user, mongo_password)
mongo = PyMongo(app)

domain_collection = mongo.db.domain

# client = MongoClient("mongodb://%s:%s@192.168.33.10:27017" % (mongo_user, mongo_password))  # host uri
# db = client.ThesisDB  # Select the database
# domain_collection = db.domain

api = Api(app)

todos = {}

class DomainList(Resource):
	def get(self):
		return list(domain_collection.find({}))

	def post(self):
		data = request.form['data']
		new_domain = {"id": 1}
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