from werkzeug import secure_filename

from flask import *

from flask import *
app = Flask(__name__)
app.secret_key = 'qweoi@#!ASDQWEJKLZXCJ'
app.config['UPLOAD_FOLDER'] = 'upload/'
app.config['MAX_CONTENT_PATH'] = 2048

@app.route('/')
def index():
	return redirect(url_for("subdomain_dashboard"))

@app.route('/dashboard')
def subdomain_dashboard():
	return render_template("subdomain_dashboard.html")