from flask import Flask, render_template, request, redirect, send_file, session, abort
import time
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_cors import CORS
import sys
import os
import random
import string
import datetime
from flask_sqlalchemy import SQLAlchemy
from PIL import Image, ImageDraw

from typing import Optional
import sqlalchemy as sa
import sqlalchemy.orm as so

from drawer import *
from io import BytesIO

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(256)
app.config.update(
	SESSION_REFRESH_EACH_REQUEST=True,
	SESSION_COOKIE_NAME="session",
	#SQLALCHEMY_DATABASE_URI = "sqlite:///" + basedir + "/sql.db"
	SQLALCHEMY_DATABASE_URI = "postgresql://root:root@postgres:11111/missions"
)
CORS(app, supports_credentials=True)

def rnd_pwd():
	return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(60))

db = SQLAlchemy(app)
class Mission(db.Model):
	#id: so.Mapped[int] = so.mapped_column(primary_key=True)
	name: so.Mapped[str] = so.mapped_column(sa.String(100), primary_key=True, index=True)
	short: so.Mapped[str] = so.mapped_column(sa.String(120))
	secret: so.Mapped[str] = so.mapped_column(sa.String(64))
	data: so.Mapped[str] = so.mapped_column(sa.String(1024000))
	created: so.Mapped[datetime.datetime] = so.mapped_column(db.DateTime(timezone=False))
	def __init__(self, name, secret, short):
		self.name = name
		self.short = short
		self.secret = secret
		self.data = ""
		self.authenticated = False
		self.created = datetime.datetime.now()
		
	def is_authenticated(self):
		return self.authenticated
	
	def is_active(self):
		return True
	
	def is_anonymous(self):
		return False
	
	def get_id(self):
		return self.name

with app.app_context():
	db.create_all() # TODO only on first start?

	query = sa.select(Mission)
	missions = db.session.scalars(query).all()
	if len(missions) == 0:
		m1 = Mission(name="Mr. R", secret="a", short="Collect information about Mr. R")
		db.session.add(m1)
	db.session.commit()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = None

@app.before_request
def make_session_permanent():
    session.permanent = True


@app.route('/api/create', methods=["POST"])
def create():
	j = request.json
	if "name" not in j or "short" not in j:
		return {"error": "Please provide all data"}, 400
	name = j["name"]
	short = j["short"]
	secret = rnd_pwd()
	if len(name) > 90 or len(short) > 110:
		return {"error": "Too long"}, 400
	a = db.session.get(Mission, name)
	if a != None:
		return {"error": "already exists"}, 400
	m = Mission(name=name, secret=secret, short=short)
	db.session.add(m)
	db.session.commit()
	m.authenticated = True
	login_user(m)
	
	limit = datetime.datetime.now() - datetime.timedelta(minutes=32)
	x = db.session.query(Mission).filter(Mission.created<limit).delete()
	db.session.commit()
	return {"error": None, "secret": secret}, 200
	
@app.route('/api/missions')
def get_missions():
	query = sa.select(Mission)
	missions = db.session.scalars(query).all()
	j = [
		{"name": m.name, "text": m.short}
		for m in missions
	]
	db.session.close()
	return j, 200

@app.route('/api/missioninfo/<mission>')
@login_required
def get_mission_info(mission):
	query = sa.select(Mission)
	missions = db.session.scalars(query).all()
	for m in missions:
		if m.name == mission:
			return m.short
	db.session.close()
	return {"error": "hm?"}

@app.route('/api/add_data', methods=['POST'])
@login_required
def add_data():
	j = request.json
	data = j['data']
	if len(data) > 100:
		return {"error": "Too long"}, 400
	current_user.data += data
	db.session.commit()
	return "OK"

@app.route('/api/get_data', methods=['POST'])
@login_required
def get_data():
	j = request.json
	if "secret" not in j:
		return {"error": "Please provide your secret for extra security"}, 400
	secret = j['secret']
	if current_user.secret == secret:
		d = {
			"name": current_user.name,
			"short": current_user.short,
			"data": current_user.data
		}
		#db.session.close()
		return d
	else:
		return {"error": "Please provide your secret for extra security"}, 400

@app.route('/api/authenticate', methods=['POST'])
def login():
	j = request.json
	if "mission" not in j or "secret" not in j:
		abort(403)
	mission = j['mission']
	secret = j['secret']
	
	uc = db.session.get(Mission, mission)
	if uc == None:
		abort(404)
	if secret != uc.secret:
		db.session.close()
		return abort(403)

	uc.authenticated = True
	login_user(uc)
	db.session.close()
	return ""#redirect('/secret')

@app.route("/api/logout")
@login_required
def logout():
	current_user.authenticated = False
	logout_user()
	db.session.commit()
	return "Logged out"

@app.route('/imgs/<name>')
def imgs(name):
	if not name.endswith(".png"):
		return "", 404
	img = draw_label(name[:-4])
	img_io = BytesIO()
	img.save(img_io, 'PNG')
	img_io.seek(0)
	return send_file(img_io, mimetype='image/png')
 
@login_manager.user_loader
def load_user(mission):
	m = db.session.get(Mission, mission)
	return m

@app.after_request
def set_response_headers(response):
	if request.method == "OPTIONS": # TODO can we remove this?
		response.headers.remove("Set-Cookie")
	return response

if __name__ == '__main__':
	app.run(threaded=False, processes=100,debug=False,host='0.0.0.0')
