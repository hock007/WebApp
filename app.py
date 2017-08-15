from flask import Flask, request, make_response, render_template, jsonify,\
                    session, url_for, redirect
from flask.ext.bcrypt import Bcrypt
import time
from datetime import datetime, timedelta
import jwt
import os
import datetime
from functools import wraps
import traceback
from db import Mdb
from wtforms.fields import SelectField
from flask_admin import Admin, BaseView, expose
from flask_admin.contrib.sqla import ModelView
import json
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user

from bson.objectid import ObjectId

app = Flask(__name__, static_path='/static')
bcrypt = Bcrypt(app)
mdb = Mdb()

app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'


#############################################
#                                           #
#        _id of mongodb record was not      #
#           getting JSON encoded, so        #
#           using this custom one           #
#                                           #
#############################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


@app.route('/create_survey')
def survey():
    templateData = {'title': 'create_survey'}
    return render_template('create_survey.html', **templateData)


@app.route('/')
def home():
    templateData = {'title': 'Login Page'}
    return render_template('index.html', session=session)


@app.route('/whoami')
def whoami():
    ret = {'error': 0}
    try:
        sumSessionCounter()
        ret['User'] = (" hii i am %s !!" % session['name'])
    except Exception as exp:
        ret['error'] = 1
        ret['user'] = 'user is not login'
    return json.dumps(ret)


@app.route('/signup')
def signin():
    templateData = {'title': 'Signup Page'}
    return render_template('signup.html', session=session)


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})

        return f(*args, **kwargs)

    return decorated


# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #
#                                           #
#        NOT USING THIS AT THE MOMENT       #
#                                           #
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX #
@app.route('/login_old')
def login_old():
    auth = request.authorization

    if auth and auth.password == 'password':
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        token = jwt.encode({'user': auth.username, 'exp': expiry},
                           app.config['secretkey'], algorithm='HS256')
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('Could not verify!', 401,
                         {'WWW-Authenticate': 'Basic realm="Login Required"'})


#############################################
#                                           #
#                  ADD USER                 #
#                                           #
#############################################
@app.route("/add_user", methods=['POST'])
def add_user():
    try:
        user = request.form['user']
        email = request.form['email']
        password = request.form['password']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        mdb.add_user(user, email, pw_hash)
        print('User is added successfully')
        templateData = {'title': 'Signin Page'}
    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return render_template('index.html', session=session)


#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/login', methods=['POST'])
def login():

    ret = {'err': 0}

    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print 'password in server, get from db class', pw_hash
            passw = bcrypt.check_password_hash(pw_hash, password)

            print 'get status=======================', passw

            if passw == True:

                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email
                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)
                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')

                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
                templateData = {'title': 'singin page'}
            else:
                return render_template('index.html', session=session)

        else:
            # Login Failed!
            return render_template('index.html', session=session)

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

        LOGIN_TYPE = 'User Login'
        email = session['email']
        user_email = email
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    # return jsonify(ret)
    return render_template('welcome.html', session=session)


#############################################
#                                           #
#                   ADD FORM                #
#                                           #
#############################################
@app.route("/user_form", methods=['POST'])
def user_form():
    try:
        print '+++++++++++++++++++++', request.form
        user_id = request.form['user_id']
        key = request.form['key']
        value = request.form['value']
        mdb.user_form(user_id, key, value)
        print('User form is added successfully')
        templateData = {'title': 'form Page'}
    except Exception as exp:
        print('User form() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return render_template('form.html', session=session)


#############################################
#                                           #
#                SAVE SURVEY                #
#                                           #
#############################################
@app.route("/save_survey", methods=['POST'])
def save_survey():

    # survery dictionary to be saved in db
    survey = {}

    try:

        title = request.form['title']
        rowCount = int(request.form['rowCount'])

        survey['title'] = title
        survey['rowCount'] = rowCount

        # adding all keys/values in form dict
        for i in range(1, rowCount+1):
            print "Reading Key%d" % i
            try:
                survey['key%d' % i] = rowCount = request.form['key%d' % i]
                survey['value%d' % i] = rowCount = request.form['value%d' % i]
            except:
                print "Key%d not  found" % i

        print "survey: ", survey

        # saving survey in db
        mdb.add_survey(survey)

        return "Survery Saved"

    except Exception as exp:
        print(traceback.format_exc())
        return "Failed to Save Survery, Exception: %s" % exp


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################
@app.route('/clear')
def clearsession():
    try:
        LOGIN_TYPE = 'User Logout'
        sumSessionCounter()
        email = session['email']
        print '=========', email
        user_email = email
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, ip, agent, LOGIN_TYPE)
        session.clear()
        return render_template('index.html', session=session)
    except Exception as exp:
        return 'Clearsession() :: Got Exception: %s' % exp


#############################################
#                                           #
#                GET SURVEY                 #
#                                           #
#############################################
@app.route("/get_surveys", methods=['GET'])
def get_surveys():
    surveys = mdb.get_surveys()
    templateData = {'title': 'Surveys', 'surveys': surveys}
    return render_template('get_survey.html', **templateData)


@app.route("/create_response", methods=['GET'])
def create_response():
    id = request.args.get("id")
    survey = mdb.get_survey(id)
    templateData = {'title': 'Survey Response', 'survey': survey}
    return render_template('create_response.html', **templateData)


@app.route('/save_response', methods=['POST'])
def save_response():
    response = {}
    try:
        id = request.form['survey_id']
        rowCount = int(request.form['rowCount'])
        response['id'] = id
        response['rowCount'] = rowCount

        for i in range(1, (rowCount+1) ):
            try:
                response['value%d' % i] = request.form['value%d' % i]
            except:
                print "Key%d not  found" % i

        mdb.save_response(response)
    except Exception as exp:
        print('save_response() :: Got exception: %s' % exp)
        print(traceback.format_exc())
    return 'save Response successfully'


@app.route('/get_info')
def get_info():
    try:
        LOGIN_TYPE = 'User Login'
        sumSessionCounter()
        email = session['email']
        user_email = email
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')

        mdb.save_login_info(user_email, ip, agent, LOGIN_TYPE)
        return 'User_email: %s, IP: %s, ' \
               'User-Agent: %s' % (user_email, ip, agent, LOGIN_TYPE)
    except Exception as exp:
        print('get_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return ('get_info() :: Got exception: %s is '
                'not found Please Login first' % exp)


#############################################
#                                           #
#                  MAIN SERVER              #
#                                           #
#############################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
