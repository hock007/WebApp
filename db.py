from pymongo import MongoClient
from config import *
from flask import jsonify
import traceback
import json
import datetime
from bson import ObjectId


#############################################
#                                           #
#                                           #
#              DATABASE CLASS               #
#                                           #
#############################################
class Mdb:

    def __init__(self):
        # conn_str = "mongodb://%s:%s@%s:%d/%s" \
        #        % (DB_USER, DB_PASS, DB_HOST, DB_PORT, AUTH_DB_NAME)

        conn_str = "mongodb://appdbuser1:" \
                   "appdbuser1@ds157712.mlab.com:57712/heroku_188g0kct"
        client = MongoClient(conn_str)
        self.db = client['heroku_188g0kct']

#############################################
#                                           #
#        GET NAME ACCORDING TO EMAIL        #
#                                           #
#############################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['user']
                email = data['email']
        return name

    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['user']
                password = data['password']
                print 'password in db class', password
        return password

#############################################
#                                           #
#            ADD USER IN DATABASE           #
#                                           #
#############################################
    def add_user(self, user, email, password):
        try:
            rec = {
                'user': user,
                'email': email,
                'password': password
            }
            self.db.user.insert(rec)

        except Exception as exp:
            print "add_user() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#            ADD FORM IN DATABASE           #
#                                           #
#############################################
    def user_form(self, user_id, key, value):
        try:
            rec = {
                'user_id': user_id,
                'key': key,
                'value': value
            }
            self.db.survey_form.insert(rec)

        except Exception as exp:
            print "user_form() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#           CHECK USER IN DATABASE          #
#                                           #
#############################################
    def user_exists(self, email):
        """
        function checks if a user with given email and password
        exists in database
        :param email: email of the user
        :param password: password of the user
        :return: True, if user exists,
                 False, otherwise
        """
        return self.db.user.find({'email': email}).count() > 0

#############################################
#                                           #
#            ADD SURVEY IN DATABASE         #
#                                           #
#############################################
    def add_survey(self, survey):
        self.db.survey.insert(survey)


#############################################
#                                           #
#            USER SESSION IN DATABASE       #
#                                           #
#############################################
    def save_login_info(self, user_email, ip, user_agent, type):
        LOGIN_TYPE = 'User Login'
        try:
            ts = datetime.datetime.utcnow()

            rec = {
                'user_email': user_email,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': type,
                'timestamp': ts
            }

            self.db.user_session.insert(rec)
        except Exception as exp:
            print "save_login_info() :: Got exception: %s", exp
            print(traceback.format_exc())


#############################################
#                                           #
#                 GET SURVEY                #
#                                           #
#############################################
    def get_surveys(self):
        collection = self.db["survey"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

    def get_survey(self, _id):
        collection = self.db["survey"]
        result = collection.find( { '_id': ObjectId(_id) } )
        for data in result:
            return data

    def save_response(self, response):
        self.db.responses.insert(response)


if __name__ == "__main__":
    mdb = Mdb()

    ###################################################
    #                                                 #
    #             Quick internal tests                #
    #                                                 #
    ###################################################

    # lets write some users
    # mdb.add_user('johny', 'johny@gmail.com', '123')
    # print "user created"

    # lets show all users
    # for user in mdb.db.user.find():
    #    print "User: ", user

    # if mdb.user_exists('johny@gmail.com', '123'):
    #    print "User exists"
    # else:
    #    print "User does not exists"

    # testing
    # mdb.register('john', 'john@gmail.con', 'jonny', '123', '123')
    """
    if mdb.user_exists('tom@gmail.com', '123'):
        print 'user exist'
    else:
        print 'user does not exist'
    """
    # mdb.get_name('gaurav@gmail.com')
    # mdb.save_login_info('id_123', '192.168.0.1', 'tom', 'User Logout')
    mdb.get_survey()
