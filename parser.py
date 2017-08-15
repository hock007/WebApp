import requests
import traceback
import json

class JsonParser:



    def __init__(self):
        pass

    def get_responce(self):
        status = True
        content = ""
        base_url = 'http://0.0.0.0:5000/get_survey'

        try:
            resp = requests.get(base_url)
            content = resp.content
        except Exception as exp:
            print('get_responce() :: Got exception: %s' %exp)
        return status, content

    def get_survey(self, resp):
        try:
            for item in resp:
                title = item['title']
                print '--------------title', title
                _id = item['_id']
                print 'id:',  _id
                # key1 = item['key1']
                # print 'key1---------', key1
                # key2 = item['key2']
                # print 'key2', key2
                # key3 = item['key3']
                # print 'key3', key3
                # key4 = item['key4']
                # print 'key4', key4
                # key5 = item['key5']
                # print 'key5', key5
                # value1 = item['value1']
                # print'value', value1
        except Exception as exp:
            print('get_survey () :: Got exception: %s' % exp)

    def get_all(self):

        jsonparser = JsonParser()
        print '+++++++++++++++++++++++++++++++++++++++++++'
        resp = content['survey']
        print 'get data all ::  %s' % resp
        j = jsonparser.get_survey(resp)
        print '++++++++++++++++++++========================get_all()', j
if __name__ == '__main__':
    jsonparser = JsonParser()
    jsonparser.get_responce()
    status, data = jsonparser.get_responce()
    content = json.loads(data)
    print '++++++++++++++++++', content
    if status:
        resp = content['survey']
        jsonparser.get_survey(resp)
    jsonparser.get_all()
