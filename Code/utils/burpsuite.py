# import the package
from PyBurprestapi import burpscanner
from requests import get

# setup burp connection
host = 'http://127.0.0.1:1337/'

# Burp API key
key = 'XNKy1NyCohRpa5M3svxcGU8XaSxr8u31'

# importing host and key
bi = burpscanner.BurpApi(host, key)

def scan(url):
    data = '{"urls":["' + url + '"]}'

    res = bi.scan(data)
    if res.message == 'OK':
        task_id = res.response_headers['Location']
        return task_id
    else:
        return None

# build db to save scan with burpsuite

# check url exists
def check_exist(url):
    return False

def get_result(task_id):
    url = host + key + '/v0.1/scan/' + str(task_id)
    res = get(url)
    return res

# Get response header (Scan ID found in Location)
# print response.response_headers