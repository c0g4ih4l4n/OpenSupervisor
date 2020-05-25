import os
from ipwhois import IPWhois
import app
from requests import post
from json import loads
from urllib.parse import quote_plus

api_vuln_key = '25837daf168a1f72927a3d79169a5db8'
VULN_DB_API = 'https://vuldb.com/?api'
proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'https://127.0.0.1:8080'}
    
def cursor_to_json(cursor):
    response = []
    for item in cursor:
        item['_id'] = str(item['_id'])
        if 'subdomain_enum_task_id' in item:
            res = app.celery.AsyncResult(item['subdomain_enum_task_id'])
            item['task_status'] = res.status
        else: 
            item['task_status'] = 'No Task'
        response.append(item)
    return response

def query_vuln(vendor, product, version):
    payload = {'apikey': api_vuln_key, 'advancedsearch': 'vendor:{},product:{},version:{}'.format(vendor, quote_plus(product), version)}

    headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8'}
    print ('Payload: ' + str(payload))
    # res = post(url=VULN_DB_API, data=payload, headers=headers, proxies=proxies, verify=False)
    res = post(url=VULN_DB_API, data=payload, headers=headers)
    print ('Response: ' + str(res))
    res_data = loads(res.text)
    return res_data