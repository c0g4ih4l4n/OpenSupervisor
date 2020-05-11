import os
from ipwhois import IPWhois
import app

def check_alive(ip):
    response = os.system("ping -c 1 " + ip)
    if response == 0:
        return 1
    else:
        return 0

# write task schedule for check alive of all domain
def task_schedule_check_alive(domain):
    pass

def whois(query):
    data = IPWhois(query).lookup_whois()
    return data

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