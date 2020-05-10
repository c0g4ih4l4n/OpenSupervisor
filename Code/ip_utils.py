import os
from ipwhois import IPWhois

def check_alive(ip)):
    response = os.system("ping -c 1 " + ip)
    if response == 0:
        return True
    else:
        return False

# write task schedule for check alive of all domain
def task_schedule_check_alive(domain):
    pass

def whois(ip):
    data = IPWhois(query).lookup_whois()
    return data