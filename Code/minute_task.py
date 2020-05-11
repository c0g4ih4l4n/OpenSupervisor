import app
import ip_utils

# check host alive in list targets
def check_host():
    list_ip = app.ip_clt.find({})

    for ip in list_ip:
        status = ip_utils.check_alive(ip)
        ip['status'] = status

        app.db.getCollection('ip').update(
            {"ip": ip},
            {'$set': {'status': status} }
        )
    pass

if __name__ == '__main__':
    print ('Checking Host Alive ...')
    check_host()