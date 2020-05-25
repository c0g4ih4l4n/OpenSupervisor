import os
import app


# need to check again
out_dir = '../screenshots/'

def get_list_http_service():
    http_serv_dict = {}
    app.ip_clt.find()
    # dict: {ip: {protocol: [port]}}
    return

def screenshot(ip, port, protocol):
    # push ip, port to file
    url = protocol + ip + ':' + port
    cmd = 'webscreenshot {} -o {}'.format(url, out_dir)
    # update screenshot to db path
    ip_entity = app.ip_clt.find_one({'ip': ip})
    file_name = protocol + '_' + ip + '_' + port + '.png'
    ip_entity['screenshot'] = out_dir + file_name

    app.ip_clt.update_one({'_id': ip_entity['_id']}, {'$set': ip_entity})
    os.system(cmd)
    return