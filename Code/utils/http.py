import os
import app
import tempfile
from requests import get
from json import dump, loads

# need to check again
out_dir = 'screenshots/'
wapp_analyzer = 'http://localhost.:3000/extract?url='

def get_all_http_serv():
    http_serv = []
    # http_serv_dict = app.ip_clt.find({'scan.tcp.{}.name': 'http'}: {$exists: True})
    ip_scan_inf = app.ip_clt.find({'scan': {'$exists': True}})
    for ip_res in ip_scan_inf:
        for p, s in ip_res['scan'][ip_res['ip']]['tcp'].items():
            if s['name'] == 'http' or s['name'] == 'https':
                http_serv.append({
                    'proto': s['name'], 
                    'ip': ip_res['ip'], 
                    'port': p})

    return http_serv
    # dict: {proto, ip, port}}
    
def get_http_serv(ip):
    http_serv = []
    # http_serv_dict = app.ip_clt.find({'scan.tcp.{}.name': 'http'}: {$exists: True})
    ip_ent = app.ip_clt.find_one({'ip': ip})
    if 'scan' not in ip_ent:
        return http_serv
    
    for p, s in ip_ent['scan'][ip_ent['ip']]['tcp'].items():
        if s['name'] == 'http' or s['name'] == 'https':
            http_serv.append({
                'proto': s['name'], 
                'ip': ip_ent['ip'], 
                'port': p})

    return http_serv

def save_res_to_db(http_serv):
    out_dir = 'screenshots/'
    for s in http_serv:
        file_name = s['proto'] + '_' + s['ip'] + '_' + s['port'] + '.png'
        if os.path.isfile(out_dir + file_name):
            # save to db 
            ip_ent = app.ip_clt.find_one({'ip': s['ip']})
            ip_ent['scan'][s['ip']]['tcp'][s['port']]['screenshot'] = out_dir + file_name

            app.ip_clt.update_one({'_id': ip_ent['_id']}, {'$set': ip_ent})
    return 'Save to db'


def screenshot_list(http_serv):
    f = tempfile.NamedTemporaryFile(mode='w+', delete=False)
    for s in http_serv:
        f.write(s['proto'] + '://' + s['ip'] + ':' + s['port'] + '\n')
    f.close()

    cmd = 'webscreenshot -i {} -o {}'.format(f.name, out_dir)
    save_res_to_db(http_serv)

    os.system(cmd)
    os.remove(f.name)
    return

def screenshot(ip, port, protocol):
    # push ip, port to file
    url = protocol + '://' + ip + ':' + port
    cmd = 'webscreenshot {} -o {}'.format(url, out_dir)
    # update screenshot to db path
    ip_entity = app.ip_clt.find_one({'ip': ip})
    file_name = protocol + '_' + ip + '_' + port + '.png'
    ip_entity['screenshot'] = out_dir + file_name

    app.ip_clt.update_one({'_id': ip_entity['_id']}, {'$set': ip_entity})
    os.system(cmd)
    return

def detect_tech (ip):
    http_serv = get_http_serv(ip)
    urls = {}
    ip_ent = app.ip_clt.find_one({'ip': ip})
    for s in http_serv:
        urls[s['port']] = s['proto'] + '://' + s['ip'] + ':' + s['port']
    
    for p, u in urls.items():
        res = get(wapp_analyzer + u)
        j_data = loads(res.text)
        if (len(j_data['applications']) == 0):
            continue
        # update to db
        ip_ent['scan'][ip]['tcp'][p]['apps'] = j_data['applications']
        
    print ('Update DB ..')
    app.ip_clt.update_one({'ip': ip}, {'$set': ip_ent})
            
    return 