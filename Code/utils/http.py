import os
import app
import tempfile

# need to check again
out_dir = 'screenshots/'

def get_all_http_serv():
    http_serv = []
    # http_serv_dict = app.ip_clt.find({'scan.tcp.{}.name': 'http'}: {$exists: True})
    ip_scan_inf = app.ip_clt.find({'scan': {'$exists': True}})
    for ip_res in ip_scan_inf:
        for p, s in ip_res['scan'][ip_res['ip']]['tcp'].items():
            if s['name'] == 'http' or s['name'] == 'https':
                http_serv.append({'proto': s['name'], 'ip': ip_res['ip'], 'port': p})

    return http_serv
    # dict: {proto, ip, port}}

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

def tech_detect (http_serv):
    url_list = []
    for s in url_list:
        # whatweb
        continue
    return