from __future__ import print_function
from openvas_lib import VulnscanManager, VulnscanException, report_parser
from threading import Semaphore
from functools import partial


HOST = '192.168.33.11'
USER = 'admin'
PASSWORD = 'admin'
PORT = 9390
TIMEOUT = 10

try:
    scanner = VulnscanManager(HOST, USER, PASSWORD, PORT, TIMEOUT)
except VulnscanException as e:
    print("Error:")
    print(e)

# simple scan
def luanch_simple_scanner(target):
    scan_id, target_id = scanner.launch_scan(target = target, # Target to scan
                                         profile = "Full and fast")
    return scan_id, target_id

# get result
def get_results(scan_id):
    openvas_results = scanner.get_results(scan_id)
    return

def parse_result(result_file):
    results = report_parser(result_file)
    r = None
    for x in results:
        if x.id == '':
            r = x

    # result

    

# delete scan
def del_scan(scan_id):
    scanner.delete_scan(scan_id)
    return

# delete target
def del_target(target_id):
    scanner.delete_target(target_id)
    return

def print_status(i):
    print(str(i))

def launch_scanner(target):
    sem = Semaphore(0)

    # Configure
    manager = VulnscanManager(HOST, USER, PASSWORD, PORT, TIMEOUT)

    # Launch
    manager.launch_scan(target,
                        profile = "empty",
                        callback_end = partial(lambda x: x.release(), sem),
                        callback_progress = print_status)

    # Wait
    sem.acquire()

    # Finished scan
    print("finished")