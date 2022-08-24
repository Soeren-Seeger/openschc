import sys
import json
from subprocess import Popen
import atexit


data = {}
end_devices = []
routing_processes = []

def init(uri):
    f = open(uri)
    data = json.load(f)

def start(interface, url):
    for adr, conf in data['route'].items():
        if conf['ifname'] == 'lpwan':
            end_devices.append(adr)

    for device in end_devices:
        dst = 'dst ' + device
        process = Popen(['./packet_picker.py', '-i', interface, url, '--untrust', '-d', '-F', dst],
                        shell=False)
        routing_processes.append(process)





def stop():
    sys.exit()

def cleanup():
    for p in routing_processes:
        p.kill()
    print("IMPORTANT: All listeners stopped!")

atexit.register(cleanup)
