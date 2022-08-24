import sys
import json
from subprocess import Popen
import atexit

f = open('conf.json')
data = json.load(f)

end_devices = []
routing_processes = []

def start(interface, url):
    for adr, conf in data['route'].items():
        if conf['ifname'] == 'lpwan':
            end_devices.append(adr)

    for device in end_devices:
        process = Popen(["packet_picker.py", "-i", interface, url, '--untrust', '-d', '-F', "\'dst", device, "\'"],
                        shell=False)
        routing_processes.append(process)

def stop():
    sys.exit()

def cleanup():
    for p in routing_processes:
        p.kill()
    print("IMPORTANT: All listeners stopped!")

atexit.register(cleanup)
