from WanRouter import WanRouter
import time

wr = WanRouter('testgw1-config.json')


wr.start('ens192', 'https://localhost:51225/dl')
time.sleep(10)
wr.stop()