from coapthon.client.helperclient import HelperClient

host = "2a05:d014:faa:5500:6ff9:8389:cf03:f3c1"
port = 5683
path ="basic"

client = HelperClient(server=(host, port))
payload = "Hallo"
client.post(path,payload)
#print (response.pretty_print())
client.stop()
