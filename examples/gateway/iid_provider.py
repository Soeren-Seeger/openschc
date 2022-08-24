from Cryptodome.Hash import CMAC as cmac
from Cryptodome.Cipher import AES

class dev_iid_provider:

    def __init__(self, prefix):
        self.prefix = prefix
        pass

    # credits: json-parser-project openSCHC - see Github.com
    def getdeviid(self, AppSKey, DevEUI):
        cobj = cmac.new(bytes.fromhex(AppSKey), ciphermod=AES)
        cobj.update(bytes.fromhex(DevEUI))
        res = cobj.hexdigest()
        iid = res[0:16]
        return iid

    def calc(self, AppSKey, DevEUI):
        iid = self.getdeviid(AppSKey, DevEUI)
        ip = self.prefix + ":" + str(iid)[0:4] + ":" + str(iid)[4:8] + ":" + str(iid)[8:12] + ":" + str(
            iid)[12:16]
        return ip


if __name__ == '__main__':
    p = "2001:8d8:1801:84dd"
    ask = "A4B643FFF8F9489A6A03D5CE1F666F55"
    eui = "70B3D54992678665"
    dip = dev_iid_provider(p)
    print(dip.calc(ask, eui))