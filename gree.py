import base64
import socket
import json
import logging
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
try:
    import netifaces
except:
    nonetifaces = True
else:
    nonetifaces = False
import mqtt
import argparse
import time


# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def logged(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.info('running %s' % func.__name__)
        try:
            return func(*args, **kwargs)
        except:
            logger.exception('%s' % func.__name__)
            raise
    return wrapper


gStatus = {
    'Pow': (0, 1),
    'Mod': (0, 1, 2, 3, 4),
    "SetTem": tuple(range(17, 31)),
    "WdSpd": (0, 1, 2, 3, 4, 5),
    "Air": (0, 1),
    "Blo": ("Blow", "X-Fan"),
    "Health": (0, 1),
    "SwhSlp": (0, 1),
    "Lig": (0, 1),
    "SwingLfRig": (0, 1, 2, 3, 4, 5, 6),
    "SwUpDn": (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
    "Quiet": (0, 1),
    "Tur": (0, 1),
    # "StHt":,
    "TemUn": (0, 1),
    # "HeatCoolType":,
    "TemRec": (0, 1),
    "SvSt": (0, 1),
}


def paramTest(params, values=None):
    logger.debug('opt parameters: %s, values: %s' % (params, values))
    assert params != [], 'opt parameters not set'
    assert set(params) <= set(gStatus.keys()), 'invalid opt parameters'
    if values is not None:
        for k, v in zip(params, values):
            assert v in gStatus[k], 'invalid opt values'


class gPack():
    def __init__(self, mac):
        self.mac = mac

    def packIt(self, cols: list, type=0, p=None):
        """
        creates a pack
        type0: reading status of a device
        type1: controlling a device 
        """
        if type == 0:
            return {"cols": cols, "mac": self.mac, "t": "status"}
        elif type == 1:
            assert p is not None, 'opt values not set'
            return {"opt": cols, "p": p, "t": "cmd"}


class Gree():
    def __init__(self, hvac_host=None, key=0):
        """init and get hvac key"""
        self.hvac_host = hvac_host
        self.BLOCK_SIZE = 16  # pad block size
        defaultkey = 'a3K8Bx%2r8Y7#xDh'
        self.cipher = AES.new(defaultkey.encode(), AES.MODE_ECB)
        self.baseinfo = self.getbaseinfo()
        if key == 0:
            self.key = self.getkey(self.baseinfo.get("mac"))
        else:
            self.key = key
        self.cipher = AES.new(self.key.encode(), AES.MODE_ECB)

    def encrypt(self, data: str, key=0):
        """encrypt data"""
        if key:
            cipher = AES.new(key.encode(), AES.MODE_ECB)
        else:
            cipher = self.cipher
        utfdata = data.encode()
        paded = pad(utfdata, self.BLOCK_SIZE)
        encrypted = cipher.encrypt(paded)
        logger.debug(encrypted)
        baseed = base64.b64encode(encrypted)
        return baseed.decode()

    def decrypt(self, data: str, key=0):
        """decrypt data"""
        if key:
            cipher = AES.new(key.encode(), AES.MODE_ECB)
        else:
            cipher = self.cipher
        debase = base64.b64decode(data.encode())
        decrypted = cipher.decrypt(debase)
        logger.debug(decrypted)
        unpaded = unpad(decrypted, self.BLOCK_SIZE)
        strdata = unpaded.decode()
        return strdata

    def senddata(self, data: str):
        if self.hvac_host == None:
            """scan hvac"""
            broadcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if nonetifaces:
                broadcast.sendto('{"t":"scan"}'.encode(),
                                 ("255.255.255.255", 7000))
            else:
                broadcastip = []
                cars = netifaces.interfaces()
                try:
                    cars.remove('lo')
                except:
                    pass
                for car in cars:
                    broadcastip.append(netifaces.ifaddresses(
                        car)[netifaces.AF_INET][0].get('broadcast'))
                for ip in broadcastip:
                    broadcast.sendto('{"t":"scan"}'.encode(), (ip, 7000))
            addr = broadcast.recvfrom(1024)[1]
            broadcast.close()
            self.hvac_host = addr[0]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        logger.debug(data)
        self.sock.sendto(data.encode(), (self.hvac_host, 7000))

    def getdata(self):
        data = json.loads(self.sock.recv(1024).decode())
        self.sock.close()
        return data

    def sendpack(self, pack_: dict, i):
        pack = json.dumps(pack_)
        data_ = {
            "cid": "app",
            "i": i,
            "pack": self.encrypt(pack),
            "t": "pack",
            "tcid": self.baseinfo.get("mac"),
            "uid": 0
        }
        data = json.dumps(data_)
        logger.debug(data)
        self.senddata(data)

    def getpack(self):
        data = self.getdata()
        logger.debug(data)
        pack = self.decrypt(data['pack'])
        logger.debug(pack)
        pack_ = json.loads(pack)
        return pack_

    def getbaseinfo(self):
        data_ = {"t": "scan"}
        data = json.dumps(data_)
        self.senddata(data)
        baseinfo = self.getdata()
        logger.info("ac baseinfo: %s " % baseinfo)
        return json.loads(self.decrypt(baseinfo['pack']))

    def getkey(self, mac):
        pack = {
            "mac": mac,
            "t": "bind",
            "uid": 0
        }
        self.sendpack(pack, 1)
        key = self.getpack()['key']
        return key

    def sendcom(self, pack: dict):
        self.sendpack(pack, 0)
        return self.getpack()


class gController():
    def __init__(self, hvac_host=None):
        self.g = Gree(hvac_host)
        mac = self.g.baseinfo.get("mac")
        self.gp = gPack(mac)

    def checkCurStatus(self, p):
        _pack = self.gp.packIt([p], type=0)
        status = self.g.sendcom(_pack)["dat"][0]
        logger.info("current %s: %s" % (p, status))
        return status

    @logged
    def checkAndSend(self, cols, v):
        paramTest(cols, v)
        _pack = self.gp.packIt(cols, type=1, p=v)
        self.g.sendcom(_pack)

    def OnOffSwitch(self):
        curStatus = self.checkCurStatus("Pow")
        s = 1 if curStatus == 0 else 0
        self.checkAndSend(["Pow"], [s])

    def setTem(self, tem):
        curStatus = self.checkCurStatus("SetTem")
        if tem != curStatus:
            self.checkAndSend(["TemUn", "SetTem"], [0, tem])

    def setMode(self, mode=0):
        curStatus = self.checkCurStatus("Mod")
        if mode != curStatus:
            self.checkAndSend(["Mod"], [mode])


def on_message(client, userdata, msg):
    pass

def publish_message(data,mqttc,t):
    topic=t+"/get"
    mqttc.publish(topic,data)

def main():
    parser = argparse.ArgumentParser(description='Gree Mqtt')
    parser.add_argument("--hvac-host", dest="hvac",
                        help="hvac host ip (default: auto scan)", default=None)
    parser.add_argument("-b", "--mqtt-broker",
                        dest="broker", help="mqtt broker ip")
    parser.add_argument("-p", "--mqtt-port", dest="port",
                        help="mqtt broker port (default: 1883/8883)", default=0)
    parser.add_argument("-t", "--mqtt-topic", dest="topic",
                        help="mqtt broker topic(default: home/greehvac)", default="home/greehvac")
    parser.add_argument("-u", "--username", type=str,
                        dest="username", help="mqtt username", default=None)
    parser.add_argument("-P", "--password", type=str, dest="password",
                        help="mqtt password", default=None)
    parser.add_argument("--tls", dest="tls", action='store_true')
    parser.add_argument("--selfsigned", dest="selfsigned",
                        help="selfsigned", default=False)
    parser.add_argument("--selfsignedfile", dest="selfsignedfile",
                        help="selfsignedfile", default=None)
    args = parser.parse_args()
    mqttc = mqtt.gMqtt()
    mqttc.on_message = on_message
    mqttc.connect(args.broker, int(args.port), args.topic,
                  args.username, args.password, args.tls, args.selfsigned, args.selfsignedfile)
    mqttc.loop_start()
    chvac = gController()
    while True:
        status={}
        for i in gStatus.keys():
            status[i]=chvac.checkCurStatus(i)
        publish_message(json.dumps(status),mqttc,args.topic)
        time.sleep(10)


if __name__ == "__main__":

    main()
