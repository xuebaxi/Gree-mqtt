#!/bin/env python
import base64
import socket
import json
import logging
import os
from sys import argv
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
try:
    import netifaces
except:
    nonetifaces = True
else:
    nonetifaces = False
import argparse
import time
import paho.mqtt.client as mqtt
import ssl


class gMqtt(mqtt.Client):
    def __init__(self):
        super().__init__()

    def connect(self, host: str, port=0, topic='home/greehvac', username=None, password=None, tls=False, isselfsigned=False, selfsignedfile=None, userdata={}):
        if port == 0:
            """Default port"""
            if tls:
                port = 8883
            else:
                port = 1883
        if tls:
            if selfsignedfile:
                if selfsignedfile == None:

                    super().tls_set(cert_reqs=ssl.CERT_NONE)
                else:
                    super().tls_set(ca_certs=selfsignedfile)
            else:
                super().tls_set()
        if username:
            super().username_pw_set(username, password)
        userdata['topic'] = topic
        super().user_data_set(userdata)
        super().connect(host, port)

    def on_connect(self, client, userdata, flags, rc):
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        topic = userdata['topic']+"/cmd/#"
        client.subscribe(topic)


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
        if hvac_host is None:
            self.scanHvac()
        else:
            self.hvac_host = hvac_host
        logger.debug("hvac host: %s" % self.hvac_host)
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
        logger.debug("encrypted: %s" % encrypted)
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
        logger.debug("decrypted: %s" % decrypted)
        unpaded = unpad(decrypted, self.BLOCK_SIZE)
        strdata = unpaded.decode()
        return strdata

    @logged
    def scanHvac(self):
        """scan hvac"""
        cmd = '{"t":"scan"}'.encode()
        netmask, port = '255.255.255.255', 7000

        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as broadcast:
                broadcast.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                broadcast.settimeout(0)
                if nonetifaces:
                    broadcast.sendto(cmd,(netmask,port))
                else:
                    broadcastip = []
                    cars = [c for c in netifaces.interfaces() if c != 'lo']
                    for car in cars:
                        ifbc = netifaces.ifaddresses(car)[netifaces.AF_INET][0].get('broadcast')
                        broadcastip.append(ifbc)
                    for ip in broadcastip:
                        broadcast.sendto(cmd, (ip, port))
                try:
                    time.sleep(5)
                    addr = broadcast.recvfrom(1024)[1]
                    self.hvac_host = addr[0]
                except BaseException as e:
                    logger.debug(e)
                    logger.info("Don't find hvac.")
                else:
                    break

    def senddata(self, data: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(100)
        logger.debug("sending data: %s" % data.encode())
        self.sock.sendto(data.encode(), (self.hvac_host, 7000))
        data=None
        try:
            data = json.loads(self.sock.recv(1024).decode())
        except:
            logger.info("timeout")
        self.sock.close()
        return data

    def sendpack(self, pack_: dict, i):
        pack = json.dumps(pack_)
        logger.debug("sending pack: %s" % pack)
        data_ = {
            "cid": "app",
            "i": i,
            "pack": self.encrypt(pack),
            "t": "pack",
            "tcid": self.baseinfo.get("mac"),
            "uid": 0
        }
        data = json.dumps(data_)
        data_get = self.senddata(data)
        logger.debug("got data: %s" % data_get)
        pack_get = self.decrypt(data_get['pack'])
        logger.debug("got pack: %s" % pack_get)
        pack_get_ = json.loads(pack_get)
        return pack_get_

    def getbaseinfo(self):
        data_ = {"t": "scan"}
        data = json.dumps(data_)
        baseinfo = self.senddata(data)
        logger.debug("ac baseinfo: %s " % baseinfo)
        return json.loads(self.decrypt(baseinfo['pack']))

    def getkey(self, mac):
        pack = {
            "mac": mac,
            "t": "bind",
            "uid": 0
        }        
        key = self.sendpack(pack, 1)['key']
        return key

    def sendcom(self, pack: dict):      
        return self.sendpack(pack, 0)


class gController():
    simpleCmds = {
        "Pow",        # power on and off
        "Mod",        # mode of operation: 0:auto, 1:cool, 2:dry, 3:fan, 4:heat
        "WdSpd",      # fan speed
        # "Air",      # not available on all units, uncomment it if your device supports it 
        # "Health",   # not available on all units, uncomment it if your device supports it 
        "SwhSlp",     # sleep mode
        "Lig",        # led light
        "SwingLfRig", # horizontal swing mode
        "SwUpDn",     # vertical swing mode
        "Quiet",      # Quiet mode
        "SvSt"        # energy saving mode
    }

    def __init__(self, hvac_host=None):
        self.g = Gree(hvac_host)
        mac = self.g.baseinfo.get("mac")
        self.gp = gPack(mac)

    def checkCurStatus(self, p):
        '''
        检查一个参数当前的值
        p: string, 空调参数
        '''
        _pack = self.gp.packIt([p], type=0)
        status = self.g.sendcom(_pack)["dat"][0]
        logger.info("current %s: %s" % (p, status))
        return status

    def checkAllCurStatus(self, p):
        '''
        检查所有参数当前的值
        p: list, 空调参数
        '''
        _pack = self.gp.packIt(p, type=0)
        status = self.g.sendcom(_pack)["dat"]
        logger.info("current %s: %s" % (p, status))
        return status

    @logged
    def checkAndSend(self, cols, v):
        '''
        检查即将发送的参数和值是否在有效范围内，并发送到AC
        cols: list, 空调参数
        v: list, 空调参数值
        return: response json
        '''
        paramTest(cols, v)
        _pack = self.gp.packIt(cols, type=1, p=v)
        return self.g.sendcom(_pack)['val']
    
    def rotateAndSend(self, cmd):
        next_value = self.checkCurStatus(cmd) + 1
        v = gStatus[cmd][0] if next_value > gStatus[cmd][-1] else next_value
        self.checkAndSend([cmd], [v])
    
    @logged
    def setCmd(self, cmd, value):
        """
        set one ac command at a time
        """
        if cmd in self.simpleCmds:
            v = int(value)
            r = self.checkAndSend([cmd], [v])
            return r[0]
        elif cmd == 'SetTem' and value == b'upTem':
            next_tem = self.checkCurStatus("SetTem")+1
            v = gStatus["SetTem"][-1] if next_tem > gStatus["SetTem"][-1] else next_tem
            r = self.checkAndSend(["TemUn", "SetTem"], [0, v])
            return r[-1]
        elif cmd == 'SetTem' and value == b'downTem':
            next_tem = self.checkCurStatus("SetTem")-1
            v = gStatus["SetTem"][0] if next_tem < gStatus["SetTem"][0] else next_tem
            r = self.checkAndSend(["TemUn", "SetTem"], [0, v])
            return r[-1]

def publish_message(data, topic, mqttc):
    mqttc.publish(topic, data)

def on_message(client, userdata, msg):
    logger.debug("msg.payload: %s" % msg.payload) # 0 or 1
    logger.debug("msg.topic: %s" % msg.topic) # home/greehvac/cmd/set/Pow 

    chvac=userdata['chvac']
    topic=userdata['topic']
    sub_topics = [f'{topic}{sub}' for sub in ('/cmd/set', '/cmd/get', '/get')]

    if msg.topic == sub_topics[-1]:
        logger.debug(f"sub topic: {sub_topics[-1]}")
        pass
    else:
        logger.debug("cmd topic")
        parent = os.path.dirname(msg.topic)
        cmd = os.path.basename(msg.topic)
        for var in (parent, cmd):
            logger.debug(f"var: {var}")
        if parent == sub_topics[0]:
            logger.debug(f"sub topic: {sub_topics[0]}")
            ac_response = chvac.setCmd(cmd, msg.payload)
            response_topic = os.path.join(sub_topics[1], cmd)
            publish_message(ac_response, response_topic, client)
        elif parent == sub_topics[1]:
            logger.debug(f"sub topic: {sub_topics[1]}")

def main():
    if len(argv) == 1:
        argv.append('-h')
    parser = argparse.ArgumentParser(description='Gree Mqtt')
    parser.add_argument("--hvac-host", dest="hvac",
                        help="hvac host ip (default: auto scan)", default=None)
    parser.add_argument("-c", "--config", help="config file",
                        dest='config', default=None)
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
    parser.add_argument("--debug", dest="debug", action='store_true')
    args = parser.parse_args()
    if args.config:
        with open(args.config) as f:
            config = json.load(f)
            args.hvac = config.get("hvac", None)
            args.broker = config.get("broker")
            args.port = config.get("port", 0)
            args.topic = config.get("topic", "home/greehvac")
            args.username = config.get("username", None)
            args.password = config.get("password", None)
            args.tls = config.get("tls", False)
            args.selfsigned = config.get("selfsigned", False)
            args.selfsigned = config.get("selfsignedfile", None)
            args.debug = config.get("debug", False)
    logger.debug("init arguments: %s" % args)
    if args.debug: logger.setLevel(logging.DEBUG)
    chvac = gController(args.hvac)
    mqttc = gMqtt()
    mqttc.on_message = on_message
    mqttc.connect(args.broker, int(args.port), args.topic,
                  args.username, args.password, args.tls, args.selfsigned, args.selfsignedfile, {'chvac': chvac})
    logger.info("running")
    mqttc.loop_forever()

if __name__ == "__main__":
    main()
