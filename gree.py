#!/bin/env python
import base64
import socket
import json
import logging
import os
import signal
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


# logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class locker:
    lock = '/tmp/greehvac.lck'

    def __init__(self, s):
        assert not os.path.isfile(self.lock), 'another instance is running ..'
        with open(self.lock, 'a'):
            os.utime(self.lock, None)
        signal.signal(signal.SIGINT, self.rmlck)
        signal.signal(signal.SIGTERM, self.rmlck)
        self.to_kill = s

    def rmlck(self, signum, frame):
        logger.warning(f"got signal: {signum}")
        self.to_kill.disconnect()
        os.unlink(self.lock)

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

def logged(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        logger.debug(f'FUNC: {func.__name__}, args: {args}, kwargs: {kwargs}')
        try:
            return func(*args, **kwargs)
        except:
            logger.exception('%s' % func.__name__)
            raise
    return wrapper

gStatus = {
    'Pow': (0, 1),
    'Mod': (0, 1, 2, 3, 4),
    "SetTem": tuple(range(16, 31)),
    "WdSpd": (0, 1, 2, 3, 4, 5),
    "Air": (0, 1),
    "Blo": ("Blow", "X-Fan"),
    "Health": (0, 1),
    "SwhSlp": (0, 1),
    "Lig": (0, 1),
    "SwingLfRig": (0, 1, 2, 3, 4, 5, 6),
    "SwUpDn": (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11),
    "Quiet": (0, 1, 2), # 发现2才是静音，好像要同时调节风速
    "Tur": (0, 1),
    # "StHt":,
    "TemUn": (0, 1),
    # "HeatCoolType":,
    "TemRec": (0, 1),
    "SvSt": (0, 1),
}

@logged
def paramTest(params, values=None):
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
        while not(self.isconnect()):
            continue
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
        #logger.debug(f"encrypted: {encrypted}")
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
        #logger.debug(f"decrypted: {decrypted}")
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
                    logger.exception(e)
                    logger.error("Don't find hvac.")
                else:
                    break
    
    def isconnect(self):
        data_ = {"t": "scan"}
        data = json.dumps(data_)
        return self.senddata(data)

    def senddata(self, data: str):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(10)
        # logger.debug("sending data: %s" % data.encode())
        self.sock.sendto(data.encode(), (self.hvac_host, 7000))
        data=None
        try:
            data = json.loads(self.sock.recv(1024).decode())
        except:
            logger.warning("timeout")
        self.sock.close()
        return data

    def sendpack(self, pack_: dict, i):
        pack = json.dumps(pack_)
        logger.debug(f"sending pack: {pack}")
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
        #logger.debug("got data: %s" % data_get)
        pack_get = self.decrypt(data_get['pack'])
        pack_get_ = json.loads(pack_get)
        logger.debug(f"got pack: {pack_get_}")
        return pack_get_

    def getbaseinfo(self):
        data_ = {"t": "scan"}
        data = json.dumps(data_)
        baseinfo = self.senddata(data)
        logger.debug(f"ac baseinfo: {baseinfo}")
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
        logger.debug(f"current {p}: {status}")
        return status

    def checkAllCurStatus(self, p=None):
        '''
        检查所有参数当前的值
        p: list, 1个或多个空调参数, 为None时自动获取所有gStatus里面的key
        '''
        p = p if p is not None else list(gStatus.keys())
        _pack = self.gp.packIt(p, type=0)
        status = self.g.sendcom(_pack)["dat"]
        status = dict(zip(p,status))
        logger.debug(f"current status: {status}")
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
    
    @logged
    def setCmd(self, cmd, value):
        """
        set one ac command at a time
        cmd: string
        value: int
        """
        if cmd in self.simpleCmds:
            r = self.checkAndSend([cmd], [value])
            return r[0]
        elif cmd == 'SetTem':
            r = self.checkAndSend(["TemUn", "SetTem"], [0, value])
            return r[-1]

@logged
def publish_message(data, topic, mqttc):
    logger.info(f"publish on {topic}")
    mqttc.publish(topic, data)

@logged
def on_message(client, userdata, msg):
    logger.info(f"Message from topic: {msg.topic}, payload: {msg.payload}")

    chvac=userdata['chvac']
    topic=userdata['topic']
    sub_topics = [f'{topic}{sub}' for sub in ('/cmd/set', '/cmd/get', '/get')]

    if msg.topic == sub_topics[2]:
        logger.debug(f"sub topic: {sub_topics[-1]}")
    elif msg.topic == sub_topics[1]:
        ac_status = json.dumps(chvac.checkAllCurStatus())
        publish_message(ac_status, sub_topics[2], client)
    else:
        logger.debug("cmd topic")
        parent = os.path.dirname(msg.topic)
        cmd = os.path.basename(msg.topic)
        value = int(msg.payload)
        for var in (parent, cmd, value):
            logger.debug(f"var: {var}")
        if parent == sub_topics[0]:
            logger.debug(f"sub topic: {sub_topics[0]}")
            # 执行指令并发布对应状态
            ac_response = chvac.setCmd(cmd, value)
            response_topic = os.path.join(sub_topics[1], cmd)
            publish_message(ac_response, response_topic, client)
            # 发布AC当前所有状态
            ac_status = json.dumps(chvac.checkAllCurStatus())
            publish_message(ac_status, sub_topics[2], client)
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
    logger.debug(f"init arguments: {args}")
    if args.debug: logger.setLevel(logging.DEBUG)
    chvac = gController(args.hvac)
    mqttc = gMqtt()
    locker(mqttc)
    mqttc.on_message = on_message
    mqttc.connect(args.broker, int(args.port), args.topic,
                  args.username, args.password, args.tls, args.selfsigned, args.selfsignedfile, {'chvac': chvac})
    logger.info("Gree-mqtt Running")
    mqttc.loop_forever()

if __name__ == "__main__":
    main()
