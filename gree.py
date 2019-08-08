import base64
import socket
import json
import logging
from functools import wraps
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
try:
    import netifaces
except:
    nonetifaces=True
else:
    nonetifaces=False


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
    'Pow': (0,1),
    'Mod': (0,1,2,3,4),
    #"SetTem":, 
    "WdSpd": (0,1,2,3,4,5), 
    "Air": (0,1), 
    "Blo": ("Blow","X-Fan"), 
    "Health": (0,1), 
    "SwhSlp": (0,1), 
    "Lig": (0,1), 
    "SwingLfRig": (0,1,2,3,4,5,6), 
    "SwUpDn": (0,1,2,3,4,5,6,7,8,9,10,11), 
    "Quiet": (0,1), 
    "Tur": (0,1), 
    # "StHt":, 
    # "TemUn":, 
    # "HeatCoolType":, 
    "TemRec": (0,1), 
    "SvSt": (0,1),
}

def paramTest(params, values=None):
    logger.debug('opt parameters: %s, values: %s' % (params, values))
    assert params != [], 'opt parameters not set'
    assert set(params) <= set(gStatus.keys()), 'invalid opt parameters'
    if values is not None:
        for k,v in zip(params, p):
            assert v in gStatus[k], 'invalid opt values'

class gPack():
    def __init__(self, mac):
        self.mac = mac
    
    @logged
    def packIt(self, cols:list, type=0, p=None):
        """
        creates a pack
        type0: reading status of a device
        type1: controlling a device 
        """
        if type == 0:
             return {"cols":cols, "mac": self.mac, "t": "status"}
        elif type == 1:
            assert p is not None, 'opt values not set'
            return {"opt":cols, "p": p, "t": "cmd"}


class Gree():
    def __init__ (self,hvac_host=0,key=0):
        """init and get hvac key"""
        self.hvac_host=hvac_host
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.BLOCK_SIZE=16 #pad block size
        defaultkey='a3K8Bx%2r8Y7#xDh'
        self.cipher = AES.new(defaultkey.encode(), AES.MODE_ECB)
        self.baseinfo=self.getbaseinfo()
        if key==0:
            self.key=self.getkey(self.baseinfo.get("mac"))
        else:
            self.key=key
        self.cipher = AES.new(self.key.encode(), AES.MODE_ECB)


    def encrypt(self,data:str,key=0):
        """encrypt data"""
        if key:
            cipher = AES.new(key.encode(), AES.MODE_ECB)
        else:
            cipher = self.cipher
        utfdata=data.encode()
        paded=pad(utfdata,self.BLOCK_SIZE)
        encrypted=cipher.encrypt(paded)
        logger.debug(encrypted)
        baseed=base64.b64encode(encrypted)
        return baseed.decode()
    def decrypt(self,data:str,key=0):
        """decrypt data"""
        if key:
            cipher = AES.new(key.encode(), AES.MODE_ECB)
        else:
            cipher = self.cipher
        debase=base64.b64decode(data.encode())
        decrypted=cipher.decrypt(debase)
        logger.debug(decrypted)
        unpaded=unpad(decrypted,self.BLOCK_SIZE)
        strdata=unpaded.decode()
        return strdata


    def senddata(self,data:str):
        if self.hvac_host==0:
            """scan hvac"""
            broadcast=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            broadcast.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if  nonetifaces:
                broadcast.sendto('{"t":"scan"}'.encode(),("255.255.255.255",7000))
            else:
                broadcastip=[]
                cars=netifaces.interfaces()
                try:
                    cars.remove('lo')
                except:
                    pass
                for car in cars:
                    broadcastip.append(netifaces.ifaddresses(car)[netifaces.AF_INET][0].get('broadcast'))
                for ip in broadcastip:
                    broadcast.sendto('{"t":"scan"}'.encode(),(ip,7000))
            addr=broadcast.recvfrom(1024)[1]
            broadcast.close()
            self.hvac_host=addr[0]

        logger.debug(data)
        self.sock.sendto(data.encode(),(self.hvac_host,7000))
    def getdata(self):
        return json.loads(self.sock.recv(1024).decode())
    def sendpack(self,pack_:dict,i):
        pack=json.dumps(pack_)
        data_={
            "cid":"app",
            "i":i,
            "pack":self.encrypt(pack),
            "t":"pack",
            "tcid":self.baseinfo.get("mac"),
            "uid":0
        }
        data=json.dumps(data_)
        logger.debug(data)
        self.senddata(data)
    def getpack(self):
        data=self.getdata()
        logger.debug(data)
        pack = self.decrypt(data['pack'])
        logger.debug(pack)
        pack_=json.loads(pack)
        return pack_
    def getbaseinfo(self):
        data_ = {"t":"scan"}
        data=json.dumps(data_)
        self.senddata(data)
        baseinfo=self.getdata()
        logger.info("ac baseinfo: %s " % baseinfo)
        return json.loads(self.decrypt(baseinfo['pack']))
    def getkey(self,mac):
        pack={
            "mac":mac,
            "t":"bind",
            "uid":0
        }
        self.sendpack(pack,1)
        key=self.getpack()['key']
        return key
    def sendcom(self,pack:dict):
        self.sendpack(pack,0)
        return self.getpack()


class gController():
    def __init__(self,hvac_host):
        self.g = Gree(hvac_host)
        mac = self.g.baseinfo.get("mac")
        self.gp = gPack(mac)
    
    def OnOffSwitch(self):
        _pack = self.gp.packIt(["Pow"], type=0)
        curStatus = self.g.sendcom(_pack)['dat'][0]
        s = 1 if curStatus == 0 else 0
        _pack = self.gp.packIt(["Pow"], type=1, p=[s])
        self.g.sendcom(_pack)
    




