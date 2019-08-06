import base64
import socket
from Crypto.Cipher import AES
import json
from Crypto.Util.Padding import pad,unpad
class Gree():
    def __init__ (self,hvac_host,key=0):
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
        #print(encrypted)
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
        #print(decrypted)
        unpaded=unpad(decrypted,self.BLOCK_SIZE)
        strdata=unpaded.decode()
        return strdata


    def senddata(self,data:str):
        #print(data)
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
        #print(data)
        self.senddata(data)
    def getpack(self):
        data=self.getdata()
        #print(data)
        pack = self.decrypt(data['pack'])
        pack_=json.loads(pack)
        return pack_
    def getbaseinfo(self):
        data_ = {"t":"scan"}
        data=json.dumps(data_)
        self.senddata(data)
        baseinfo=self.getdata()
        #print(baseinfo)
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
