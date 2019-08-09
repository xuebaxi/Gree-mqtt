import paho.mqtt.client as mqtt
import ssl


class gMqtt(mqtt.Client):
    def __init__(self):
        super().__init__()

    def connect(self, host: str, port=0, topic='home/greehvac', username=None, password=None, tls=False, isselfsigned=False, selfsignedfile=None,userdata={}):
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
        userdata['topic']=topic
        super().user_data_set(userdata)
        super().connect(host, port)

    def on_connect(self,client, userdata, flags, rc):
        # Subscribing in on_connect() means that if we lose the connection and
        # reconnect then subscriptions will be renewed.
        topic = userdata['topic']+"/cmd/#"
        client.subscribe(topic)
