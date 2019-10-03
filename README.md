# Gree-mqtt
A Gree air-conditioning control tool on Linux.

### Install
    chmod +x install.sh && ./install.sh
### Usage
    gree [-h] [--hvac-host HVAC] [-c CONFIG] [-b BROKER] [-p PORT]
                [-t TOPIC] [-u USERNAME] [-P PASSWORD] [--tls]
                [--selfsigned SELFSIGNED] [--selfsignedfile SELFSIGNEDFILE]
                [--debug]

    optional arguments:
      -h, --help            show this help message and exit
      --hvac-host HVAC      hvac host ip (default: auto scan)
      -c CONFIG, --config CONFIG
                            config file
      -b BROKER, --mqtt-broker BROKER
                            mqtt broker ip
      -p PORT, --mqtt-port PORT
                            mqtt broker port (default: 1883/8883)
      -t TOPIC, --mqtt-topic TOPIC
                            mqtt broker topic(default: home/greehvac)
      -u USERNAME, --username USERNAME
                            mqtt username
      -P PASSWORD, --password PASSWORD
                            mqtt password
      --tls
      --selfsigned SELFSIGNED
                            selfsigned
      --selfsignedfile SELFSIGNEDFILE
                            selfsignedfile
      --debug
### Requirements
    Python 3.x
    Netifaces 0.10.9
    Paho-MQTT 1.4.0
    Pycryptodome 3.8.2
