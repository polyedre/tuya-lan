"""Platform for sensor integration."""

from homeassistant.helpers.entity import Entity
from homeassistant.components.sensor import PLATFORM_SCHEMA
from pytuya import OutletDevice
from homeassistant.const import POWER_WATT, DEVICE_CLASS_POWER
from homeassistant.const import CONF_IP_ADDRESS, CONF_DEVICE_ID, CONF_API_KEY, CONF_SENSORS
import homeassistant.helpers.config_validation as cv
import voluptuous as vol
import logging
import csv
import os
import asyncio as aio
import sys
import base64
import json
from collections import OrderedDict
from colorsys import hsv_to_rgb, rgb_to_hsv
from Crypto.Cipher import AES
from hashlib import md5
import time
import csv
import threading

SENSORS_FILE = os.environ['HOME'] + "/.homeassistant/custom_components/tuya_lan/.sensors.txt"

# You have to change this
WIFI_SSID = ''
WIFI_PASSWORD = ''

MAXNORESP = 5
DFLTPORT = 6668
DFLTVERS = "3.1"
DISCCNT = 3

log = logging.getLogger(__name__)

_LOGGER = logging.getLogger(__name__)

# Validation of the user's configuration
SENSOR_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_IP_ADDRESS): cv.string,
    vol.Required(CONF_DEVICE_ID): cv.string,
    vol.Required(CONF_API_KEY): cv.string,
})

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {vol.Required(CONF_SENSORS): cv.schema_with_slug_keys(SENSOR_SCHEMA)}
)

def setup_platform(hass, config, add_entities,
                               discovery_info=None):
    """Set up the sensor platform."""

    sensors = []
    _LOGGER.debug("Setuping Tuya Sensors")

    start_background_process()
    time.sleep(10)

    loaded_sensors = load_registered_sensors()
    new_sensors = [s for s in loaded_sensors if not s in sensors]

    _LOGGER.debug("New sensors: %s", new_sensors)
    new_sensors_entities = [TuyaPlug(*s) for s in new_sensors]
    add_entities(new_sensors_entities)

    hass.services.register('tuya_lan', 'sync_plugs', sync_plugs)

def load_registered_sensors():
    sensors = []
    with open(SENSORS_FILE, 'r') as sensor_file:
        data = csv.reader(sensor_file)
        for ip_address, device_id, local_key in data:
            sensors.append((ip_address, device_id, local_key))
    return sensors

class TuyaPlug(Entity):
    """Representation of a Tuya plug sensor."""

    number_of_plug = 0

    def __init__(self, ip_address, device_id, local_key):
        """Initialize the sensor."""
        _LOGGER.debug("Creating Plug(ip=%s, id=%s, key=%s)", ip_address, device_id, local_key)
        self.error_state = 'Not detected'
        self._power = self.error_state
        self._voltage = self.error_state
        self._intensity = self.error_state
        self._state = self.error_state
        self.identifiants = device_id, ip_address, local_key
        self.data = {}
        self.reconnect()
        self._device_class = DEVICE_CLASS_POWER
        TuyaPlug.number_of_plug += 1

    @property
    def name(self):
        """Return the name of the sensor."""
        return 'Tuya Plug {}'.format(TuyaPlug.number_of_plug)

    @property
    def unit_of_measurement(self):
        """Return the unit of measurement."""
        return POWER_WATT

    @property
    def state(self):
        """Return the default state of the plug."""
        return self._power

    @property
    def power(self):
        """Return the power of the plug."""
        return self._power

    @property
    def voltage(self):
        """Return the voltage of the plug."""
        return self._voltage

    @property
    def intensity(self):
        """Return the intensity of the plug."""
        return self._intensity

    def update(self):
        """Fetch new state data for the plug """
        self.data = {}
        for _ in range(3):
            try:
                self.data = self.device.status()
                # _LOGGER.debug(self.data)
                break
            except ConnectionResetError:
                _LOGGER.debug("Failed fetching data for %s, reconnecting...", self.name())
                self.reconnect()
        if self.data:
            # _LOGGER.debug("New data fetched : ", self.data)
            self._power = self.get_power()
            self._voltage = self.get_voltage()
            self._intensity = self.get_intensity()
        else:
            self._power = self.error_state

    def get_intensity(self):
        """Return the intensity in mA"""
        return self.data['dps']['18'] / 10

    def get_power(self):
        """Return the power in Watts"""
        return self.data['dps']['19'] / 10

    def get_voltage(self):
        """Return the voltage in V"""
        return self.data['dps']['20'] / 10

    def reconnect(self):
        """Reconnects to the Device"""
        self.device = OutletDevice(*self.identifiants)

class TuyaException(Exception):
    pass

class TuyaCipher():

    def __init__(self, key, version="3.1"):
        self.key = key
        try:
            self.version = version.encode()
        except:
            print("This is it {}".format(version))
            self.version = version
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def decrypt(self, rawdata):
        if self.version:
            data = base64.b64decode(rawdata[19:])
        else:
            data = rawdata

        data = self.cipher.decrypt(data)
        try:
            return json.loads(data[:data.rfind(b'}')+1])
        except:
            return data

    def encrypt(self, rawdata):
        data=json.dumps(rawdata,separators=(',', ':')).encode()
        if len(data)%16 :
            pbyte = int.to_bytes(16 - len(data)%16, 1, "big")
            data += pbyte * (16 - len(data)%16)

        data = self.cipher.encrypt(data)
        if self.version:
            data = base64.b64encode(data)
        return data, self.md5(data)

    def md5(self,data):
        thisdata = b"data="+data+b"||lpv="+self.version+b"||"+self.key.encode()
        return md5(thisdata).hexdigest().lower()[8:24].encode()


class TuyaMessage():

    def __init__(self, cipher = None):
        self.cipher = cipher
        self.leftover = ""

    def parse(self, data):
        if data is None:
            raise TuyaException("No data to parse")
        if len(data) < 16:
            raise TuyaException("Message too short to be parsed")

        processmsg = True
        result = []

        while processmsg:
            prefix = data[:4]

            if prefix != b'\x00\x00\x55\xaa':
                result.append((999,TuyaException("Incorrect prefix")))
                break

            suffix = data[-4:]

            if suffix != b'\x00\x00\xaa\x55':
                result.append((999, TuyaException("Incorrect suffix")))
                break

            cmdbyte = data[11:12]
            msgsize = int.from_bytes(data[12:16],"big")

            if msgsize != len(data[12:-4]):
                self.leftover = data[16+msgsize:]
                data = data[:16+msgsize]
                _LOGGER.debug("{} vs {}".format(msgsize,len(data[12:-4])))
                _LOGGER.debug("Leftover is {}".format(self.leftover))
            else:
                self.leftover = ''
                processmsg = False


            #Removing Prefix, Msg size, also crc and suffix
            mydata = data[16:-8]
            returncode = int.from_bytes(mydata[:4],"big")
            # _LOGGER.debug("Return Code is {}".format(returncode))
            if returncode:
                _LOGGER.debug("Error: {}".format(data))
            #Removing 0x00 padding
            try:
                while mydata[0:1] == b'\x00':
                    mydata = mydata[1:]
            except:
                #Empty message
                result.append((returncode, None))
                if self.leftover:
                    continue
                else:
                    break

            if self.cipher and cmdbyte != b'\x0a':
                result.append((returncode, self.cipher.decrypt(mydata)))
            else:
                #_LOGGER.debug("Loading {}".format(mydata[:mydata.decode().rfind('}')+1]))
                try:
                    result.append((returncode, json.loads(mydata.decode()[:mydata.decode().rfind('}')+1])))
                except:
                    result.append((returncode, mydata))
        return result

    def encode(self, command, data):
        if command == "get":
            cmdbyte = b'\x0a'
        elif command == 'set':
            cmdbyte = b'\x07'
        else:
            raise TuyaException("Unknown command")

        if isinstance(data, dict):
            payload = json.dumps(data,separators=(',', ':')).encode()
        elif isinstance(data, str):
            payload = data.encode()
        elif isinstance(data,bytes):
            payload = data
        else:
            raise TuyaException("Don't know who to send {}".format(data.__class__))

        prefix = b'\x00\x00\x55\xaa'+ b'\x00'*7 + cmdbyte
        #CRC
        payload += b'\x00'*4   #Apparently not checked, so we dpn't bother
        #Suffix
        payload += b'\x00\x00\xaa\x55'
        try:
            return prefix + int.to_bytes(len(payload),4,"big") + payload
        except Exception as e:
            _LOGGER.debug("Error was {}".format(e))
            return None




class TuyaScanner(aio.DatagramProtocol):
    """This will monitor UDP broadcast from Tuya devices"""

    def __init__(self, parent= None,ip='0.0.0.0', port=6666):
        self.ip = ip
        self.port = port
        self.loop = None
        self.message = TuyaMessage()
        self.task = None
        self.parent = parent

    def connection_made(self, transport):
        _LOGGER.debug("Scanner Connected")
        self.transport = transport
        sock = transport.get_extra_info("socket")  # type: socket.socket
        #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def datagram_received(self, rdata, addr):
        resu =self.message.parse(rdata)
        for code, data in resu:
            # _LOGGER.debug('broadcast received: {}'.format(data))
            if self.parent:
                self.parent.notify(data)

    def start(self, loop):
        """Starting the control of the device
        """
        self.loop = loop
        coro = self.loop.create_datagram_endpoint(
            lambda: self, local_addr= (self.ip, self.port))

        self.task = self.loop.create_task(coro)
        return self.task

    def close(self):
        if self.transport:
            self.transport.close()
            self.transport = None


class TuyaManager:
    """This class manages Tuya devices. It will create devices when notified,
    if will also destroy and recreate them when the IP address changes. It will only create devices
    for which it knows an encryption key

    This works by looking for broadcast packets. If the device type is unknown, we start with a
    generic TuyaDevice set with raw_dps, upon receiving a status we try to figure out what the device
    actually is.

    DEWARE  TuyaManager is used as parent for the generic TuyaDevice, so the method register will be called.
    When overloading register, make sure you understand the consequences

    """

    def __init__(self, knowndevs={}, dev_parent = [], loop = None):
        """ knowndevs should be a dictionary. The key is the device id
            and the value, the encryption key. dev_parent is the device parent,
            with register/unregister/got_data methods
        """
        self.known_devices = knowndevs
        self.running_devices = []
        self.pending_devices = {}
        self.version_devices = {}
        self.ignore_devices = []
        self.error_device = {}
        self.loop = aio.get_event_loop() if loop is None else loop
        self.dev_parent = dev_parent
        self.load_keys()


    def notify(self,data):
        if all([ x in data for x in ["productKey", "ip", "gwId"] ]):
            device = data["ip"], data["gwId"], data["productKey"]

            self.upsert_device(device)
        # _LOGGER.debug(self.running_devices)

    def upsert_device(self, new_device):
        for i, dev in enumerate(self.running_devices):
            if dev[1] == new_device[1]:
                self.running_devices[i] = new_device
                return
        self.running_devices.append(new_device)
        self.save_sensors()

    def save_sensors(self):
        with open(SENSORS_FILE, 'w') as sensor_file:
            data = csv.writer(sensor_file)
            for sensor in self.running_devices:
                _LOGGER.debug("New sensor saved")
                data.writerow(sensor)

    def register(self,dev):
        #Avoid overloading.... it will run when a "pending" device connects
        pass

    def unregister(self,dev):
        #Just delete the pending id
        try:
            del(self.pending_devices[dev.devid])
        except:
            pass

    def new_key(self, devid, key):
        self.known_devices[devid] = key
        if devid in self.ignore_devices:
            self.ignore_devices.remove(devid)
        self.persist_keys()


    def persist_keys(self):
        pass

    def load_keys(self):
        pass


    def got_data(self,data):
        """We are trying to figure out the device type"""
        if "devId" not in data: #Ooops
            return

        if data["devId"] not in self.pending_devices:
            _LOGGER.debug("Oops, devid {} should not sent data here.".format(data["devId"]))
            return

        tclass = None
        discdev = self.pending_devices[data["devId"]]

        if tclass:
            newdev = tclass(discdev.devid, self.known_devices[discdev.devid],discdev.ip, parent = self.dev_parent, vers=self.version_devices[data["devId"]])
            self.running_devices[newdev.devid] = newdev
            newdev.start(self.loop)
        else:
            _LOGGER.debug("No match for {}".format(data))
        self.pending_devices[data["devId"]].seppuku()
        del(self.pending_devices[data["devId"]])

    def got_error(self, dev, data):
        """Looks like we got a problem. Given how we do things, this must be from one of the pending
        devices, i.e. some generic device. Let's try to send a command to see if that fix things."""
        _LOGGER.debug("Got error from {}: {}".format(dev.devid,data))
        if dev.devid not in self.error_device:
            self.error_device[dev.devid] = 0
            #Only the first time around
            dev.raw_set({'1':False})
        elif self.error_device[dev.devid] == 1:
            #Try the second time around
            dev.raw_set({'1':'3'})

        self.error_device[dev.devid] += 1
        if self.error_device[dev.devid]>=5:
            try:
                _LOGGER.debug("Done trying with {}".format(dev.devid))
                self.ignore_devices.append(dev.devid)
                self.pending_devices[dev.devid].seppuku()
                del(self.error_device[dev.devid])
            except Exception as e:
                _LOGGER.debug("Error disabling dev {}, {}".format(dev.devid, e))



    def close(self):
        _LOGGER.debug("On closing we have:")
        _LOGGER.debug("           running : {}".format(self.running_devices))
        _LOGGER.debug("           pending : {}".format(self.pending_devices))
        _LOGGER.debug("          ignoring : {}".format(self.ignore_devices))
        for x in self.pending_devices.values():
            x.seppuku()
        for x in self.running_devices.values():
            x.seppuku()

def fetch_devices():
    """Start the listening process"""
    logging.basicConfig(
            level=logging.DEBUG,
            format='%(levelname)7s: %(message)s',
            stream=sys.stderr,
        )
    loop = aio.new_event_loop()
    aio.set_event_loop(loop)
    manager = TuyaManager()
    scanner = TuyaScanner(parent=manager)
    scanner.start(loop)
    try:
        loop.run_forever()
    except:
        scanner.close()
        manager.close()
        loop.run_until_complete(aio.sleep(2))
        pass

def start_background_process():
    logging.basicConfig(
            level=logging.DEBUG,
            format='%(levelname)7s: %(message)s',
            stream=sys.stderr,
        )
    t = threading.Thread(target=fetch_devices)
    t.start()

import asyncio as aio
import socket
import json
import math
from hashlib import md5
from collections import OrderedDict
import aiohttp, random,string
import logging

PORT = 6668
RPORT = 63145
ADDRESS = ("255.255.255.255", 30011)

APIKEY='kqnykr87uwxn99wcyjvk'
APISECRET = 'm5tsnq9998wjdgunak9upxnyftg873jj'

REGIONMATCH={"america":"AZ","asia":"AY","europe":"EU"}
REGIONURL = {"AZ": 'https://a1.tuyaus.com/api.json',
             'AY': 'https://a1.tuyacn.com/api.json',
             'EU': 'https://a1.tuyaeu.com/api.json'}
SIGNKEY = [ 'a', 'v', 'lat', 'lon', 'lang', 'deviceId', 'imei',
            'imsi', 'appVersion', 'ttid', 'isH5', 'h5Token', 'os',
            'clientId', 'postData', 'time', 'n4h5', 'sid', 'sp']

log = logging.getLogger(__name__)

class TuyaCloud(object):
    """This class describe the minimum needed to interact
    with TuYa cloud so we can link devices
    """
    def __init__(self, email, passwd, region = "america", tz = "+00:00", apikey = APIKEY, apisecret = APISECRET):
        try:
            self.region = REGIONMATCH[region.lower()]
        except:
            raise Exception("Error: Region must be one of {}, not {}".format(REGIONMATCH.keys(),region))

        if len(apikey) != 20:
            raise Exception("Error: API Key must be 20 char long, it is {}.".format(len(apikey)))
        self.key = apikey

        if len(apisecret) != 32:
            raise Exception("Error: API Key must be 32 char long, it is {}.".format(len(apikey)))

        self.secret = apisecret
        self.email = email
        self.password = passwd
        self.tz = tz
        self.sessionid = None
        self.deviceid = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(44))
        self.token = ''
        self.tokensecret = ''


    async def _request(self, command, data):

        def shufflehash(data):
            prehash = md5(data.encode()).hexdigest()
            return prehash[8:16] + prehash[0:8] + prehash[24:32] + prehash[16:24]

        def sortOD(od):
            res = OrderedDict()
            for k, v in sorted(od.items()):
                if isinstance(v, dict):
                    res[k] = sortOD(v)
                else:
                    res[k] = v
            return res

        rawdata = {"a": command,
                 "deviceId": data.get("deviceId",self.deviceid),
                 "os": 'Linux',
                 "lang": 'en',
                 "v": '1.0',
                 "clientId": self.key,
                 "time": round(time()),
                 "postData": json.dumps(data,separators=(',', ':'))}

        if self.sessionid:
            rawdata["sid"] = self.sessionid

        sorteddata = sortOD(rawdata)
        log.debug("Request is {}".format(rawdata))
        tosign = ""
        for key in sorteddata:
            if key not in SIGNKEY or not rawdata[key]:
                continue
            tosign += key + "="
            if key == 'postData':
                tosign += shufflehash(rawdata[key])
            else:
                tosign += str(rawdata[key])
            tosign += "||"
        tosign += self.secret
        rawdata["sign"] = md5(tosign.encode()).hexdigest()
        async with aiohttp.ClientSession() as session:
            async with session.get(REGIONURL[self.region], params=rawdata) as resp:
                rdata = await resp.text()
                rdata = json.loads(rdata)

        if not rdata["success"]:
            myex = Exception("Error in request: Code: {}, Message: {}".format(rdata["errorCode"], rdata["errorMsg"]))
            myex.errcode = rdata["errorCode"]
            raise myex
        log.debug("Response to cloud request: {}".format(rdata["result"]))
        return rdata["result"]


    async def login(self):
        data = {"countryCode": self.region,
                "email": self.email,
                "passwd": md5(self.password.encode()).hexdigest()}

        resu = await self._request( 'tuya.m.user.email.password.login',data)
        self.sessionid = resu["sid"]
        return resu

    async def register(self):
        data = {"countryCode": self.region,
                "email": self.email,
                "passwd": md5(self.password.encode()).hexdigest()}

        resu = await self._request( 'tuya.m.user.email.register',data)
        self.sessionid = resu["sid"]
        return resu

    async def newtoken(self):
        data = {"timeZone": self.tz}
        resu = await self._request( 'tuya.m.device.token.create',data)
        self.token = resu['token']
        self.tokensecret = resu['secret']
        #log.debug("Got new token: {}".format(resu))
        return resu

    async def listtoken(self):
        data = {"token": self.token}
        resu = await self._request('tuya.m.device.list.token',data)
        #log.debug("Got token list: {}".format(resu))
        return resu



class TuyaProvision(aio.DatagramProtocol):

    def __init__(self, tuya = None, ssid = None, passphrase = None):
        self.target = ADDRESS
        self.loop = None
        self.tuya = tuya
        self.ssid = ssid
        self.passphrase = passphrase
        self.abortbroadcast = False
        self.provisiondata = []
        self.devices = []
        self.task = None

    def connection_made(self, transport: aio.transports.DatagramTransport):
        #log.debug('started')
        self.transport = transport
        sock = transport.get_extra_info("socket")  # type: socket.socket
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.loop.create_task(self._provision_devices())

    async def _provision_devices(self):
        await self._tuya_login()
        if not self.provisiondata:
            self.loop.create_task(self.seppuku())
            return

        await self.startbroadcast()
        self.loop.create_task(self.waitinfo())
        await self.sendlinkdata()

    async def _tuya_login(self):
        try:
            try:
                resu = await self.tuya.login()
            except:
                resu = await self.tuya.register()
            resu = await self.tuya.newtoken()
        except:
            await self.seppuku()
            return
        self.provisiondata = self._make_linkdata()

    async def waitinfo(self):
        cnt = 5
        for x in range(200):
            lodevs = await self.tuya.listtoken()
            if lodevs:
                self.loop.stop()
            _LOGGER.debug("LODEVS %s", lodevs)
            if len(lodevs) > len(self.devices):
                self.devices = lodevs
                cnt = 5
            elif cnt == 0:
                self.abortbroadcast = True
                break
            elif len(self.devices):
                cnt -= 1
        self.register()
        await self.seppuku()

    def register(self):
        log.debug(self.devices)

    def datagram_received(self, data, addr):
        #We are not expecting data
        #log.debug('data received:', data, addr)
        pass

    async def startbroadcast(self):
        for x in range(144):
            for s in [1, 3, 6, 10]:
                string="\x00"*s
                self.transport.sendto(string.encode(), self.target)
            await aio.sleep(((x % 8) + 33)/1000.0)
            if self.abortbroadcast:
                log.debug("Broadcast aborted")
                break
        log.debug("Broadcast done")

    async def sendlinkdata(self):
        delay = 0
        for x in range(30):
            if self.abortbroadcast:
                break

            if delay > 26:
                delay = 6

            for s in self.provisiondata:
                string="\x00"*s
                self.transport.sendto(string.encode(), self.target)
                await aio.sleep(delay/1000.0)

            await aio.sleep(0.2)
            delay += 3

        self.abortbroadcast = False

    def _make_linkdata(self):

        def docrc(data):
            crc = 0
            for i in range(len(data)):
                crc = docrc1Byte(crc ^ data[i])
            return crc

        def docrc1Byte(abyte):
            crc1Byte = 0
            for i in range(8):
                if ( crc1Byte ^ abyte ) & 0x01 > 0:
                    crc1Byte ^= 0x18
                    crc1Byte >>= 1
                    crc1Byte |= 0x80
                else:
                    crc1Byte >>= 1
                abyte >>= 1

            return crc1Byte

        barray=bytearray(1)+self.passphrase.encode()
        clen = len(barray)
        barray[0] = clen-1
        lenpass = clen -1
        barray += bytearray(1) + (self.tuya.region+self.tuya.token+self.tuya.tokensecret).encode()
        barray[clen] = len(barray) - clen - 1
        lenrts = len(barray) - clen - 1
        clen = len(barray)
        barray += self.ssid.encode()
        lenssid = len(self.ssid.encode())

        rlen = len(barray)

        edata = []
        log.debug("\nLength are {} {} {}\n".format(lenpass, lenrts, lenssid))
        fstrlen = (lenpass + lenrts + lenssid + 2) % 256
        log.debug("\nStr length is {}".format(fstrlen))
        fstrlencrc = docrc([fstrlen])
        log.debug("\nCRC length is {}".format(fstrlencrc))

        edata.append((fstrlen // 16) | 16)
        edata.append((fstrlen % 16) | 32)
        edata.append((fstrlencrc // 16) | 48)
        edata.append((fstrlencrc % 16) | 64)

        edidx = 0
        seqcnt = 0
        while edidx < rlen:
            crcdata = []
            crcdata.append(seqcnt)
            for idx in range(4):
                crcdata.append(barray[edidx] if edidx < rlen else  0)
                edidx += 1
            crc = docrc(crcdata)
            edata.append((crc % 128) | 128)

            edata.append((seqcnt % 128) | 128)
            #data
            for idx in range(4):
                edata.append((crcdata[idx+1] % 256) | 256)
            seqcnt += 1
        log.debug("Link data is: {}".format(edata))
        return edata

    def start(self, loop):
        self.loop = loop
        coro = self.loop.create_datagram_endpoint(
            lambda: self, local_addr=('0.0.0.0', RPORT))

        self.task = self.loop.create_task(coro)
        return self.task

    async def seppuku(self):
        self.abortbroadcast = True
        await aio.sleep(1)
        self.transport.close()
        #log.debug("Dying")

def sync_plugs(call):
    tuya = TuyaCloud("basic@email.com", "random_pass")
    prov = TuyaProvision(tuya, WIFI_SSID, WIFI_PASSWORD)
    loop = aio.new_event_loop()
    aio.set_event_loop(loop)
    prov.start(loop)
    loop.run_forever()
