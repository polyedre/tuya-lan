#!/usr/bin/env python3
# -*- coding:utf-8 -*-
#
# This module provides a library to control Tuya devices over the LAN
# The various devices expose the functions of the devices in a developper-friendly
# way. Note that in order to be able to set the devices, a key must be lnown. the
# key can be aquired by using the provisioning functions.
#
# Copyright (c) 2019 François Wautier
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies
# or substantial portions of the Software.
#
# Portion of this code is covered by the following license
#
# Copyright 2003 Paul Scott-Murphy, 2014 William McBrine
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
# IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
# USA
#
# Modified by Lucas HENRY

import sys
import logging
import os

import asyncio as aio
import base64
import json
from collections import OrderedDict
from colorsys import hsv_to_rgb, rgb_to_hsv
from Crypto.Cipher import AES
from hashlib import md5
from time import time
import csv
import threading

SENSORS_FILE = os.environ['HOME'] + "/.homeassistant/custom_components/tuya_lan/.sensors.txt"

MAXNORESP = 5
DFLTPORT = 6668
DFLTVERS = "3.1"
DISCCNT = 3

log = logging.getLogger(__name__)

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
                log.debug("{} vs {}".format(msgsize,len(data[12:-4])))
                log.debug("Leftover is {}".format(self.leftover))
            else:
                self.leftover = ''
                processmsg = False


            #Removing Prefix, Msg size, also crc and suffix
            mydata = data[16:-8]
            returncode = int.from_bytes(mydata[:4],"big")
            log.debug("Return Code is {}".format(returncode))
            if returncode:
                log.debug("Error: {}".format(data))
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
                #log.debug("Loading {}".format(mydata[:mydata.decode().rfind('}')+1]))
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
            log.debug("Error was {}".format(e))
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
        log.debug("Scanner Connected")
        self.transport = transport
        sock = transport.get_extra_info("socket")  # type: socket.socket
        #sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def datagram_received(self, rdata, addr):
        resu =self.message.parse(rdata)
        for code, data in resu:
            log.debug('broadcast received: {}'.format(data))
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
        log.debug(self.running_devices)

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
            log.debug("Oops, devid {} should not sent data here.".format(data["devId"]))
            return

        tclass = None
        discdev = self.pending_devices[data["devId"]]

        if tclass:
            newdev = tclass(discdev.devid, self.known_devices[discdev.devid],discdev.ip, parent = self.dev_parent, vers=self.version_devices[data["devId"]])
            self.running_devices[newdev.devid] = newdev
            newdev.start(self.loop)
        else:
            log.debug("No match for {}".format(data))
        self.pending_devices[data["devId"]].seppuku()
        del(self.pending_devices[data["devId"]])

    def got_error(self, dev, data):
        """Looks like we got a problem. Given how we do things, this must be from one of the pending
        devices, i.e. some generic device. Let's try to send a command to see if that fix things."""
        log.debug("Got error from {}: {}".format(dev.devid,data))
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
                log.debug("Done trying with {}".format(dev.devid))
                self.ignore_devices.append(dev.devid)
                self.pending_devices[dev.devid].seppuku()
                del(self.error_device[dev.devid])
            except Exception as e:
                log.debug("Error disabling dev {}, {}".format(dev.devid, e))



    def close(self):
        log.debug("On closing we have:")
        log.debug("           running : {}".format(self.running_devices))
        log.debug("           pending : {}".format(self.pending_devices))
        log.debug("          ignoring : {}".format(self.ignore_devices))
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
    print("Called")
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

if __name__ == '__main__':
    logging.basicConfig(
            level=logging.DEBUG,
            format='%(levelname)7s: %(message)s',
            stream=sys.stderr,
        )
