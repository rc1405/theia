#!/usr/bin/env python
'''
   Copyright 2017 Ryan M Cote

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

import yaml
import os
import zmq
import os
import re
from time import time, sleep
import sys
import msgpack
from cryptography.fernet import Fernet
from multiprocessing import Process
import struct
import os
import socket
import platform
import subprocess
import ctypes
from fcntl import ioctl


IFF_PROMISC = 0x100
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
    
    
class _ifreq(ctypes.Structure):
    _fields_ = [("ifr_ifrn", ctypes.c_char * 16),
                ("ifr_flags", ctypes.c_short)]


def _promisc(s, iface):
    freq = _ifreq()
    freq.ifr_ifrn = iface
    ioctl(s.fileno(), SIOCGIFFLAGS, freq)
    freq.ifr_flags |= IFF_PROMISC
    ioctl(s.fileno(), SIOCSIFFLAGS, freq)
    
    
class TheiaSniffer(Process):
    def __init__(self, conf, iface, send_url='ipc://.agent-receiver'):
        Process.__init__(self)
        self.conf = conf
        self.iface = iface
        self.send_url = send_url
        
    def run(self):
        
        bpf = '(not (host {} and port {}))'.format(
            self.conf['destination']['name'],
            self.conf['destination']['port']
        )

        if self.conf['packet_filter']:
            bpf = bpf + "and ({})".format(self.conf['packet_filter'])



        def add_filter(s, bpf, iface):
            
            tcmd = subprocess.Popen('which tcpdump', shell=True, stdout=subprocess.PIPE)
            tcmd, err = tcmd.communicate()
            
            if err:
                raise IOError("No tcpdump found")
                
            tcmd = tcmd.replace('\n','')
            
            tdump = subprocess.Popen([
                tcmd,
                '-i',
                iface,
                '-ddd',
                '-s',
                '1600',
                bpf
            ],
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE
            )
            results, err = tdump.communicate()
            if err:
                raise IOError('Error Calling tcpdump')
                
            results = results.split('\n')
            ct = int(results[0])
            st_bpf = ''
            for row in results[1:]:
                if len(row.split()) == 0:
                    continue
                st_bpf += struct.pack("HBBI", *map(long, row.split(' ')))
        
            if platform.architecture()[0] == '64bit':
                padding = 36
            else:
                padding = 20
        
            s.setsockopt(1, 26, struct.pack("HL", ct, id(st_bpf)+padding))       

               
        ins = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        ins.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)

        add_filter(ins, bpf, self.iface)

        _promisc(ins, self.iface)

        ins.bind((self.iface, 3))

        pkts = []
        # count = 0
        
        context = zmq.Context()
        sender = context.socket(zmq.PUSH)
        sender.connect(self.send_url)

        sleep(2)
        while True:
            pkt = ins.recv(65565)
            sender.send(pkt)    

        
class TheiaEncryptedSender(Process):
    def __init__(self, conf, key, recv_url=['ipc://.agent-workers'], send_url=['ipc://.server-receiver'], MAIN=False):
        Process.__init__(self)
        self.conf = conf
        self.key = key
        self.MAIN = MAIN
        self.recv_url = recv_url
        self.send_url = send_url
        
    def run(self):
        encrypt = Fernet(self.key).encrypt
        context = zmq.Context()
        receiver = context.socket(zmq.PULL)
        if self.MAIN:
            for s in self.recv_url:
                receiver.bind(s)
        else:
            for s in self.recv_url:
                receiver.connect(s)
            
        sender = context.socket(zmq.PUSH)
        for s in self.send_url:
            sender.connect(s)
            
        packets = []
        packet_ct = 0
        
        mdumps = msgpack.dumps
        sname = self.conf['sensor_name']
        packet_start = int(time())
        
        while True:
            if receiver.poll(1000):
                pkt = receiver.recv()
                packets.append(pkt)
                packet_ct += 1
            if (int(time()) - packet_start) >= 5 and packet_ct > 0:
                    sender.send(encrypt(mdumps({
                        "sensor": sname,
                        "packets": packets
                    })))
                    del packets
                    packets = []
                    packet_ct = 0
                    packet_start = int(time())
        
        
class TheiaProxy(Process):
    def __init__(self, conf, recv_url=['ipc://.agent-receiver'], send_url=['ipc://.agent-workers']):
        Process.__init__(self)
        self.conf = conf
        self.send_url = send_url
        self.recv_url = recv_url
    
    def run(self):
        context = zmq.Context()
        receiver = context.socket(zmq.PULL)
        for s in self.recv_url:
            receiver.bind(s)
        
        workers = context.socket(zmq.PUSH)
        for s in self.send_url:
            workers.bind(s)
        
        try:
            zmq.proxy(receiver, workers)
            receiver.close()
            workers.close()
        except:
            receiver.close()
            workers.close()
            sys.exit()


class TheiaReplay(Process):
    def __init__(self, conf, key, recv_url=["ipc://.server-workers"]):
        Process.__init__(self)
        self.conf = conf
        self.key = key
        self.recv_url = recv_url
        
    def run(self):
        context = zmq.Context()
        worker = context.socket(zmq.PULL)
        for r in self.recv_url:
            worker.connect(r)
        
        sensors = {}
        for i in self.conf['receivers'],{}:
            if len(i.keys()) == 0:
                break
            sensor = i.keys()[0]
            iface = i[sensor]['name']
            sensors[sensor] = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            sensors[sensor].setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
            _promisc(sensors[sensor], iface)
            sensors[sensor].bind((iface, 3))
            
        events = {}
        event_ct = 0
        event_start = int(time())
        
        decrypt = Fernet(self.key).decrypt
        mloads = msgpack.loads
        
        try:
            while True:
                if worker.poll(1000):
                    work = worker.recv()
                    # decrypt stuff
                    try:
                        denc_work = decrypt(work)
                        msg_work = mloads(denc_work)
                    except: # Add specifics
                        continue
                    
                    try:
                        events[msg_work['sensor']].extend(msg_work['packets'])
                    except KeyError:
                        events[msg_work['sensor']] = msg_work['packets']
                    event_ct += 1
                    del denc_work
                    del msg_work
                if (int(time()) - event_start >= 5) and event_ct > 0:
                    for sensor in events.keys():
                        for p in events[sensor]:
                            sensors[sensor].send(p)
                    del events
                    events = {}
                    event_ct = 0
                    event_start = int(time())
                
        except:
            worker.close()
            sys.exit()
            
            
    @staticmethod
    def setup_interfaces(conf):
        if not os.system("lsmod|grep dummy"):
            if conf['dummy_count']:
                os.system("modprobe dummy numdummies={}".format(conf['dummy_count']))
            else:
                os.system("modprobe dummy numdummies={}".format(len(conf['receivers'])))

        net_dev = open('/proc/net/dev','r').read()
    
        for s in conf['receivers']:
            s = conf['receivers'][s]
            if len(re.findall("({})".format(s['name']), net_dev)) > 0:
                os.system("ip link set {} mtu 9000 up".format(s['name']))
            elif len(re.findall("{}".format(s['dummy_dev']), net_dev)) > 0:
                os.system("ip link set name {} dev {} mtu 9000 up".format(
                    s['name'],
                    s['dummy_dev']
                ))
