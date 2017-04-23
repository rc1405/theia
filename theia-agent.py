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

import time
import yaml
import os
import sys
from theia import TheiaSniffer, TheiaEncryptedSender, TheiaProxy

if __name__ == '__main__':

    with open('/etc/theia/agent.yaml') as c:
        conf = yaml.load(c)

    if not 'server_key' in conf or not conf['server_key']: 
        print("Missing encryption key\nCreate semetric key using python theia-genkey.py")
        print("NOTE: This must match receiving server's key")
        sys.exit(1)

    proxy = TheiaProxy(conf)
        
    proxy.start()

    senders = []
        
    for i in xrange(0, conf['threads']):
        sender = TheiaEncryptedSender(
            conf,
            conf['server_key'],
            send_url = ["tcp://{}:{}".format(
                conf['destination']['name'],
                conf['destination']['port']
            )]
        )
        sender.start()
        senders.append(sender)
    
    sniffers = {}
    for i in conf['interfaces']:
        sniff = TheiaSniffer(conf, i)
        sniff.start()
        sniffers[i] = sniff


    try:
        while True:
            if not proxy.is_alive():
                proxy = TheiaProxy(conf)
                proxy.start()
                
            for s in senders:
                if not s.is_alive():
                    sender = TheiaEncryptedSender(
                        conf,
                        conf['server_key'],
                        send_url = ["tcp://{}:{}".format(
                            conf['destination']['name'],
                            conf['destination']['port']
                        )]
                    )
                    sender.start()
                    senders.append(sender)
                    senders.remove(s)

            for s in sniffers.keys():
                if not sniffers[s].is_alive():
                    sniff = TheiaSniffer(conf, s)
                    sniff.start()
                    sniffers[i] = sniff

            time.sleep(5)
    except:
        for s in sniffers.keys():
            sniff[s].terminate()
            
        for s in senders:
            s.terminate()
            
        proxy.terminate()
        sys.exit()
