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
from theia import TheiaReplay, TheiaProxy


if __name__ == '__main__':

    with open('/etc/theia/server.yaml') as c:
        conf = yaml.load(c)

    if not 'server_key' in conf or not conf['server_key']:
        print("Missing encryption key\nCreate semetric key using python gen_key.py")
        print("NOTE: This must match receiving server's key")
        sys.exit(1)

    if conf['configure_interfaces']:
        TheiaReplay.setup_interfaces(conf)


    listener = TheiaProxy(
        conf,
        recv_url=["tcp://{}:{}".format(
            conf['listen_addr'],
            conf['listen_port']
        )],
        send_url=["ipc://.server-workers"]
    )
    listener.start()

    workers = []
    for _ in xrange(0, conf['threads']):
        recvr = TheiaReplay(
            conf,
            conf['server_key']
        )
        recvr.start()
        workers.append(recvr)

    try:
        while True:
            for w in workers:
                if not w.is_alive():
                    recvr = TheiaReplay(
                        conf,
                        conf['server_key']
                    )
                    recvr.start()
                    workers.append(recvr)
                    workers.remove(w)
            if not listener.is_alive():
                listener = TheiaProxy(
                    conf,
                    recv_url=["tcp://{}:{}".format(
                    conf['listen_addr'],
                    conf['listen_port']
                )],
                )
                listener.start()
            time.sleep(5)
    except:
        listener.terminate()
        for w in workers:
            w.terminate()
        sys.exit()

