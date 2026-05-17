"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

#!/usr/bin/env python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

class NetworkTopo(Topo):

    def build(self):

        s1 = self.addSwitch('s1') 
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Add hosts
        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.1.3/24', defaultRoute='via 10.0.1.1')
        ser = self.addHost('ser', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')
        ext = self.addHost('ext', ip='192.168.1.123/24', defaultRoute='via 192.168.1.1')

        linkopts = dict(bw=15, delay='10ms')

        # Order should stay same since port numbers need to remain constant
        # First, External host to s3 that is, s3-eth1 (port 1)
        self.addLink(ext, s3, **linkopts)

        # Second, switch s2 to s3 that i, s3-eth2 (port 2)
        self.addLink(s2, s3, **linkopts)

        # Third, switch s1 to s3 that is, s3-eth3 (port 3)
        self.addLink(s1, s3, **linkopts)

        self.addLink(h1, s1, **linkopts)
        self.addLink(h2, s1, **linkopts)
        self.addLink(ser, s2, **linkopts)

def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo,
                  switch=OVSKernelSwitch,
                  link=TCLink,
                  controller=None)
    net.addController(
        'c1',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    net.start()
    print("Network is up.")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()