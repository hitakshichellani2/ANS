"""
Copyright (c) 2026 Computer Networks Group @ UPB

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

#!/usr/bin/python

from mininet.topo import Topo


class BridgeTopo(Topo):
    "Creat a bridge-like customized network topology according to Figure 1 in the lab0 description."

    def __init__(self):

        Topo.__init__(self)

        # TODO: add nodes and links to construct the topology; remember to specify the link properties
        h1 = self.addHost("h1", ip="10.0.0.1")
        h2 = self.addHost("h2", ip="10.0.0.2")
        h3 = self.addHost("h3", ip="10.0.0.3")
        h4 = self.addHost("h4", ip="10.0.0.4")
        s1 = self.addSwitch("s1", type="OVSBridge")
        s2 = self.addSwitch("s2", type="OVSBridge")
        self.addLink(h1, s1, bw=15, delay="20ms")
        self.addLink(h2, s1, bw=15, delay="20ms")
        self.addLink(h3, s2, bw=15, delay="20ms")
        self.addLink(h4, s2, bw=15, delay="20ms")
        self.addLink(s1, s2, bw=20, delay="45ms")


topos = {"bridge": (lambda: BridgeTopo())}
