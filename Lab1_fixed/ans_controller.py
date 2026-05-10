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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp
from ryu.lib.packet import ether_types
from ryu.ofproto import ether


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.pending_packets = {}  # [dst_ip: [(msg, in_port)]]

        # For ROuter dpid
        self.router_ports = {
            3: {
                3: {"ip": "10.0.1.1",      "mac": "00:00:00:00:01:01"},
                2: {"ip": "10.0.2.1",      "mac": "00:00:00:00:01:02"},
                1: {"ip": "192.168.1.1",   "mac": "00:00:00:00:01:03"},
            }
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match_initial = parser.OFPMatch()
        actions_initial = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, match_initial, actions_initial)  # Catch all rule

        # ARP handling: router->controller, others->flood
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        if datapath.id == 3:
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        else:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        # ARP Packets will be handled with more priority
        self.add_flow(datapath, 1, match_arp, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        src_mac = eth.src
        
        # Learn mac to port
        self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port

        # According to etype, handle different packets
        etype = eth.ethertype
        if etype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
            self.logger.info("ARP from %s (%s) learnt on switch %s port %s",
                            arp_pkt.src_ip, arp_pkt.src_mac, dpid, in_port)
            
            # Sending buffered packets
            dst_ip = arp_pkt.src_ip
            if dst_ip in self.pending_packets:
                self.logger.info("Sending buffered packets")
                for pending_msg, in_port in self.pending_packets.pop(dst_ip):
                    self._forward_ip(datapath, pending_msg, in_port)
            
            # On router and ARP, then reply
            if arp_pkt.opcode == arp.ARP_REQUEST and dpid == 3:
                self._handle_arp(datapath, in_port, eth, arp_pkt)
            return
        elif etype == ether_types.ETH_TYPE_IP:
            if dpid == 3: # IPv4 routing on router switch
                self._handle_router_ip(datapath, in_port, pkt, msg)
            else: # IPV4 routing on switches
                self._handle_switch_ip(datapath, in_port, pkt, msg)
            return
        

    def _handle_switch_ip(self, datapath, in_port, pkt, msg):
        ofproto = datapath.ofproto; parser = datapath.ofproto_parser;
        eth = pkt.get_protocol(ethernet.ethernet); ip = pkt.get_protocol(ipv4.ipv4)
        
        out = self.mac_to_port[datapath.id].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out)]
        m = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
        self.add_flow(datapath, 1, m, actions)
        outmsg = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=msg.data
        )
        datapath.send_msg(outmsg)

    def _handle_router_ip(self, datapath, in_port, pkt, msg):
        dpid = datapath.id; parser = datapath.ofproto_parser;
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip, dst_ip = ip_pkt.src, ip_pkt.dst

        # 1. No ICMP to ext
        if (dst_ip == "192.168.1.123" or (src_ip == "192.168.1.123" and dst_ip != "192.168.1.1")) and ip_pkt.proto == 1:
            match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                        ip_proto=1
                    )
            self.logger.info("Dropping ICMP packets to/from external")
            self.add_flow(datapath, priority=100, match=match, actions=[]) # Drop Packet
            self.logger.info("Installed flow rule for dropping ICMP packets from %s to %s", src_ip, dst_ip)
            return
        
        # 2. No TCP/UDP from ext to ser
        if ((src_ip == "192.168.1.123" and dst_ip == "10.0.2.2") or (src_ip == "10.0.2.2" and dst_ip == "192.168.1.123")) and ip_pkt.proto in (6, 17):
            udp_match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=17
            )
            self.add_flow(datapath, priority=50, match=udp_match, actions=[]) # Drop Packet

            tcp_match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
                ip_proto=6
            )
            self.add_flow(datapath, priority=50, match=tcp_match, actions=[]) # Drop Packet

            self.logger.info("Dropping TCP/UDP packets to/from external and ser")
            self.logger.info("Installed flow rule for dropping TCP/UDP packets from %s to %s", src_ip, dst_ip)
            return
        
        # 3. Drop other gateways
        for port_no, info in self.router_ports[dpid].items():
            if dst_ip == info['ip'] and in_port != port_no:
                self.logger.info("Blocking access to other gateway %s", dst_ip)
                
                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )
                self.add_flow(datapath, 100, match, [])
                self.logger.info("Installed flow rule for dropping packets to other gateways, from %s to %s", src_ip, dst_ip)
                return
        
        # 4. Reply to ICMP Echo Requests
        for port_no, info in self.router_ports[dpid].items():
            if dst_ip == info['ip'] and ip_pkt.proto == 1:
                self._reply_icmp(datapath, in_port, eth, ip_pkt, pkt.get_protocol(icmp.icmp), info['mac'])
                return

        # 5. ARP if needed
        if dst_ip not in self.arp_table:
            self.logger.info("Need ARP for %s", dst_ip)
            # Buffer packet and send later when ARP replied
            self.logger.info("Packet buffered for sending later")
            self.pending_packets.setdefault(dst_ip, []).append((msg, in_port))
            for port_no, info in self.router_ports[dpid].items():
                subnet = info['ip'].rsplit('.', 1)[0] + '.'
                if dst_ip.startswith(subnet):
                    self._send_arp_request(datapath, port_no, info['mac'], dst_ip, subnet)
                    return
            return
        # 6. forward IP
        self._forward_ip(datapath, msg, in_port)

    def _reply_icmp(self, datapath, in_port, eth, ip_pkt, icmp_pkt, router_mac):
        dst_mac = eth.src
        src_mac = router_mac
        dst_ip = ip_pkt.src
        src_ip = ip_pkt.dst
        
        
        rep = packet.Packet()
        rep.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_IP,
            src=src_mac, dst=dst_mac))
        rep.add_protocol(ipv4.ipv4(
            proto=ip_pkt.proto,
            src=src_ip, dst=dst_ip,
            ttl=64))
        rep.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY,
            code=0,
            csum=0,
            data=icmp_pkt.data))
        rep.serialize()
        
        actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=rep.data
        )
        datapath.send_msg(out)

    def _forward_ip(self, datapath, msg, in_port):
        parser = datapath.ofproto_parser; ofproto = datapath.ofproto
        pkt = packet.Packet(msg.data); eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
        dst_mac = self.arp_table[dst_ip]

        for port, info in self.router_ports[datapath.id].items():
            if ip_pkt.dst.startswith(info['ip'].rsplit('.',1)[0] + '.'):
                actions = [parser.OFPActionSetField(eth_src=info['mac']),
                           parser.OFPActionSetField(eth_dst=dst_mac),
                           parser.OFPActionOutput(port)]
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst)
                self.add_flow(datapath, 1, match, actions)
                datapath.send_msg(parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=in_port, actions=actions, data=msg.data))
                break

        # Reverse flow: match replies from dst→src
        reverse_match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_src=ip_pkt.dst,
                                        ipv4_dst=ip_pkt.src)
        reverse_actions = [parser.OFPActionSetField(eth_src=dst_mac),
                            parser.OFPActionSetField(eth_dst=eth.src),
                            parser.OFPActionOutput(in_port)]
        self.add_flow(datapath, 1, reverse_match, reverse_actions)

    def _handle_arp(self, datapath, port, eth, arp_pkt):
        for _, info in self.router_ports.get(datapath.id, {}).items():
            if arp_pkt.dst_ip == info['ip']:
                mac = info['mac']
                break
        else:
            self.logger.info("ARP for unknown IP %s", arp_pkt.dst_ip)
            return

        self.logger.info("Replying ARP for %s with %s", arp_pkt.dst_ip, mac)
        resp = packet.Packet()
        resp.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP, src=mac, dst=eth.src))
        resp.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=mac, src_ip=arp_pkt.dst_ip,
            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip
        ))
        resp.serialize()
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=[datapath.ofproto_parser.OFPActionOutput(port)],
            data=resp.data
        )
        datapath.send_msg(out)

    def _send_arp_request(self, datapath, out_port, src_mac, target_ip, subnet):
        src_ip = None
        for info in self.router_ports.get(datapath.id, {}).values():
            if target_ip.startswith(subnet):
                src_ip = info['ip']
                break

        if src_ip is None:
            # IP not in any connected subnet
            return

        self.logger.info("Sending ARP request for %s out port %s", target_ip, out_port)
        req = packet.Packet()
        req.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP, src=src_mac, dst='ff:ff:ff:ff:ff:ff'))
        req.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac, src_ip=src_ip,
            dst_mac='00:00:00:00:00:00', dst_ip=target_ip))
        req.serialize()
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=datapath.ofproto.OFP_NO_BUFFER,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=[datapath.ofproto_parser.OFPActionOutput(out_port)],
            data=req.data
        )
        datapath.send_msg(out)




# ryu-manager --ofp-tcp-listen-port 6633 ans_controller.py