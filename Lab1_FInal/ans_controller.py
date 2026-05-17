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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp, icmp, ether_types

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Learning table for switches: dpid -> mac->port
        self.host_port_map = {}

        # Router ARP table: ip -> mac
        self.arp_table = {}

        # Packets waiting for ARP resolution: dst_ip -> [(msg, in_port)]
        self.arp_waitlist = {}

        self.gateway_mac = {
            1: "00:00:00:00:01:03",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:01"
        }
        
        self.gateway_ip = {
            1: "192.168.1.1",
            2: "10.0.2.1",
            3: "10.0.1.1"
        }
        
        self.gateway_subnet = {
            1: "192.168.1",
            2: "10.0.2",
            3: "10.0.1"
        }

        # Router ports structure keyed by datapath id for convenience
        # Gateway description indexed by datapath id
        self.gateway_map = {
            3: {
                1: {"ip": self.gateway_ip[1], "mac": self.gateway_mac[1]},
                2: {"ip": self.gateway_ip[2], "mac": self.gateway_mac[2]},
                3: {"ip": self.gateway_ip[3], "mac": self.gateway_mac[3]},
            }
        }

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        # Install ARP handling: on router send ARP to controller, elsewhere flood
        match_arp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        if datapath.id == 3:
            actions_arp = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        else:
            actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.add_flow(datapath, 1, match_arp, actions_arp)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def _install_drop(self, datapath, match, priority=50):
        """Install an empty-action flow (drop) for given match."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = []
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id

        if dpid in [1, 2]:
            self._process_switch(datapath, msg, pkt, eth, in_port)
        elif dpid == 3:
            self._process_router(datapath, msg, pkt, eth, in_port)

    def _process_switch(self, datapath, msg, pkt, eth, in_port):
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.host_port_map.setdefault(dpid, {})
        self.host_port_map[dpid][eth.src] = in_port

        if eth.dst in self.host_port_map[dpid]:
            out_port = self.host_port_map[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _process_router(self, datapath, msg, pkt, eth, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Accept packets destined to any gateway MAC or broadcasts
        known_macs = set(self.gateway_mac.values())
        if eth.dst not in known_macs and eth.dst != 'ff:ff:ff:ff:ff:ff':
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._process_arp(datapath, msg, pkt, eth, arp_pkt, in_port)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self._process_ipv4(datapath, msg, pkt, eth, ipv4_pkt, in_port)
            return

    def _process_arp(self, datapath, msg, pkt, eth, arp_pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # Learn MAC
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac

        # Replay any buffered packets for this IP
        if arp_pkt.src_ip in self.arp_waitlist:
            for pending_msg, pending_in in self.arp_waitlist.pop(arp_pkt.src_ip):
                pending_pkt = packet.Packet(pending_msg.data)
                try:
                    pend_eth = pending_pkt.get_protocols(ethernet.ethernet)[0]
                except Exception:
                    pend_eth = None
                pend_ip = pending_pkt.get_protocol(ipv4.ipv4)
                if pend_ip:
                    self._process_ipv4(datapath, pending_msg, pending_pkt, pend_eth, pend_ip, pending_in)

        if arp_pkt.opcode == arp.ARP_REQUEST:
            target_ip = arp_pkt.dst_ip
            # Check if this ARP request is for one of router's own IPs
            if target_ip in self.gateway_ip.values():
                reply_mac = self.gateway_mac[in_port]
                
                # Create ARP Reply
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=reply_mac))
                reply_pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=reply_mac, src_ip=target_ip,
                                             dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
                reply_pkt.serialize()

                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
                datapath.send_msg(out)

            return

    def _get_subnet(self, ip_str):
        return ".".join(ip_str.split('.')[:3])

    def _process_ipv4(self, datapath, msg, pkt, eth, ipv4_pkt, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst

        # If destined to router itself
        if dst_ip in self.gateway_ip.values():
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                # Check if src is in the same subnet as the targeted gateway IP
                req_gw_port = None
                for port, ip in self.gateway_ip.items():
                    if ip == dst_ip:
                        req_gw_port = port
                        break
                
                src_subnet = self._get_subnet(src_ip)
                if req_gw_port is not None and self.gateway_subnet[req_gw_port] == src_subnet:
                    # Same subnet, reply
                    reply_pkt = packet.Packet()
                    reply_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.gateway_mac[in_port]))
                    reply_pkt.add_protocol(ipv4.ipv4(dst=src_ip, src=dst_ip, proto=ipv4_pkt.proto))
                    reply_pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data))
                    reply_pkt.serialize()

                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=reply_pkt.data)
                    datapath.send_msg(out)
            return

        # Routing to other subnets
        out_port = None
        dst_subnet = self._get_subnet(dst_ip)
        for port, sn in self.gateway_subnet.items():
            if sn == dst_subnet:
                out_port = port
                break
                
        if out_port is None:
            return # Drop if unknown subnet

        # Firewall Rules
        # 1. ext cannot ping internal hosts, and internal hosts cannot ping ext
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            if (in_port == 1 and out_port in [2, 3]) or (in_port in [2, 3] and out_port == 1):
                # install a drop rule so switch handles this in future
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=1)
                self._install_drop(datapath, match, priority=100)
                return
                
        # 2. no TCP/UDP between ext and ser
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        if tcp_pkt or udp_pkt:
            if (in_port == 1 and out_port == 2 and dst_ip == "10.0.2.2") or \
               (in_port == 2 and out_port == 1 and src_ip == "10.0.2.2"):
                # drop in-switch for future packets
                for proto in (6, 17):
                    m = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip, ip_proto=proto)
                    self._install_drop(datapath, m, priority=50)
                return

        if dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]
            src_mac = self.gateway_mac[out_port]
            
            # Install flow
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)
            actions = [
                parser.OFPActionSetField(eth_src=src_mac),
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionDecNwTtl(),
                parser.OFPActionOutput(out_port)
            ]
            self.add_flow(datapath, 1, match, actions)
                
            # Send packet out
            reply_pkt = packet.Packet()
            for p in pkt.protocols:
                if isinstance(p, ethernet.ethernet):
                    reply_pkt.add_protocol(ethernet.ethernet(ethertype=p.ethertype, dst=dst_mac, src=src_mac))
                elif isinstance(p, ipv4.ipv4):
                    reply_pkt.add_protocol(ipv4.ipv4(version=p.version, header_length=p.header_length, tos=p.tos, 
                                           total_length=p.total_length, identification=p.identification, 
                                           flags=p.flags, offset=p.offset, ttl=p.ttl-1, proto=p.proto, 
                                           csum=0, src=p.src, dst=p.dst))
                else:
                    reply_pkt.add_protocol(p)
            reply_pkt.serialize()

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=[parser.OFPActionOutput(out_port)], data=reply_pkt.data)
            datapath.send_msg(out)
            # Add reverse flow so replies are forwarded by switch
            rev_match = parser.OFPMatch(eth_type=0x0800, ipv4_src=dst_ip, ipv4_dst=src_ip)
            rev_actions = [parser.OFPActionSetField(eth_src=dst_mac), parser.OFPActionSetField(eth_dst=eth.src), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 1, rev_match, rev_actions)
        else:
            # Generate ARP request
            src_mac = self.gateway_mac[out_port]
            src_ip_router = self.gateway_ip[out_port]
            
            arp_req = packet.Packet()
            arp_req.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_ARP, dst='ff:ff:ff:ff:ff:ff', src=src_mac))
            arp_req.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=src_mac, src_ip=src_ip_router,
                                         dst_mac='00:00:00:00:00:00', dst_ip=dst_ip))
            arp_req.serialize()
            
            actions = [parser.OFPActionOutput(out_port)]
            # Buffer the original packet so we can send it when ARP reply arrives
            self.arp_waitlist.setdefault(dst_ip, []).append((msg, in_port))

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=arp_req.data)
            datapath.send_msg(out)