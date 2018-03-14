import logging
import random
import ptf
import ptf.packet as scapy
import ptf.dataplane as dataplane

from ptf import config
from ptf.base_tests import BaseTest
from ptf.mask import Mask
from ptf.testutils import *
from ipaddress import ip_address, ip_network

router_mac='00:77:66:55:44:00'

class OCPDemo(BaseTest):
    def __init__(self):
        '''
        @summary: constructor
        '''
        BaseTest.__init__(self)
        self.test_params = test_params_get()

    #---------------------------------------------------------------------

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        self.src_ports = range(1, 64)
        self.srv_ip = '192.169.1.1'
        self.srv_mac = 'e4:1d:2d:f2:95:58'
        self.VM_ip = '192.169.2.1'
        self.host_ip = '10.10.10.1'
        self.vxlan_default_router_mac='00:11:11:11:11:11'
        self.underlay_neighbor_mac = 'ec:f4:bb:ff:77:a3'
        self.underlay_nhop_ip = '1.1.1.1'
        self.underlay_route_addr = '0.0.0.0'
        self.underlay_route_mask = '0.0.0.0'
        self.my_lb_ip_addr = '1.1.1.3'
        self.my_lb_ip_mask = '255.255.255.255'
        self.vni = 20
        self.host_inner_dmac = self.vxlan_default_router_mac

    #---------------------------------------------------------------------

    def runTest(self):
        """
        @summary:
        """
        try:
            print "Tunnel Decap:"
            print "sending packet from VM to Srv"
            pkt1 = simple_tcp_packet(
                eth_dst=router_mac,
                eth_src=self.vxlan_default_router_mac,
                ip_dst=self.srv_ip,
                ip_src=self.VM_ip,
                ip_id=108,
                ip_ttl=64)
            vxlan_pkt = simple_vxlan_packet(
                eth_dst=router_mac,
                eth_src=self.underlay_neighbor_mac,
                ip_id=0,
                ip_src=self.host_ip,
                ip_dst=self.my_lb_ip_addr,
                ip_ttl=64,
                #ip_flags=0x2,
                udp_sport=11638,
                vxlan_vni=self.vni,
                with_udp_chksum=False,
                inner_frame=pkt1)
            pkt2 = simple_tcp_packet(
                eth_src=router_mac,
                eth_dst=self.srv_mac,
                ip_dst=self.srv_ip,
                ip_src=self.VM_ip,
                ip_id=108,
                ip_ttl=63)
            send_packet(self, 1, str(vxlan_pkt))
            verify_packet(self, pkt2, 0)
            print "Tunnel Encap"
            print "sending packet from Srv to VM"
            pkt = simple_tcp_packet(
                      eth_dst=router_mac,
                      eth_src=self.srv_mac,
                      ip_dst=self.VM_ip,
                      ip_src=self.srv_ip,
                      ip_id=105,
                      ip_ttl=64)
            pkt2 = simple_tcp_packet(
                eth_dst=self.host_inner_dmac,
                eth_src=router_mac,
                ip_dst=self.VM_ip,
                ip_src=self.srv_ip,
                ip_id=105,
                ip_ttl=63)
            vxlan_pkt1 = simple_vxlan_packet(
                eth_src=router_mac,
                eth_dst=self.underlay_neighbor_mac,
                ip_id=0,
                ip_src=self.my_lb_ip_addr,
                ip_dst=self.host_ip,
                ip_ttl=64,
                #ip_flags=0x2,
                udp_sport=20481,
                with_udp_chksum=False,
                vxlan_vni=self.vni,
                inner_frame=pkt2)
            send_packet(self, 0, str(pkt))
            verify_packet(self, vxlan_pkt1, 1)
        finally:
            print
