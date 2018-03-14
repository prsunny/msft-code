# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Thrift SAI Tunnel tests
"""

import socket
import pdb
from ptf.mask import Mask
import sai_base_test
from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from switch_sai_thrift.sai_headers import *
from switch_utils import *

import os
this_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(this_dir, '..'))


def sai_thrift_create_loopback_rif(client, vr_oid, rmac, v4=1, v6=1):
    #vrf attribute
    rif_attr_list = []
    rif_attribute1_value = sai_thrift_attribute_value_t(oid=vr_oid)
    rif_attribute1 = sai_thrift_attribute_t(
        id=SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID,
        value=rif_attribute1_value)
    #interface type
    rif_attr_list.append(rif_attribute1)
    rif_attribute2_value = sai_thrift_attribute_value_t(
        s32=SAI_ROUTER_INTERFACE_TYPE_LOOPBACK)
    rif_attribute2 = sai_thrift_attribute_t(
        id=SAI_ROUTER_INTERFACE_ATTR_TYPE, value=rif_attribute2_value)
    rif_attr_list.append(rif_attribute2)

    #v4_enabled
    rif_attribute4_value = sai_thrift_attribute_value_t(booldata=v4)
    rif_attribute4 = sai_thrift_attribute_t(
        id=SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
        value=rif_attribute4_value)
    rif_attr_list.append(rif_attribute4)
    #v6_enabled
    rif_attribute5_value = sai_thrift_attribute_value_t(booldata=v6)
    rif_attribute5 = sai_thrift_attribute_t(
        id=SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
        value=rif_attribute5_value)
    rif_attr_list.append(rif_attribute5)

    if rmac:
        rif_attribute6_value = sai_thrift_attribute_value_t(mac=rmac)
        rif_attribute6 = sai_thrift_attribute_t(
            id=SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
            value=rif_attribute6_value)
        rif_attr_list.append(rif_attribute6)

    rif_id = client.sai_thrift_create_router_interface(rif_attr_list)
    return rif_id


def sai_thrift_create_nhop_tunnel(client, tunnel, ip_addr, mac='', addr_family=SAI_IP_ADDR_FAMILY_IPV4, vni=0):
    attr_list = []
    #ip addr
    if addr_family == SAI_IP_ADDR_FAMILY_IPV4:
        addr = sai_thrift_ip_t(ip4=ip_addr)
        ipaddr = sai_thrift_ip_address_t(
            addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    else:
        addr = sai_thrift_ip_t(ip6=ip_addr)
        ipaddr = sai_thrift_ip_address_t(
            addr_family=SAI_IP_ADDR_FAMILY_IPV6, addr=addr)
    attr_value = sai_thrift_attribute_value_t(ipaddr=ipaddr)
    attr = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_IP, value=attr_value)
    attr_list.append(attr)
    #tunnel type
    attr_value = sai_thrift_attribute_value_t(
        s32=SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP)
    attr = sai_thrift_attribute_t(id=SAI_NEXT_HOP_ATTR_TYPE, value=attr_value)
    attr_list.append(attr)
    #tunnel id
    attr_value = sai_thrift_attribute_value_t(oid=tunnel)
    print hex(tunnel)
    attr = sai_thrift_attribute_t(
        id=SAI_NEXT_HOP_ATTR_TUNNEL_ID, value=attr_value)
    attr_list.append(attr)
    #tunnel vni
    if vni:
        attr_value = sai_thrift_attribute_value_t(u32=vni)
        attr = sai_thrift_attribute_t(
            id=SAI_NEXT_HOP_ATTR_TUNNEL_VNI, value=attr_value)
        attr_list.append(attr)
    #tunnel mac
    if mac:
        attr_value = sai_thrift_attribute_value_t(mac=mac)
        attr = sai_thrift_attribute_t(
            id=SAI_NEXT_HOP_ATTR_TUNNEL_MAC, value=attr_value)
        attr_list.append(attr)

    nhop = client.sai_thrift_create_next_hop(thrift_attr_list=attr_list)
    return nhop


def sai_thrift_create_tunnel(client,
                             type,
                             tunnel_sip,
                             urif,
                             orif=0,
                             imap=0,
                             emap=0):
    tunnel_attr_list = []
    #tunnel type
    attr_value = sai_thrift_attribute_value_t(s32=type)
    attr = sai_thrift_attribute_t(id=SAI_TUNNEL_ATTR_TYPE, value=attr_value)
    tunnel_attr_list.append(attr)
    #underlay rif
    attr_value = sai_thrift_attribute_value_t(oid=urif)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE, value=attr_value)
    tunnel_attr_list.append(attr)
    #overlay rif
    if orif:
        attr_value = sai_thrift_attribute_value_t(oid=orif)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_ATTR_OVERLAY_INTERFACE, value=attr_value)
        tunnel_attr_list.append(attr)
    #src ip addr
    addr = sai_thrift_ip_t(ip4=tunnel_sip)
    ip_addr = sai_thrift_ip_address_t(
        addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    attr_value = sai_thrift_attribute_value_t(ipaddr=ip_addr)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_ATTR_ENCAP_SRC_IP, value=attr_value)
    tunnel_attr_list.append(attr)
    #encap mapper
    attr_value = sai_thrift_attribute_value_t(
        objlist=sai_thrift_object_list_t(count=1, object_id_list=[imap]))
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_ATTR_ENCAP_MAPPERS, value=attr_value)
    tunnel_attr_list.append(attr)
    #decap mapper
    attr_value = sai_thrift_attribute_value_t(
        objlist=sai_thrift_object_list_t(count=1, object_id_list=[emap]))
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_ATTR_DECAP_MAPPERS, value=attr_value)
    tunnel_attr_list.append(attr)
    tunnel_id = client.sai_thrift_create_tunnel(tunnel_attr_list)
    return tunnel_id


def sai_thrift_create_tunnel_term(client, type, vr_id, src_ip, dst_ip,
                                  tunnel_id, tunnel_type):
    tunnel_term_list = []
    #entry typr
    attr_value = sai_thrift_attribute_value_t(s32=type)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE, value=attr_value)
    tunnel_term_list.append(attr)
    #vrf id
    attr_value = sai_thrift_attribute_value_t(oid=vr_id)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID, value=attr_value)
    tunnel_term_list.append(attr)
    #src ip
    if type == SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2P:
        addr = sai_thrift_ip_t(ip4=src_ip)
        ip_addr = sai_thrift_ip_address_t(
            addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
        attr_value = sai_thrift_attribute_value_t(ipaddr=ip_addr)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_SRC_IP, value=attr_value)
        tunnel_term_list.append(attr)
    #dst ip
    addr = sai_thrift_ip_t(ip4=dst_ip)
    ip_addr = sai_thrift_ip_address_t(
        addr_family=SAI_IP_ADDR_FAMILY_IPV4, addr=addr)
    attr_value = sai_thrift_attribute_value_t(ipaddr=ip_addr)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP, value=attr_value)
    tunnel_term_list.append(attr)
    #vrf id
    attr_value = sai_thrift_attribute_value_t(oid=tunnel_id)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID, value=attr_value)
    tunnel_term_list.append(attr)
    #tunnel type
    attr_value = sai_thrift_attribute_value_t(s32=tunnel_type)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE, value=attr_value)
    tunnel_term_list.append(attr)
    tunnel_term_id = client.sai_thrift_create_tunnel_term(tunnel_term_list)
    return tunnel_term_id


def sai_thrift_create_tunnel_map(client, map_type):
    attr_list = []
    #tunnel map type
    attr_value = sai_thrift_attribute_value_t(s32=map_type)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_MAP_ATTR_TYPE, value=attr_value)
    attr_list.append(attr)
    tunnel_map_id = client.sai_thrift_create_tunnel_map(attr_list)
    return tunnel_map_id


def sai_thrift_create_tunnel_map_entry(client, map_type, tunnel_map_id, ln,
                                       vlan, vrf, vni):
    attr_list = []
    #tunnel map type
    attr_value = sai_thrift_attribute_value_t(s32=map_type)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE, value=attr_value)
    attr_list.append(attr)
    # tunnel map
    attr_value = sai_thrift_attribute_value_t(oid=tunnel_map_id)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP, value=attr_value)
    attr_list.append(attr)
    if (map_type == SAI_TUNNEL_MAP_TYPE_VNI_TO_BRIDGE_IF):
        #ln handle
        attr_value = sai_thrift_attribute_value_t(oid=ln)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_VALUE, value=attr_value)
        attr_list.append(attr)
    if (map_type == SAI_TUNNEL_MAP_TYPE_VNI_TO_VLAN_ID):
        #vlan handle
        attr_value = sai_thrift_attribute_value_t(u16=vlan)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_VALUE, value=attr_value)
        attr_list.append(attr)
    if (map_type == SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID):
        #vrf handle
        attr_value = sai_thrift_attribute_value_t(oid=vrf)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE,
            value=attr_value)
        attr_list.append(attr)
    #vni handle
    attr_value = sai_thrift_attribute_value_t(u32=vni)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE, value=attr_value)
    attr_list.append(attr)

    if (map_type == SAI_TUNNEL_MAP_TYPE_BRIDGE_IF_TO_VNI):
        #ln handle
        attr_value = sai_thrift_attribute_value_t(oid=ln)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_MAP_ENTRY_ATTR_BRIDGE_ID_KEY, value=attr_value)
        attr_list.append(attr)
    if (map_type == SAI_TUNNEL_MAP_TYPE_VLAN_ID_TO_VNI):
        #vlan handle
        attr_value = sai_thrift_attribute_value_t(u16=vlan)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_MAP_ENTRY_ATTR_VLAN_ID_KEY, value=attr_value)
        attr_list.append(attr)
    if (map_type == SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI):
        #vrf handle
        attr_value = sai_thrift_attribute_value_t(oid=vrf)
        attr = sai_thrift_attribute_t(
            id=SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY,
            value=attr_value)
        attr_list.append(attr)
    #vni handle
    attr_value = sai_thrift_attribute_value_t(u32=vni)
    attr = sai_thrift_attribute_t(
        id=SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY, value=attr_value)
    attr_list.append(attr)
    tunnel_map_entry = client.sai_thrift_create_tunnel_map_entry(attr_list)
    return tunnel_map_entry


@group('tunnel-ocp')
class OCPDemo(sai_base_test.ThriftInterfaceDataPlane):
    # Routing in-and-out of Vxlan tunnels
    def createSaiRpcClient(self):
        # Set up thrift client and contact server

        if self.test_params.has_key("thrift_server"):
            server = self.test_params['thrift_server']
        else:
            server = 'localhost'

        self.transport = TSocket.TSocket(server, 9092)
        self.transport = TTransport.TBufferedTransport(self.transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        self.client = switch_sai_rpc.Client(self.protocol)
        self.transport.open()
        return


    def setUp(self):
        super(self.__class__, self).setUp()
        print
        OCPDemo.createSaiRpcClient(self)
        switch_init(self.client)
        self.test_params = testutils.test_params_get()
        switch_attr_list = self.client.sai_thrift_get_switch_attribute()
        attr_list = switch_attr_list.attr_list
        port_list = []
        for attr in attr_list:
          if attr.id == SAI_SWITCH_ATTR_PORT_LIST:
            for x in attr.value.objlist.object_id_list:
              port_list.append(x)

        # Create port 1/0 --> 0 40G
        self.P1_port = 4294967345 # Port 49
        # Create port 3/0 --> 8 40G
        self.P3_port = 4294967346 # Port 50

        #Server IP
        self.srv_ip = '192.169.1.1'
        self.srv_subnet = '192.169.1.0'
        
        #Server MAC
        self.srv_mac = 'e4:1d:2d:f2:95:58'
        self.VM_ip = '192.169.2.1'
        self.host_ip = '10.10.10.1'

        # Inner Destination MACs
        self.vxlan_default_router_mac='00:11:11:11:11:11' 

        # VM MAC
        self.host_inner_dmac = self.vxlan_default_router_mac

        # Create Default VRF ( also used as underlay vrf )
        v4_enabled = 1
        self.uvrf = sai_thrift_create_virtual_router(self.client, v4_enabled, 0)

        # Create Underlay loopback RIF ( required for tunnel object creation )
        self.urif_lb = sai_thrift_create_loopback_rif(self.client, self.uvrf, router_mac)

        #
        # Create Overlay VRF/VNI
        #
        self.ovrf = sai_thrift_create_virtual_router(self.client, v4_enabled, 0)
        self.vni = 20

        #
        # Setup underlay default route, the nexthop is 1.1.1.1.
        #
        self.underlay_neighbor_mac = 'ec:f4:bb:ff:77:a3'
        self.underlay_nhop_ip = '1.1.1.1'
        self.underlay_route_addr = '0.0.0.0'
        self.underlay_route_mask = '0.0.0.0'

        self.underlay_rif = sai_thrift_create_router_interface(self.client, self.uvrf, 1, self.P3_port, 0, 1, 0 , 0)
        self.underlay_neighbor = sai_thrift_create_neighbor(self.client, SAI_IP_ADDR_FAMILY_IPV4,
                                                            self.underlay_rif, self.underlay_nhop_ip, self.underlay_neighbor_mac)
        self.underlay_nhop = sai_thrift_create_nhop(self.client, SAI_IP_ADDR_FAMILY_IPV4, self.underlay_nhop_ip, self.underlay_rif)
        self.underlay_default_route = sai_thrift_create_route(self.client, self.uvrf, SAI_IP_ADDR_FAMILY_IPV4,
                                                              self.underlay_route_addr, self.underlay_route_mask, self.underlay_nhop)

        #
        # Setup overlay routes
        #

        # create port-based router interface for srv2
        self.srv_rif = sai_thrift_create_router_interface(self.client, self.ovrf, 1, self.P1_port, 0, 1, 1, '')
        sai_thrift_create_neighbor(self.client, SAI_IP_ADDR_FAMILY_IPV4, self.srv_rif, self.srv_ip, self.srv_mac)
        self.nhop4 = sai_thrift_create_nhop(self.client, SAI_IP_ADDR_FAMILY_IPV4, self.srv_ip, self.srv_rif)

        #
        # Create Tunnel
        #

        # Create Encap/decap mappers
        self.encap_tunnel_map = sai_thrift_create_tunnel_map(self.client, SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI)
        self.decap_tunnel_map = sai_thrift_create_tunnel_map(self.client, SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID)

        # Create Tunnel object
        self.my_lb_ip_addr = '1.1.1.3'
        self.my_lb_ip_mask = '255.255.255.255'
        self.tunnel_id = sai_thrift_create_tunnel(self.client, SAI_TUNNEL_TYPE_VXLAN, self.my_lb_ip_addr, self.urif_lb, 0, self.encap_tunnel_map, self.decap_tunnel_map)

        # Create Tunnel Map entries
        self.encap_tunnel_map_entry = sai_thrift_create_tunnel_map_entry(self.client, SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI, self.encap_tunnel_map, 0, 0, self.ovrf, self.vni)
        self.decap_tunnel_map_entry = sai_thrift_create_tunnel_map_entry(self.client, SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID, self.decap_tunnel_map, 0, 0, self.ovrf, self.vni)

        # Create tunnel decap for VM to customer server
        self.tunnel_term_id = sai_thrift_create_tunnel_term(self.client, SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP, self.uvrf,
                                                       self.my_lb_ip_mask, self.my_lb_ip_addr, self.tunnel_id, SAI_TUNNEL_TYPE_VXLAN)

        # create tunnel nexthop for VM */
        self.tunnel_nexthop_id = sai_thrift_create_nhop_tunnel(self.client, self.tunnel_id, self.host_ip, self.host_inner_dmac, SAI_IP_ADDR_FAMILY_IPV4)

        # Create routes
        VM_route = sai_thrift_create_route(self.client, self.ovrf, SAI_IP_ADDR_FAMILY_IPV4, self.VM_ip, '255.255.255.255', self.tunnel_nexthop_id)
        Access_route = sai_thrift_create_route(self.client, self.ovrf, SAI_IP_ADDR_FAMILY_IPV4, self.srv_subnet, '255.255.255.0', self.nhop4)

    def runTest(self):
        return
