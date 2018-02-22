/**
 * This is a sample code to validate the VNET pairing functionality
 * using VIRTUAL_ROUTER_ID to VNI and vice-versa to setup overlay and
 * underlay routers
 *
 * Code is meant for test purpose to lay-out various SAI flow/attributes
 * to achieve this functionality.
 *
 * Use-case is captured below @
 * https://github.com/lguohan/SAI/blob/vni/doc/SAI-Proposal-QinQ-VXLAN.md
 */

#include "sai.h"
#include <vector>
#include <string.h>
#include <arpa/inet.h>

/* Global variables */
sai_object_id_t gSwitchId = SAI_NULL_OBJECT_ID;
sai_mac_t gSwitchMac = {0x00,0x11,0x11,0x11,0x011,0x11};

extern sai_switch_api_t *sai_switch_api;
extern sai_virtual_router_api_t *sai_virtual_router_api;
extern sai_router_interface_api_t* sai_router_intfs_api;
extern sai_tunnel_api_t *sai_tunnel_api;
extern sai_next_hop_api_t *sai_next_hop_api;
extern sai_next_hop_group_api_t *sai_next_hop_group_api;
extern sai_route_api_t *sai_route_api;
extern sai_neighbor_api_t *sai_neighbor_api;

// Helper functions

sai_object_id_t create_encap_tunnel_map()
{
    sai_status_t status;
    sai_attribute_t attr;
    sai_object_id_t tunnel_map_id;
    std::vector<sai_attribute_t> tunnel_map_attrs;

    attr.id = SAI_TUNNEL_MAP_ATTR_TYPE;
    attr.value.s32 = SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI;
    tunnel_map_attrs.push_back(attr);

    sai_tunnel_api->create_tunnel_map(&tunnel_map_id, gSwitchId, 1, tunnel_map_attrs.data());

    return tunnel_map_id;
}

sai_object_id_t create_encap_tunnel_map_entry(
    sai_object_id_t tunnel_map_id,
    sai_object_id_t router_id,
    sai_uint32_t vni)
{
    sai_status_t status;
    sai_attribute_t attr;
    sai_object_id_t tunnel_map_entry_id;
    std::vector<sai_attribute_t> tunnel_map_entry_attrs;

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE;
    attr.value.s32 = SAI_TUNNEL_MAP_TYPE_VIRTUAL_ROUTER_ID_TO_VNI;
    tunnel_map_entry_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP;
    attr.value.oid = tunnel_map_id;
    tunnel_map_entry_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_KEY;
    attr.value.oid = router_id;
    tunnel_map_entry_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_VALUE;
    attr.value.u32 = vni;
    tunnel_map_entry_attrs.push_back(attr);

    sai_tunnel_api->create_tunnel_map_entry(&tunnel_map_entry_id, gSwitchId,
                                            tunnel_map_entry_attrs.size(),
                                            tunnel_map_entry_attrs.data());

    return tunnel_map_entry_id;
}

sai_object_id_t create_decap_tunnel_map()
{
    sai_status_t status;
    sai_attribute_t attr;
    sai_object_id_t tunnel_map_id;
    std::vector<sai_attribute_t> tunnel_map_attrs;

    attr.id = SAI_TUNNEL_MAP_ATTR_TYPE;
    attr.value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID;
    tunnel_map_attrs.push_back(attr);

    sai_tunnel_api->create_tunnel_map(&tunnel_map_id, gSwitchId, 1, tunnel_map_attrs.data());

    return tunnel_map_id;
}

sai_object_id_t create_decap_tunnel_map_entry(
    sai_object_id_t tunnel_map_id,
    sai_object_id_t router_id,
    sai_uint32_t vni)
{
    sai_status_t status;
    sai_attribute_t attr;
    sai_object_id_t tunnel_map_entry_id;
    std::vector<sai_attribute_t> tunnel_map_entry_attrs;

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP_TYPE;
    attr.value.s32 = SAI_TUNNEL_MAP_TYPE_VNI_TO_VIRTUAL_ROUTER_ID;
    tunnel_map_entry_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_TUNNEL_MAP;
    attr.value.oid = tunnel_map_id;
    tunnel_map_entry_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VNI_ID_KEY;
    attr.value.u32 = vni;
    tunnel_map_entry_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_MAP_ENTRY_ATTR_VIRTUAL_ROUTER_ID_VALUE;
    attr.value.oid = router_id;
    tunnel_map_entry_attrs.push_back(attr);

    sai_tunnel_api->create_tunnel_map_entry(&tunnel_map_entry_id, gSwitchId,
                                            tunnel_map_entry_attrs.size(),
                                            tunnel_map_entry_attrs.data());

    return tunnel_map_entry_id;
}

// Create Tunnel

sai_status_t create_tunnel(
    sai_object_id_t ingress_router_id,
    sai_object_id_t egress_router_id,
    sai_object_id_t underlay_rif,
    sai_uint32_t vni,
    sai_object_id_t *tunnel_id,
    sai_object_id_t *tunnel_encap_map_id,
    sai_object_id_t *tunnel_decap_map_id)
{
	sai_status_t status;
	sai_attribute_t attr;
	sai_object_id_t tunnel_encap_entry_id;
	sai_object_id_t temp;
	std::vector<sai_attribute_t> tunnel_attrs;

	attr.id = SAI_TUNNEL_ATTR_TYPE;
	attr.value.s32 = SAI_TUNNEL_TYPE_VXLAN;
	tunnel_attrs.push_back(attr);

	attr.id = SAI_TUNNEL_ATTR_UNDERLAY_INTERFACE;
	attr.value.oid = underlay_rif;
	tunnel_attrs.push_back(attr);

	*tunnel_encap_map_id = create_encap_tunnel_map();
	create_encap_tunnel_map_entry(*tunnel_encap_map_id, ingress_router_id, vni);

	sai_object_id_t encap_list[] = { *tunnel_encap_map_id };
	attr.id = SAI_TUNNEL_ATTR_ENCAP_MAPPERS;
	attr.value.objlist.count = 1;
	attr.value.objlist.list = encap_list;
	tunnel_attrs.push_back(attr);

	*tunnel_decap_map_id = create_decap_tunnel_map();
	create_decap_tunnel_map_entry(*tunnel_decap_map_id, egress_router_id, vni);

	sai_object_id_t decap_list[] = { *tunnel_decap_map_id };
	attr.id = SAI_TUNNEL_ATTR_DECAP_MAPPERS;
	attr.value.objlist.count = 1;
	attr.value.objlist.list = decap_list;
	tunnel_attrs.push_back(attr);

	// source ip
	attr.id = SAI_TUNNEL_ATTR_ENCAP_SRC_IP;
	sai_ip_address_t ip_addr = {SAI_IP_ADDR_FAMILY_IPV4, 0x0a0a0a0a};
	attr.value.ipaddr = ip_addr;
	tunnel_attrs.push_back(attr);

	// ttl mode (uniform/pipe)
	attr.id = SAI_TUNNEL_ATTR_DECAP_TTL_MODE;
	attr.value.s32 = SAI_TUNNEL_TTL_MODE_UNIFORM_MODEL;
	tunnel_attrs.push_back(attr);

	// dscp mode (uniform/pipe)
	attr.id = SAI_TUNNEL_ATTR_DECAP_DSCP_MODE;
	attr.value.s32 = SAI_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
	tunnel_attrs.push_back(attr);

	status = sai_tunnel_api->create_tunnel(tunnel_id, gSwitchId, tunnel_attrs.size(), tunnel_attrs.data());

	return status;
}

// Create nexthop for the tunnel interface

sai_status_t create_nexthop_tunnel(
    sai_ip4_t host_ip,
    sai_uint32_t vni, // optional vni
    sai_mac_t mac, // inner destination mac
    sai_object_id_t tunnel_id,
    sai_object_id_t *next_hop_id)
{
    std::vector<sai_attribute_t> next_hop_attrs;
    sai_attribute_t next_hop_attr;

    next_hop_attr.id = SAI_NEXT_HOP_ATTR_TYPE;
    next_hop_attr.value.s32 = SAI_NEXT_HOP_TYPE_TUNNEL_ENCAP;
    next_hop_attrs.push_back(next_hop_attr);

    next_hop_attr.id = SAI_NEXT_HOP_ATTR_IP;
    next_hop_attr.value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    next_hop_attr.value.ipaddr.addr.ip4 = htonl(host_ip);
    next_hop_attrs.push_back(next_hop_attr);

    next_hop_attr.id = SAI_NEXT_HOP_ATTR_TUNNEL_ID;
    next_hop_attr.value.oid = tunnel_id;
    next_hop_attrs.push_back(next_hop_attr);

    if (vni != 0)
    {
        next_hop_attr.id = SAI_NEXT_HOP_ATTR_TUNNEL_VNI;
        next_hop_attr.value.u32 = vni;
        next_hop_attrs.push_back(next_hop_attr);
    }

    if (mac != NULL)
    {
        next_hop_attr.id = SAI_NEXT_HOP_ATTR_TUNNEL_MAC;
        memcpy(next_hop_attr.value.mac, mac, sizeof(mac));
        next_hop_attrs.push_back(next_hop_attr);
    }

    sai_status_t status = sai_next_hop_api->create_next_hop(next_hop_id, gSwitchId,
                                                          next_hop_attrs.size(), next_hop_attrs.data());
    return status;
}

// Create tunnel termination

sai_status_t create_tunnel_termination(
    sai_object_id_t oid,  // tunnel oid
    sai_object_id_t vrid,
    sai_ip4_t dstip,      // tunnel dstip ip
    sai_object_id_t *term_table_id)
{
    sai_attribute_t attr;
    std::vector<sai_attribute_t> tunnel_attrs;

    attr.id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TYPE;
    attr.value.s32 = SAI_TUNNEL_TERM_TABLE_ENTRY_TYPE_P2MP;
    tunnel_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_DST_IP;
    attr.value.ip4 = htonl(dstip);
    tunnel_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_TUNNEL_TYPE;
    attr.value.s32 = SAI_TUNNEL_TYPE_VXLAN;
    tunnel_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_ACTION_TUNNEL_ID;
    attr.value.oid = oid;
    tunnel_attrs.push_back(attr);

    attr.id = SAI_TUNNEL_TERM_TABLE_ENTRY_ATTR_VR_ID;
    attr.value.oid = vrid;
    tunnel_attrs.push_back(attr);

    sai_status_t status;
    status = sai_tunnel_api->create_tunnel_term_table_entry(term_table_id, gSwitchId,
             tunnel_attrs.size(), tunnel_attrs.data());

    return status;
}

/*
 * Generic route, next-hop etc APIs to create
 * Virtual Router, RIF, Routes, Neighbor, Nexthop
 */

sai_status_t create_route(
    sai_ip4_t ip,
    sai_ip4_t mask,
    sai_object_id_t vrf_id,
    sai_object_id_t nexthop_id)
{
    sai_status_t status;
    sai_route_entry_t route_entry;
    route_entry.switch_id = gSwitchId;
    route_entry.vr_id = vrf_id;

    sai_ip_prefix_t destination;
    destination.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    destination.addr.ip4 = htonl(ip);
    destination.mask.ip4 = htonl(mask);
    route_entry.destination = destination;

    sai_attribute_t attr;
    attr.id = SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID;
    attr.value.oid = nexthop_id;

    status = sai_route_api->create_route_entry(&route_entry, 1, &attr);
    return status;
}

sai_status_t create_neighbor(
    sai_ip4_t ip,
    sai_object_id_t rif_id,
    sai_mac_t mac)
{
    sai_status_t status;
    sai_neighbor_entry_t neigh_entry;
    neigh_entry.switch_id = gSwitchId;
    neigh_entry.rif_id = rif_id;
    neigh_entry.ip_address.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    neigh_entry.ip_address.addr.ip4 = htonl(ip);

    sai_attribute_t attr;
    attr.id = SAI_NEIGHBOR_ENTRY_ATTR_DST_MAC_ADDRESS;
    memcpy(attr.value.mac, mac, sizeof(mac));

    status = sai_neighbor_api->create_neighbor_entry(&neigh_entry, 1, &attr);
    return status;
}

sai_object_id_t create_nexthop(
    sai_ip4_t ip,
    sai_object_id_t rif_id)
{
    std::vector<sai_attribute_t> next_hop_attrs;

    sai_attribute_t next_hop_attr;
    next_hop_attr.id = SAI_NEXT_HOP_ATTR_TYPE;
    next_hop_attr.value.s32 = SAI_NEXT_HOP_TYPE_IP;
    next_hop_attrs.push_back(next_hop_attr);

    next_hop_attr.id = SAI_NEXT_HOP_ATTR_IP;
    next_hop_attr.value.ipaddr.addr_family = SAI_IP_ADDR_FAMILY_IPV4;
    next_hop_attr.value.ipaddr.addr.ip4 = htonl(ip);
    next_hop_attrs.push_back(next_hop_attr);

    next_hop_attr.id = SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID;
    next_hop_attr.value.oid = rif_id;
    next_hop_attrs.push_back(next_hop_attr);

    sai_object_id_t next_hop_id;
    sai_status_t status = sai_next_hop_api->create_next_hop(&next_hop_id, gSwitchId,
                                                            next_hop_attrs.size(), next_hop_attrs.data());
    return next_hop_id;
}

sai_object_id_t create_nexthop_group(const std::vector<sai_object_id_t>& nh_ids)
{
    sai_attribute_t nhg_attr;
    std::vector<sai_attribute_t> nhg_attrs;

    nhg_attr.id = SAI_NEXT_HOP_GROUP_ATTR_TYPE;
    nhg_attr.value.s32 = SAI_NEXT_HOP_GROUP_TYPE_ECMP;
    nhg_attrs.push_back(nhg_attr);

    sai_object_id_t next_hop_group_id;
    sai_status_t status = sai_next_hop_group_api->create_next_hop_group(&next_hop_group_id,
                          gSwitchId, (uint32_t)nhg_attrs.size(), nhg_attrs.data());

    for (auto nh_id: nh_ids)
    {
        // Create a next hop group member
        std::vector<sai_attribute_t> nhgm_attrs;

        sai_attribute_t nhgm_attr;
        nhgm_attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_GROUP_ID;
        nhgm_attr.value.oid = next_hop_group_id;
        nhgm_attrs.push_back(nhgm_attr);

        nhgm_attr.id = SAI_NEXT_HOP_GROUP_MEMBER_ATTR_NEXT_HOP_ID;
        nhgm_attr.value.oid = nh_id;
        nhgm_attrs.push_back(nhgm_attr);

        sai_object_id_t next_hop_group_member_id;
        status = sai_next_hop_group_api->create_next_hop_group_member(&next_hop_group_member_id,
                 gSwitchId, (uint32_t)nhgm_attrs.size(), nhgm_attrs.data());
    }

    return next_hop_group_id;
}

sai_status_t create_router_interface_lb(
    sai_object_id_t router_id,
    sai_mac_t mac,
    sai_object_id_t *router_intf)
{
    sai_attribute_t attr;
    std::vector<sai_attribute_t> attrs;

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = router_id;
    attrs.push_back(attr);

    if (mac != NULL)
    {
        attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
        memcpy(attr.value.mac, mac, sizeof(sai_mac_t));
        attrs.push_back(attr);
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_LOOPBACK;
    attrs.push_back(attr);

    sai_status_t status = sai_router_intfs_api->create_router_interface(router_intf, gSwitchId,
                                                (uint32_t)attrs.size(), attrs.data());
}

sai_status_t create_router_interface_port(
    sai_object_id_t router_id,
    sai_object_id_t port_id,
    sai_mac_t mac,
    sai_object_id_t *router_intf)
{
    sai_attribute_t attr;
    std::vector<sai_attribute_t> attrs;

    attr.id = SAI_ROUTER_INTERFACE_ATTR_VIRTUAL_ROUTER_ID;
    attr.value.oid = router_id;
    attrs.push_back(attr);

    if (mac != NULL)
    {
        attr.id = SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS;
        memcpy(attr.value.mac, mac, sizeof(sai_mac_t));
        attrs.push_back(attr);
    }

    attr.id = SAI_ROUTER_INTERFACE_ATTR_TYPE;
    attr.value.s32 = SAI_ROUTER_INTERFACE_TYPE_PORT;
    attrs.push_back(attr);

    attr.id = SAI_ROUTER_INTERFACE_ATTR_PORT_ID;
    attr.value.oid = port_id;
    attrs.push_back(attr);

    sai_status_t status = sai_router_intfs_api->create_router_interface(router_intf, gSwitchId,
                                                (uint32_t)attrs.size(), attrs.data());
}

sai_status_t create_vrid(sai_object_id_t *vr_id)
{
    sai_attribute_t attr;
    sai_status_t status;

    attr.id = SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE;
    attr.value.booldata = true;
    status = sai_virtual_router_api->create_virtual_router(vr_id, gSwitchId, 1, &attr);

    return status;
}

// Main function derived from the use-case

int main(void)
{
    // Some random value for port_id, Need to be adjusted
    sai_object_id_t port_id_1 = 0x100000000000a;
    sai_object_id_t port_id_2 = 0x100000000000b;
    sai_object_id_t port_id_3 = 0x100000000000c;
    sai_object_id_t port_id_4 = 0x100000000000d;
    sai_object_id_t port_id_5 = 0x100000000000e;
    sai_object_id_t port_id_6 = 0x100000000000f;

    sai_attribute_t switch_attr;
    sai_status_t status;
    sai_ip4_t ip4, mask;

    switch_attr.id = SAI_SWITCH_ATTR_VXLAN_DEFAULT_ROUTER_MAC;
    memcpy(switch_attr.value.mac, gSwitchMac, sizeof(sai_mac_t));
    sai_switch_api->set_switch_attribute(gSwitchId, &switch_attr);

    switch_attr.id = SAI_SWITCH_ATTR_VXLAN_DEFAULT_PORT;
    switch_attr.value.u16 = 12345;
    sai_switch_api->set_switch_attribute(gSwitchId, &switch_attr);

    switch_attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;
    status = sai_switch_api->get_switch_attribute(gSwitchId, 1, &switch_attr);
    sai_object_id_t default_vrid = switch_attr.value.oid;

    /*
     * Setup underlay default route, the nexthop is 1.1.1.1, 2.2.2.1 (ECMP)
     */
    std::vector<sai_object_id_t> nh_ids;
    sai_object_id_t nh_id, rif_id, underlay_rif;

    create_router_interface_lb(default_vrid, gSwitchMac, &underlay_rif);

    create_router_interface_port(default_vrid, port_id_5, gSwitchMac, &rif_id);
    ip4 = 0x01010101; //1.1.1.1
    sai_mac_t underlay_mac1 = {0x00,0x00,0x0a,0x0b,0x0c,0x01};
    status = create_neighbor(ip4, rif_id, underlay_mac1);
    nh_id = create_nexthop(ip4, rif_id);
    nh_ids.push_back(nh_id);

    create_router_interface_port(default_vrid, port_id_6, gSwitchMac, &rif_id);
    ip4 = 0x02020201; //2.2.2.1
    sai_mac_t underlay_mac2 = {0x00,0x00,0x0a,0x0b,0x0c,0x02};
    status = create_neighbor(ip4, rif_id, underlay_mac2);
    nh_id = create_nexthop(ip4, rif_id);
    nh_ids.push_back(nh_id);

    sai_object_id_t nh_group_id = create_nexthop_group(nh_ids);

    ip4 = 0x00000000; //0.0.0.0
    mask = 0x00000000; //0.0.0.0
    status = create_route(ip4, mask, default_vrid, nh_group_id);

    /*
     * Setup overlay route
     */
    sai_object_id_t vrid_1_ingress, vrid_1_egress;
    sai_object_id_t vrid_2_ingress, vrid_2_egress;
    sai_object_id_t vrid_3_ingress, vrid_3_egress;
    sai_object_id_t rif_1, rif_2, rif_3, rif_4;

    /* create virtual router for C1 */
    create_vrid(&vrid_1_ingress);
    create_vrid(&vrid_1_egress);

    /* create virtual router for C3 */
    create_vrid(&vrid_2_ingress);
    create_vrid(&vrid_2_egress);

    /* create virtual router for C4 */
    create_vrid(&vrid_3_ingress);
    create_vrid(&vrid_3_egress);

    /* create port-based router interface for C1 */
    status = create_router_interface_port(vrid_1_ingress, port_id_1, NULL, &rif_1);
    ip4 = 0x64640301; //"100.100.3.1" ;
    sai_mac_t mac_1 = {0x00,0x00,0x00,0x00,0x00,0x01}; //"00:00:00:00:00:01"
    status = create_neighbor(ip4, rif_1, mac_1);

    /* create port-based router interface for C2 */
    status = create_router_interface_port(vrid_1_ingress, port_id_2, NULL, &rif_2);
    ip4 = 0x64640401; //"100.100.4.1" ;
    sai_mac_t mac_2 = {0x00,0x00,0x00,0x00,0x00,0x02}; //"00:00:00:00:00:02"
    status = create_neighbor(ip4, rif_2, mac_2);

    /* create port-based router interface for C3 */
    status = create_router_interface_port(vrid_2_ingress, port_id_3, NULL, &rif_3);
    ip4 = 0x64660101; //"100.102.1.1" ;
    sai_mac_t mac_3 = {0x00,0x00,0x00,0x00,0x00,0x03}; //"00:00:00:00:00:03"
    status = create_neighbor(ip4, rif_3, mac_3);

    /* create port-based router interface for C4 */
    status = create_router_interface_port(vrid_3_ingress, port_id_4, NULL, &rif_4);
    ip4 = 0x64650101; //"100.101.1.1" ;
    sai_mac_t mac_4 = {0x00,0x00,0x00,0x00,0x00,0x04}; //"00:00:00:00:00:04"
    status = create_neighbor(ip4, rif_3, mac_4);


    /* create tunnel with tunnel map for C1 and C2 */
    sai_object_id_t tunnel_id, tunnel_encap_map_id, tunnel_decap_map_id;
    status = create_tunnel(vrid_1_ingress, vrid_1_egress, underlay_rif, 2000,
                           &tunnel_id, &tunnel_encap_map_id, &tunnel_decap_map_id);

    /* add tunnel map entry for C3 */
    create_encap_tunnel_map_entry(tunnel_encap_map_id, vrid_2_ingress, 2001);
    create_decap_tunnel_map_entry(tunnel_decap_map_id, vrid_2_egress, 2001);

    /* add tunnel map entry for C4 */
    create_encap_tunnel_map_entry(tunnel_encap_map_id, vrid_3_ingress, 2005);
    create_decap_tunnel_map_entry(tunnel_decap_map_id, vrid_3_egress, 2005);

    /* create tunnel decap for VM to customer server */
    ip4 = 0x0a0a0a0a; // "10.10.10.10"
    sai_object_id_t term_table_id;
    status = create_tunnel_termination(tunnel_id, default_vrid, ip4, &term_table_id);

    /* create tunnel nexthop for VM1, VM2 and VM3 */
    sai_object_id_t nexthop_id_1, nexthop_id_2, nexthop_id_3;
    ip4 = 0x0a0a0a01; // "10.10.10.1"
    status = create_nexthop_tunnel(ip4, 2000, NULL, tunnel_id, &nexthop_id_1);
    ip4 = 0x0a0a0a02; // "10.10.10.2"
    sai_mac_t mac = {0x00,0x12,0x34,0x56,0x78,0x9a}; // "00:12:34:56:78:9a"
    status = create_nexthop_tunnel(ip4, 2001, mac, tunnel_id, &nexthop_id_2);
    ip4 = 0x0a0a0a03; // "10.10.10.3"
    status = create_nexthop_tunnel(ip4, 0, NULL, tunnel_id, &nexthop_id_3);

    sai_ip4_t dest;
    sai_ip4_t mask_32=0xffffffff; // For /32 prefix
    sai_ip4_t mask_24=0xffffff00; // For /24 prefix

    /* create routes for vrid 1 ingress */
    dest = 0x64640101; // "100.100.1.1/32"
    status = create_route(dest, mask_32, vrid_1_ingress, nexthop_id_1);
    dest = 0x64640201; // "100.100.2.1/32"
    status = create_route(dest, mask_32, vrid_1_ingress, nexthop_id_2);
    dest = 0x64640300; // "100.100.3.0/24"
    status = create_route(dest, mask_24, vrid_1_ingress, rif_1);
    dest = 0x64640400; // "100.100.4.0/24"
    status = create_route(dest, mask_24, vrid_1_ingress, rif_2);
    dest = 0x64660100; // "100.102.1.0/24"
    status = create_route(dest, mask_24, vrid_1_ingress, rif_3);

    /* create routes for vrid 1 egress */
    dest = 0x64640300; // "100.100.3.0/24"
    status = create_route(dest, mask_24, vrid_1_egress, rif_1);
    dest = 0x64640400; // "100.100.4.0/24"
    status = create_route(dest, mask_24, vrid_1_egress, rif_2);

    /* create routes for vrid 2 ingress */
    dest = 0x64640101; // "100.100.1.1/32"
    status = create_route(dest, mask_32, vrid_2_ingress, nexthop_id_1);
    dest = 0x64640201; // "100.100.2.1/32"
    status = create_route(dest, mask_32, vrid_2_ingress, nexthop_id_2);
    dest = 0x64640300; // "100.100.3.0/24"
    status = create_route(dest, mask_24, vrid_2_ingress, rif_1);
    dest = 0x64640400; // "100.100.4.0/24"
    status = create_route(dest, mask_24, vrid_2_ingress, rif_2);
    dest = 0x64660100; // "100.102.1.0/24"
    status = create_route(dest, mask_24, vrid_2_ingress, rif_3);

    /* create routes for vrid 2 egress */
    dest = 0x64660100; // "100.102.1.0/24"
    status = create_route(dest, mask_24, vrid_2_egress, rif_3);

    /* create routes for vrid 3 ingress */
    dest = 0x64650201; // "100.101.2.1/32"
    status = create_route(dest, mask_32, vrid_3_ingress, nexthop_id_3);
    dest = 0x64650100; // "100.101.1.0/24"
    status = create_route(dest, mask_24, vrid_3_ingress, rif_4);

    /* create routes for vrid 3 egress */
    dest = 0x64650100; // "100.101.1.0/24"
    status = create_route(dest, mask_24, vrid_3_egress, rif_4);

    return 0;
}
