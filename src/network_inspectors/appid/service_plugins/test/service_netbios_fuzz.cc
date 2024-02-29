//--------------------------------------------------------------------------
// Copyright (C) 2020-2024 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// service_netbios_test.cc author Kani Murthi<kamurthi@cisco.com>
// unit test for service_netbios
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "protocols/packet.h"

void ServiceDiscovery::initialize(AppIdInspector&) {}
void ServiceDiscovery::reload() {}
void ServiceDiscovery::finalize_service_patterns() {}
void ServiceDiscovery::match_by_pattern(AppIdSession&, const Packet*, IpProtocol) {}
void ServiceDiscovery::get_port_based_services(IpProtocol, uint16_t, AppIdSession&) {}
void ServiceDiscovery::get_next_service(const Packet*, const AppidSessionDirection, AppIdSession&)
{}
int ServiceDiscovery::identify_service(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return 0; }
int ServiceDiscovery::add_ftp_service_state(AppIdSession&) { return 0; }
bool ServiceDiscovery::do_service_discovery(AppIdSession&, Packet*, AppidSessionDirection,
    AppidChangeBits&) { return false; }
int ServiceDiscovery::incompatible_data(AppIdSession&, const Packet*,AppidSessionDirection,
    ServiceDetector*) { return 0; }
int ServiceDiscovery::fail_service(AppIdSession&, const Packet*, AppidSessionDirection,
    ServiceDetector*, ServiceDiscoveryState*) { return 0; }
int ServiceDiscovery::add_service_port(AppIdDetector*,
    const ServiceDetectorPort&) { return APPID_EINVALID; }
void AppIdSessionApi::set_netbios_name(AppidChangeBits&, const char*) {}
void AppIdSessionApi::set_netbios_domain(AppidChangeBits&, const char*) {}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 7)
        return 0;
    AppidSessionDirection dir = (data[0] & 1) ? APP_ID_FROM_INITIATOR : APP_ID_FROM_RESPONDER;
    IpProtocol iprot = (data[0] & 2) ? IpProtocol::TCP : IpProtocol::UDP;
    AppIdInspector ins;
    OdpContext odp_ctxt(config, nullptr);
    snort::Packet pkt;
    AppidChangeBits cb;
    SfIp ip;
    AppIdSession asd(iprot, &ip, data[5] << 8 | data[6], ins, odp_ctxt);
    AppIdDiscoveryArgs args(data+7, size-7, dir, asd, &pkt,cb);
    /*AppIdDiscoveryArgs args;
    args.size = size-7;
    args.data = data+7;
    args.dir = dir;*/
    ServiceDiscovery& s_discovery_manager = asd.get_odp_ctxt().get_service_disco_mgr();
    args.pkt->ptrs.sp = data[1] << 8 | data[2];
    args.pkt->ptrs.dp = data[3] << 8 | data[4];
    NbdgmServiceDetector nsd(&s_discovery_manager);
    nsd.validate(args);
    asd.free_flow_data();
    delete &asd.get_api();
    return 0;
}
