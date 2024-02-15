//--------------------------------------------------------------------------
// Copyright (C) 2023-2024 Cisco and/or its affiliates. All rights reserved.
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
// geneve_codec_test.cc author Steve Chew <stechew@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "utils/endian.h"
#include "framework/codec.h"
#include "protocols/protocol_ids.h"
#include "main/snort_config.h"
#include "codecs/codec_module.h"
#include "log/text_log.h"
#include "protocols/packet_manager.h"
#include "protocols/layer.h"
#include "detection/detection_engine.h"
#include "stream/stream.h"

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }
sfip_var_t* sfip_var_from_string(const char* addr, const char* caller) { return NULL; }
void sfvar_free(sfip_var_t* var) { }
unsigned int get_random_seed() { return 42; }
bool sfvar_ip_in(sfip_var_t* var, const snort::SfIp* ip) {return false;}

NetworkPolicy np;
NetworkPolicy::NetworkPolicy(unsigned int, unsigned int) { }
NetworkPolicy::~NetworkPolicy() = default;

namespace snort
{
    SnortConfig::SnortConfig(snort::SnortConfig const*, const char*) { }
    SnortConfig::~SnortConfig() = default;

NetworkPolicy* get_network_policy() { return &np; }
InspectionPolicy* get_inspection_policy() { return nullptr; }

    bool TextLog_Print(TextLog* const, const char*, ...) { return false; }
    bool TextLog_Putc(TextLog* const, char) { return false; }
    bool TextLog_Write(TextLog* const, const char*, int len) { return false; }
    void LogEthAddrs(TextLog*, const eth::EtherHdr*) { }
    void LogTcpOptions(TextLog*, const tcp::TCPHdr*, uint16_t valid_tcp_len) { }
    void CreateTCPFlagString(const tcp::TCPHdr* const, char*) { }
    void LogIpOptions(TextLog*, const ip::IP4Hdr*, uint16_t valid_ip4_len) { }
    bool SnortConfig::tunnel_bypass_enabled(unsigned short) const { return false; }
    int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
    const SnortConfig* SnortConfig::get_conf() { return NULL; }
    const char* PacketManager::get_proto_name(IpProtocol) { return "dummy"; }
    Layer Flow::get_mpls_layer_per_dir(bool client) {Layer dummy = {}; return dummy;}
    bool Stream::get_held_pkt_seq(Flow*, uint32_t&) {return false;}
    char* snort_strdup(const char* str) { return strdup(str);}
}

using namespace snort;

static int fuzz_init = 0;
static Codec* s_protocols[0x10000];

static void load_proto(const CodecApi* api) {
    Codec *codec = api->ctor(NULL);
    std::vector<ProtocolId> ids;
    codec->get_protocol_ids(ids);
    for(ProtocolId& id : ids) {
        s_protocols[(int)id] = codec;
    }
}

extern const BaseApi* cd_geneve[];
extern const BaseApi* cd_gtp[];
extern const BaseApi* cd_icmp4_ip[];
extern const BaseApi* cd_icmp6_ip[];
extern const BaseApi* cd_llc[];
extern const BaseApi* cd_teredo[];
extern const BaseApi* cd_vxlan[];

extern const BaseApi* cd_ah[];
extern const BaseApi* cd_dstopts[];
extern const BaseApi* cd_esp[];
extern const BaseApi* cd_frag[];
extern const BaseApi* cd_gre[];
extern const BaseApi* cd_hopopts[];
extern const BaseApi* cd_icmp4[];
extern const BaseApi* cd_icmp6[];
extern const BaseApi* cd_igmp[];
extern const BaseApi* cd_ipv4[];
extern const BaseApi* cd_ipv6[];
extern const BaseApi* cd_mobility[];
extern const BaseApi* cd_pgm[];
extern const BaseApi* cd_routing[];
extern const BaseApi* cd_tcp[];
//needs access to ip layer extern const BaseApi* cd_udp[];

extern const BaseApi* cd_arp[];
extern const BaseApi* cd_ciscometadata[];
extern const BaseApi* cd_erspan2[];
extern const BaseApi* cd_erspan3[];
extern const BaseApi* cd_fabricpath[];
extern const BaseApi* cd_mpls[];
extern const BaseApi* cd_pppencap[];
extern const BaseApi* cd_pppoepkt[];
extern const BaseApi* cd_transbridge[];
extern const BaseApi* cd_vlan[];

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (fuzz_init == 0) {
        load_proto((const CodecApi*)cd_geneve[0]);
        load_proto((const CodecApi*)cd_gtp[0]);
        load_proto((const CodecApi*)cd_icmp4_ip[0]);
        load_proto((const CodecApi*)cd_icmp6_ip[0]);
        load_proto((const CodecApi*)cd_llc[0]);
        load_proto((const CodecApi*)cd_teredo[0]);
        load_proto((const CodecApi*)cd_vxlan[0]);

        load_proto((const CodecApi*)cd_ah[0]);
        load_proto((const CodecApi*)cd_dstopts[0]);
        load_proto((const CodecApi*)cd_esp[0]);
        load_proto((const CodecApi*)cd_frag[0]);
        load_proto((const CodecApi*)cd_gre[0]);
        load_proto((const CodecApi*)cd_hopopts[0]);
        load_proto((const CodecApi*)cd_icmp4[0]);
        load_proto((const CodecApi*)cd_icmp6[0]);
        load_proto((const CodecApi*)cd_igmp[0]);
        load_proto((const CodecApi*)cd_ipv4[0]);
        load_proto((const CodecApi*)cd_ipv6[0]);
        load_proto((const CodecApi*)cd_mobility[0]);
        load_proto((const CodecApi*)cd_pgm[0]);
        load_proto((const CodecApi*)cd_routing[0]);
        load_proto((const CodecApi*)cd_tcp[0]);
        //load_proto((const CodecApi*)cd_udp[0]);

        load_proto((const CodecApi*)cd_arp[0]);
        load_proto((const CodecApi*)cd_ciscometadata[0]);
        load_proto((const CodecApi*)cd_erspan2[0]);
        load_proto((const CodecApi*)cd_erspan3[0]);
        load_proto((const CodecApi*)cd_fabricpath[0]);
        load_proto((const CodecApi*)cd_mpls[0]);
        load_proto((const CodecApi*)cd_pppencap[0]);
        load_proto((const CodecApi*)cd_pppoepkt[0]);
        load_proto((const CodecApi*)cd_transbridge[0]);
        load_proto((const CodecApi*)cd_vlan[0]);

        fuzz_init = 1;
    }
    if (size < 2) {
        return 0;
    }

    SnortConfig sc;
    ProtocolId prot = (ProtocolId) ((data[0] << 8) | (data[1]));
    Codec *codec = s_protocols[(int)prot];
    if (codec == NULL) {
        return 0;
    }
    CodecData codec_data(&sc, prot);

    DAQ_Msg_t msg = {0};
    DAQ_PktHdr_t ph = {0};
    msg.hdr = &ph;
    RawData raw_data(&msg, data + 2, size - 2);
    DecodeData decode_data;

    codec->decode(raw_data, codec_data, decode_data);
    return 0;
}
