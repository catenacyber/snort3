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

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

namespace snort
{
    bool TextLog_Print(TextLog* const, const char*, ...) { return false; }
    bool TextLog_Putc(TextLog* const, char) { return false; }
    bool TextLog_Write(TextLog* const, const char*, int len) { return false; }
    void Codec::codec_event(const CodecData&, CodecSid) { }
    bool SnortConfig::tunnel_bypass_enabled(unsigned short) const { return false; }
    const SnortConfig* SnortConfig::get_conf() { return NULL; }
    uint16_t ip::IpApi::dgram_len() const { return 0; }
    const char* PacketManager::get_proto_name(IpProtocol) { return "dummy"; }
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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (fuzz_init == 0) {
        load_proto((const CodecApi*)cd_geneve[0]);
        load_proto((const CodecApi*)cd_gtp[0]);
        load_proto((const CodecApi*)cd_icmp4_ip[0]);
        load_proto((const CodecApi*)cd_icmp6_ip[0]);
        load_proto((const CodecApi*)cd_llc[0]);
        load_proto((const CodecApi*)cd_teredo[0]);
        load_proto((const CodecApi*)cd_vxlan[0]);
        fuzz_init = 1;
    }
    if (size < 2) {
        return 0;
    }

    ProtocolId prot = (ProtocolId) ((data[0] << 8) | (data[1]));
    Codec *codec = s_protocols[(int)prot];
    if (codec == NULL) {
        return 0;
    }
    CodecData codec_data(nullptr, prot);

    RawData raw_data(nullptr, data + 2, size - 2);
    DecodeData decode_data;

    codec->decode(raw_data, codec_data, decode_data);
    return 0;
}
