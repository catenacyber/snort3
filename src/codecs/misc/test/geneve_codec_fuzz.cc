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

#include "../cd_geneve.cc"

#include "utils/endian.h"

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

namespace snort
{
    bool TextLog_Print(TextLog* const, const char*, ...) { return false; }
    void Codec::codec_event(const CodecData&, CodecSid) { }
    bool SnortConfig::tunnel_bypass_enabled(unsigned short) const { return false; }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    GeneveCodec geneve_codec;
    RawData raw_data(nullptr, data, size);
    CodecData codec_data(nullptr, ProtocolId::GENEVE);
    DecodeData decode_data;

    geneve_codec.decode(raw_data, codec_data, decode_data);
    return 0;
}
