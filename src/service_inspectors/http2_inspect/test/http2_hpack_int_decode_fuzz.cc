//--------------------------------------------------------------------------
// Copyright (C) 2024 Cisco and/or its affiliates. All rights reserved.
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

// http2_hpack_int_decode_test.cc author Maya Dagon <mdagon@cisco.com>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../http2_enum.h"

using namespace Http2Enums;
#include "../http2_hpack_int_decode.h"
#include "../http2_varlen_int_decode_impl.h"

namespace snort
{
// Stubs whose sole purpose is to make the test code link
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    Http2EventGen local_events;
    Http2Infractions local_inf;
    uint32_t bytes_processed = 0;
    uint64_t res = 0;
    // take one byte between 4 and 8 included
    Http2HpackIntDecode* const decode = new Http2HpackIntDecode(((data[0]&0x7)%5)+4);

    decode->translate(data+1, size-1, bytes_processed, res, &local_events, &local_inf,
        false);

    delete decode;
    return 0;
}
