//--------------------------------------------------------------------------
// Copyright (C) 2016-2024 Cisco and/or its affiliates. All rights reserved.
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

// http_uri_norm_test.cc author Tom Peters <thopeter@cisco.com>
// unit test main

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "helpers/literal_search.h"
#include "log/messages.h"

#include "service_inspectors/http_inspect/http_js_norm.h"
#include "service_inspectors/http_inspect/http_uri_norm.h"

using namespace snort;

namespace snort
{
// Stubs whose sole purpose is to make the test code link
void ParseWarning(WarningGroup, const char*, ...) {}
void ParseError(const char*, ...) {}
void Value::get_bits(std::bitset<256ul>&) const {}
void Value::set_first_token() {}
bool Value::get_next_csv_token(std::string&) { return false; }
bool Value::get_next_token(std::string& ) { return false; }
int DetectionEngine::queue_event(unsigned int, unsigned int) { return 0; }
LiteralSearch::Handle* LiteralSearch::setup() { return nullptr; }
void LiteralSearch::cleanup(LiteralSearch::Handle*) {}
LiteralSearch* LiteralSearch::instantiate(LiteralSearch::Handle*, const uint8_t*, unsigned, bool,
    bool) { return nullptr; }
void DecodeConfig::set_decompress_pdf(bool) {}
void DecodeConfig::set_decompress_swf(bool) {}
void DecodeConfig::set_decompress_zip(bool) {}
void DecodeConfig::set_decompress_vba(bool) {}
SearchTool::~SearchTool() {}
}

snort::SearchTool* js_create_mpse_open_tag() { return nullptr; }
snort::SearchTool* js_create_mpse_tag_type() { return nullptr; }
snort::SearchTool* js_create_mpse_tag_attr() { return nullptr; }

void show_stats(PegCount*, const PegInfo*, unsigned, const char*) { }
void show_stats(PegCount*, const PegInfo*, const IndexVec&, const char*, FILE*) { }

int64_t Parameter::get_int(char const*) { return 0; }

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    uint8_t* buffer = new uint8_t[size];
    HttpParaList::UriParam uri_param;
    HttpInfractions infractions;
    HttpEventGen events;
    if (data[0] & 1)
        uri_param.percent_u = true; // cppcheck-suppress unreadVariable
    if (data[0] & 2) {
        uri_param.iis_unicode = true;   // cppcheck-suppress unreadVariable
        uri_param.unicode_map = new uint8_t[65536];
    }
    if (data[0] & 4)
        uri_param.utf8_bare_byte = true;    // cppcheck-suppress unreadVariable
    if (data[0] & 8)
        uri_param.iis_double_decode = true; // cppcheck-suppress unreadVariable
    if (data[0] & 0x10)
        uri_param.backslash_to_slash = true;    // cppcheck-suppress unreadVariable
    Field input(size-1, data+1);
    Field result;
    UriNormalizer::normalize(input, result, true, buffer, uri_param, &infractions, &events);
    delete[] buffer;
    return 0;
}
