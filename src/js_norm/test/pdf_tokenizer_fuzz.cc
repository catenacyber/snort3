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
// pdf_tokenizer_test.cc author Cisco

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <vector>

#include <FlexLexer.h>

#include "catch/catch.hpp"
#include "js_norm/pdf_tokenizer.h"

using namespace jsn;
using namespace std;
using namespace std::string_literals;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string str((char *)data, size);
    istringstream in(str);
    ostringstream out;
    PDFTokenizer extractor(in, out);
    extractor.process();
    return 0;
}
