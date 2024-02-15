add_cpputest( http2_hpack_int_decode_test )

add_cpputest( http2_hpack_string_decode_test
  SOURCES
        ../http2_huffman_state_machine.cc
)

#uninteresting add_fuzztest( http2_hpack_int_decode_fuzz )

add_fuzztest( http2_hpack_string_decode_fuzz
  SOURCES
        ../http2_huffman_state_machine.cc
)
