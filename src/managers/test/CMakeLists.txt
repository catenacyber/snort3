add_cpputest(get_inspector_test
    SOURCES
        get_inspector_stubs.h
        ../inspector_manager.cc
)

#to move with main.cc snort exec add_fuzztest(packet_manager_decode_fuzz
#    LIBS protocols managers log parser main packet_io ${STATIC_CODEC_PLUGINS} framework target_based utils ${STATIC_NETWORK_INSPECTOR_PLUGINS} detection trace flow profiler helpers ips_options loggers ${LUAJIT_LIBRARIES} lua ports events filter sfip hash ips_actions time stream memory file_api side_channel latency control codecs payload_injector js_norm host_tracker dump_config ${OPENSSL_CRYPTO_LIBRARY} ${PCAP_LIBRARIES} ${DAQ_LIBRARIES} ${PCRE_LIBRARIES} ${ZLIB_LIBRARIES} ${LIBLZMA_LIBRARIES} connectors search_engines policy_selectors network_inspectors sfrt file_connector tcp_connector
#)
