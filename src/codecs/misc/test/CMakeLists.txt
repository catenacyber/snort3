add_cpputest(geneve_codec_test
    SOURCES
        ../../../framework/module.cc
)

add_fuzztest(geneve_codec_fuzz
    SOURCES
        ../../../framework/module.cc
        ../cd_geneve.cc
        ../cd_gtp.cc
        ../cd_icmp4_ip.cc
        ../cd_icmp6_ip.cc
        ../cd_llc.cc
        ../cd_teredo.cc
        ../cd_vxlan.cc
)
