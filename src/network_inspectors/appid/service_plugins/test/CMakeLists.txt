
include_directories ( appid PRIVATE ${APPID_INCLUDE_DIR} )

add_cpputest( service_rsync_test )
add_cpputest( alpn_patterns_tests )

add_fuzztest( service_netbios_fuzz
    SOURCES
        ../service_detector.cc
        ../service_netbios.cc
)