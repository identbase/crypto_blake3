cmake_minimum_required(VERSION 3.7 FATAL_ERROR)
project(blake3_library VERSION 1.0.0 LANGUAGES C)
add_library(blake3_library SHARED blake3.c blake3.def)
add_executable(blake3_test example.c)

set_target_properties(blake3_library PROPERTIES
    PUBLIC_HEADER blake3.h
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "blake3"
    XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "CFE0FA7C0643DA3DD685147E510D763A6A231FE3"
)
