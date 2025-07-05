cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME age)

# DuckDB's extension distribution supports vcpkg. As such, dependencies can be added in ./vcpkg.json and then
# used in cmake with find_package. Feel free to remove or replace with other dependencies.
# Note that it should also be removed from vcpkg.json to prevent needlessly installing it..
find_package(OpenSSL REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})
include_directories(src/include)

# Add Rust build as external project
include(ExternalProject)

ExternalProject_Add(
    rust_age_crypto
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/rust
    CONFIGURE_COMMAND ""
    BUILD_COMMAND cargo build --release
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/rust/target/release/libduckdb_age_crypto.a
    BUILD_IN_SOURCE 1
)

# Add Rust library
add_library(age_crypto STATIC IMPORTED)
set_target_properties(age_crypto PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/rust/target/release/libduckdb_age_crypto.a
)

set(EXTENSION_SOURCES src/age_extension.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

# Link Rust library and OpenSSL in both the static library as the loadable extension
target_link_libraries(${EXTENSION_NAME} age_crypto OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(${LOADABLE_EXTENSION_NAME} age_crypto OpenSSL::SSL OpenSSL::Crypto)
add_dependencies(${EXTENSION_NAME} rust_age_crypto)
add_dependencies(${LOADABLE_EXTENSION_NAME} rust_age_crypto)

# Link system libraries required by Rust
if(APPLE)
    target_link_libraries(${EXTENSION_NAME} "-framework Security")
    target_link_libraries(${LOADABLE_EXTENSION_NAME} "-framework Security")
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
