# CMakeLists.txt
#
# Copyright 2023 Missing Link Electronics Inc,
# Björn Petersen <bjoern.petersen@missinglinkelectronics.com>
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

cmake_minimum_required(VERSION 3.1)

project(HomaDissector VERSION 0.0.1 DESCRIPTION "Wireshark Homa Plugin" LANGUAGES C)
option(INSTALL_PLUGIN_LOCAL "Install the homa dissector plugin inside the local folder of wireshark" ON)

find_package(Wireshark CONFIG REQUIRED)

if (NOT Wireshark_PLUGINS_ENABLED)
    message(FATAL_ERROR "Wireshark was compiled without support for plugins")
endif ()

set(CMAKE_C_VISIBILITY_PRESET hidden)
if (CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "-Wall -Wextra ${CMAKE_C_FLAGS}")
endif ()

add_definitions(-DVERSION=\"${PROJECT_VERSION}\")

add_library(${PROJECT_NAME} MODULE homa.c)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" DEFINE_SYMBOL "")
target_link_libraries(${PROJECT_NAME} epan)

if (${INSTALL_PLUGIN_LOCAL})
    install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION "$ENV{HOME}/.local/lib/wireshark/plugins/${Wireshark_MAJOR_VERSION}.${Wireshark_MINOR_VERSION}/epan" NAMELINK_SKIP)
else ()
    install(TARGETS ${PROJECT_NAME} LIBRARY DESTINATION "${Wireshark_PLUGIN_INSTALL_DIR}/epan" NAMELINK_SKIP)
endif ()
