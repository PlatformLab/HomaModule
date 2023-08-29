# CMakeLists.txt
#
# Copyright 2023 Missing Link Electronics Inc,
# Björn Petersen <bjoern.petersen@missinglinkelectronics.com>
#
# This code is dual licensed under one of the following 2 licenses:
#
#                          ################
#                          # GPL2 License #
#                          ################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#
#                          ################
#                          # HOMA License #
#                          ################
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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
