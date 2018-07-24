# Copyright (c) 1996-2018, OPC Foundation. All rights reserved.
#
#   The source code in this file is covered under a dual-license scenario:
#     - RCL: for OPC Foundation members in good-standing
#     - GPL V2: everybody else
#
#   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/
#
#   GNU General Public License as published by the Free Software Foundation;
#   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2
#
#   This source code is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

if(WIN32)
    #
    # Hint at old root folder (see build_win32/build_win64.bat)
    #
    set (OPENSSL_ROOT_DIR ${_PROJECT_ROOT}/openssl)
endif(WIN32)
find_package(OpenSSL REQUIRED)

if(WIN32)
    set(UASTACK_PLATFORM_DIR win32)
else()
    set(UASTACK_PLATFORM_DIR linux)
endif()

    set(_uastack_src
        core/opcua_buffer.c
        core/opcua_core.c
        core/opcua_datetime.c
        core/opcua_guid.c
        core/opcua_list.c
        core/opcua_memory.c
        core/opcua_memorystream.c
        core/opcua_proxystub.c
        core/opcua_string.c
        core/opcua_thread.c
        core/opcua_timer.c
        core/opcua_trace.c
        core/opcua_utilities.c

        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_binary.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_cryptofactory.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_datetime.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_guid.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_interface.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_internal.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_memory.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_mutex.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_aes.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_hmac_sha.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_nosecurity.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_pki.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_pki_nosecurity.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_random.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_rsa.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_sha.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_openssl_x509.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_pkifactory.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_semaphore.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_socket.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_socket_interface.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_socket_internal.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_socket_ssl.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_string.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_thread.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_timer.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_trace.c
        platforms/${UASTACK_PLATFORM_DIR}/opcua_p_utilities.c

        proxystub/clientproxy/opcua_asynccallstate.c
        proxystub/clientproxy/opcua_channel.c
        proxystub/clientproxy/opcua_clientapi.c
        proxystub/serverstub/opcua_endpoint.c
        proxystub/serverstub/opcua_serverapi.c
        proxystub/serverstub/opcua_servicetable.c

        securechannel/opcua_secureconnection.c
        securechannel/opcua_securelistener.c
        securechannel/opcua_securelistener_channelmanager.c
        securechannel/opcua_securelistener_policymanager.c
        securechannel/opcua_securestream.c
        securechannel/opcua_soapsecurechannel.c
        securechannel/opcua_tcpsecurechannel.c

        stackcore/opcua_binarydecoder.c
        stackcore/opcua_binaryencoder.c
        stackcore/opcua_builtintypes.c
        stackcore/opcua_connection.c
        stackcore/opcua_crypto.c
        stackcore/opcua_decoder.c
        stackcore/opcua_encodeableobject.c
        stackcore/opcua_encoder.c
        stackcore/opcua_enumeratedtype.c
        stackcore/opcua_extensionobject.c
        stackcore/opcua_listener.c
        stackcore/opcua_messagecontext.c
        stackcore/opcua_pki.c
        stackcore/opcua_securechannel.c
        stackcore/opcua_stream.c
        stackcore/opcua_stringtable.c
        stackcore/opcua_types.c

        transport/https/opcua_httpsconnection.c
        transport/https/opcua_httpslistener.c
        transport/https/opcua_httpslistener_connectionmanager.c
        transport/https/opcua_httpsstream.c
        transport/https/opcua_https_internal.c

        transport/tcp/opcua_tcpconnection.c
        transport/tcp/opcua_tcplistener.c
        transport/tcp/opcua_tcplistener_connectionmanager.c
        transport/tcp/opcua_tcpstream.c
    )

if(WIN32)
    list(APPEND _uastack_src
        platforms/win32/opcua_p_win32_pki.c
    )
else()
    set(CMAKE_THREAD_PREFER_PTHREAD 1)
#     set(THREADS_PREFER_PTHREAD_FLAG 1)
    find_package(Threads)
endif()

set(UASTACK_HEADERS
    core/opcua_buffer.h
    core/opcua_config.h
    core/opcua_core.h
    core/opcua_datetime.h
    core/opcua_errorhandling.h
    core/opcua_exclusions.h
    core/opcua_guid.h
    core/opcua_memory.h
    core/opcua_memorystream.h
    core/opcua_proxystub.h
    core/opcua_socket.h
    core/opcua_stackstatuscodes.h
    core/opcua_statuscodes.h
    core/opcua_string.h
    core/opcua_thread.h
    core/opcua_timer.h
    core/opcua_trace.h
    core/opcua_utilities.h
    platforms/${UASTACK_PLATFORM_DIR}/opcua_p_crypto.h
    platforms/${UASTACK_PLATFORM_DIR}/opcua_p_interface.h
    platforms/${UASTACK_PLATFORM_DIR}/opcua_p_pki.h
    platforms/${UASTACK_PLATFORM_DIR}/opcua_p_types.h
    platforms/${UASTACK_PLATFORM_DIR}/opcua_p_utilities.h
    platforms/${UASTACK_PLATFORM_DIR}/opcua_platformdefs.h
    proxystub/clientproxy/opcua_channel.h
    proxystub/clientproxy/opcua_clientapi.h
    proxystub/serverstub/opcua_endpoint.h
    proxystub/serverstub/opcua_serverapi.h
    stackcore/opcua_attributes.h
    stackcore/opcua_binaryencoder.h
    stackcore/opcua_builtintypes.h
    stackcore/opcua_browsenames.h
    stackcore/opcua_connection.h
    stackcore/opcua_credentials.h
    stackcore/opcua_crypto.h
    stackcore/opcua_decoder.h
    stackcore/opcua_encodeableobject.h
    stackcore/opcua_encoder.h
    stackcore/opcua_enumeratedtype.h
    stackcore/opcua_identifiers.h
    stackcore/opcua_messagecontext.h
    stackcore/opcua_pki.h
    stackcore/opcua_stream.h
    stackcore/opcua_stringtable.h
    stackcore/opcua_types.h
)

    add_library(uastack ${_uastack_src})
    set_target_properties(uastack PROPERTIES
        SOVERSION   ${PROJECT_VERSION_MAJOR}
        VERSION     ${PROJECT_VERSION}
    )
    target_include_directories(uastack
        PUBLIC
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/core>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/stackcore>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/proxystub/clientproxy>"
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/proxystub/serverstub>"
            "$<INSTALL_INTERFACE:include/uastack>"
        PRIVATE
            securechannel
            transport/https
            transport/tcp
    )
    option(trace_enable "set to OFF to disable stack tracing." ON)
if (trace_enable)
    target_compile_definitions(uastack PUBLIC OPCUA_TRACE_ENABLE)
endif()
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    target_compile_definitions(uastack PUBLIC _DEBUG)
endif()
if(WIN32)
    target_include_directories(uastack PUBLIC platforms/win32)
    if(MSVC)
        target_compile_definitions(uastack
            PUBLIC _CRT_SECURE_NO_WARNINGS
            PUBLIC STRICT
        )
        if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
            target_compile_definitions(uastack PUBLIC _CRTDBG_MAP_ALLOC)
        else()
            target_compile_definitions(uastack PUBLIC NDEBUG)
        endif()
    endif()
    target_link_libraries(uastack
        PUBLIC ws2_32 
        PUBLIC crypt32 
        PUBLIC rpcrt4
    )
else()
    target_include_directories(uastack
        PUBLIC
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/platforms/linux>"
    )
    target_compile_definitions(uastack PUBLIC _GNU_SOURCE)
    target_link_libraries(uastack PRIVATE Threads::Threads)
endif()
target_link_libraries(uastack PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
  # Place here the install rule for win32
elseif(UNIX)
    install(TARGETS uastack
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
    )
    install(FILES
        ${UASTACK_HEADERS}
        DESTINATION include/uastack
    )
endif()
