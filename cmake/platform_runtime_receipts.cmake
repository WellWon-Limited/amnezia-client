# Generated platform/runtime release receipts are the only way to advertise a native session
# guard.  A normal developer/store build has no receipt and therefore compiles every flag false.
set(TRIBE_ANDROID_AWG_GUARD_RECEIPT 0)
set(TRIBE_ANDROID_XRAY_GUARD_RECEIPT 0)
set(TRIBE_IOS_AWG_GUARD_RECEIPT 0)
set(TRIBE_IOS_XRAY_GUARD_RECEIPT 0)
set(TRIBE_MACOS_DAEMON_AWG_GUARD_RECEIPT 0)
set(TRIBE_MACOS_DAEMON_XRAY_GUARD_RECEIPT 0)
set(TRIBE_MACOS_NE_AWG_GUARD_RECEIPT 0)
set(TRIBE_MACOS_NE_XRAY_GUARD_RECEIPT 0)

if(DEFINED TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE
   AND NOT "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE}" STREQUAL "")
    if(NOT IS_ABSOLUTE "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE}"
       OR NOT EXISTS "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE}")
        message(FATAL_ERROR "platform runtime receipt must be an existing absolute JSON path")
    endif()
    string(LENGTH "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256}" _tribe_receipt_sha256_length)
    if(NOT DEFINED TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256
       OR NOT _tribe_receipt_sha256_length EQUAL 64
       OR NOT "${TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256}" MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "platform runtime receipt requires its CI-pinned lowercase SHA-256")
    endif()
    file(SHA256 "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE}" _tribe_receipt_actual_sha256)
    if(NOT _tribe_receipt_actual_sha256 STREQUAL TRIBE_PLATFORM_RUNTIME_RECEIPT_SHA256)
        message(FATAL_ERROR "platform runtime receipt SHA-256 mismatch")
    endif()
    file(READ "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE}" _tribe_receipt_json LIMIT 131072)
    string(JSON _tribe_receipt_schema ERROR_VARIABLE _tribe_receipt_error
           GET "${_tribe_receipt_json}" schema)
    if(_tribe_receipt_error OR NOT _tribe_receipt_schema EQUAL 1)
        message(FATAL_ERROR "platform runtime receipt schema invalid")
    endif()
    execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
                    OUTPUT_VARIABLE _tribe_source_commit OUTPUT_STRIP_TRAILING_WHITESPACE
                    RESULT_VARIABLE _tribe_git_result)
    string(JSON _tribe_receipt_commit ERROR_VARIABLE _tribe_receipt_error
           GET "${_tribe_receipt_json}" source_commit)
    if(_tribe_git_result OR _tribe_receipt_error
       OR NOT _tribe_receipt_commit STREQUAL _tribe_source_commit)
        message(FATAL_ERROR "platform runtime receipt is not bound to this source commit")
    endif()

    function(_tribe_import_guard_receipt json_path output_name)
        string(JSON _entry ERROR_VARIABLE _entry_error GET "${_tribe_receipt_json}" ${json_path})
        if(_entry_error)
            set(${output_name} 0 PARENT_SCOPE)
            return()
        endif()
        foreach(_required artifact_matrix exact_lifecycle route_leak_matrix device_receipt_sha256)
            string(JSON _value ERROR_VARIABLE _value_error GET "${_entry}" ${_required})
            if(_value_error)
                message(FATAL_ERROR "platform runtime receipt ${json_path}.${_required} missing")
            endif()
            if(_required STREQUAL "device_receipt_sha256")
                string(LENGTH "${_value}" _value_length)
                if(NOT _value_length EQUAL 64
                   OR NOT _value MATCHES "^[0-9a-f]+$"
                   OR _value STREQUAL
                      "0000000000000000000000000000000000000000000000000000000000000000")
                    message(FATAL_ERROR "platform runtime receipt device evidence digest invalid")
                endif()
            elseif(NOT _value STREQUAL "passed")
                message(FATAL_ERROR "platform runtime receipt claims support without passed ${_required}")
            endif()
        endforeach()
        set(${output_name} 1 PARENT_SCOPE)
    endfunction()

    _tribe_import_guard_receipt("platforms;android;awg" TRIBE_ANDROID_AWG_GUARD_RECEIPT)
    _tribe_import_guard_receipt("platforms;android;xray" TRIBE_ANDROID_XRAY_GUARD_RECEIPT)
    _tribe_import_guard_receipt("platforms;ios;awg" TRIBE_IOS_AWG_GUARD_RECEIPT)
    _tribe_import_guard_receipt("platforms;ios;xray" TRIBE_IOS_XRAY_GUARD_RECEIPT)
    # Normal macOS has an authenticated GUI↔root-helper PREPARE/CLAIM/STOP/RELEASE bridge and a
    # durable helper-owned PF lease. It may advertise support only after the same artifact,
    # lifecycle, PF route-leak and device evidence checks as mobile.
    _tribe_import_guard_receipt("platforms;macos_daemon;awg"
                                TRIBE_MACOS_DAEMON_AWG_GUARD_RECEIPT)
    _tribe_import_guard_receipt("platforms;macos_daemon;xray"
                                TRIBE_MACOS_DAEMON_XRAY_GUARD_RECEIPT)
    # The optional macOS-NE target intentionally has no app-side PREPARE/ACTIVATE/STOP/RELEASE
    # bridge or shared vault entitlement. A device receipt cannot turn an absent production
    # implementation into a capability; these two flags remain compile-time false.
endif()

if(DEFINED TRIBE_REQUIRED_RUNTIME_PLATFORM
   AND NOT "${TRIBE_REQUIRED_RUNTIME_PLATFORM}" STREQUAL "")
    if(NOT TRIBE_REQUIRED_RUNTIME_PLATFORM MATCHES
       "^(android|ios|macos_daemon|macos_ne)$")
        message(FATAL_ERROR "unknown required platform runtime receipt")
    endif()
    if(NOT DEFINED TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE
       OR "${TRIBE_PLATFORM_RUNTIME_RECEIPT_FILE}" STREQUAL "")
        message(FATAL_ERROR "release build requires a platform runtime receipt")
    endif()
    execute_process(
        COMMAND git status --porcelain=v1 --untracked-files=all
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE _tribe_release_tree_status
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _tribe_release_tree_result)
    if(_tribe_release_tree_result OR NOT _tribe_release_tree_status STREQUAL "")
        message(FATAL_ERROR
            "release runtime receipt may only be consumed from an exact clean source tree")
    endif()
    string(TOUPPER "${TRIBE_REQUIRED_RUNTIME_PLATFORM}" _tribe_required_prefix)
    foreach(_tribe_required_transport AWG XRAY)
        set(_tribe_required_flag
            "TRIBE_${_tribe_required_prefix}_${_tribe_required_transport}_GUARD_RECEIPT")
        if(NOT DEFINED ${_tribe_required_flag} OR NOT ${${_tribe_required_flag}} EQUAL 1)
            message(FATAL_ERROR
                "release receipt lacks passed ${TRIBE_REQUIRED_RUNTIME_PLATFORM}/${_tribe_required_transport}")
        endif()
    endforeach()
endif()
