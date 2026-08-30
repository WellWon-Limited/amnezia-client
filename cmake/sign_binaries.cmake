if(NOT DEFINED SIGNTOOL_SUBJECT_NAME)
    set(SIGNTOOL_SUBJECT_NAME "$ENV{SIGNTOOL_SUBJECT_NAME}")
endif()
if(NOT DEFINED CODESIGN_SIGNATURE)
    set(CODESIGN_SIGNATURE "$ENV{CODESIGN_SIGNATURE}")
endif()
if(NOT DEFINED CODESIGN_KEYCHAIN)
    set(CODESIGN_KEYCHAIN "$ENV{CODESIGN_KEYCHAIN}")
endif()

if(WIN32)
    file(GLOB_RECURSE BINARIES
        "${CPACK_TEMPORARY_DIRECTORY}/*.dll"
        "${CPACK_TEMPORARY_DIRECTORY}/*.exe"
    )

    if(BINARIES AND SIGNTOOL_SUBJECT_NAME)
        include(${CMAKE_CURRENT_LIST_DIR}/util/signtool.cmake)
        signtool_sign_files("${BINARIES}" "${SIGNTOOL_SUBJECT_NAME}")
    endif()
endif()

if(APPLE)
    if(NOT CODESIGN_SIGNATURE)
        message(FATAL_ERROR "macOS productbuild requires a Developer ID Application identity")
    endif()
    if(NOT CODESIGN_KEYCHAIN OR NOT EXISTS "${CODESIGN_KEYCHAIN}")
        message(FATAL_ERROR "macOS productbuild requires the explicit release signing keychain")
    endif()

    file(GLOB_RECURSE all_subdirs LIST_DIRECTORIES true "${CPACK_TEMPORARY_DIRECTORY}/*")

    set(bundle ${all_subdirs})
    list(FILTER bundle INCLUDE REGEX [[/TribeVPN\.app$]])
    list(LENGTH bundle bundle_count)
    if(NOT bundle_count EQUAL 1)
        message(FATAL_ERROR "Expected exactly one staged TribeVPN.app, found ${bundle_count}")
    endif()
    list(GET bundle 0 bundle)

    # Closed executable allowlist. A recursive Contents/MacOS glob also catches
    # geoip/geosite, PF rules and shell scripts and asks codesign to treat data
    # as nested code; that is both non-portable and outside the signed-code ABI.
    set(runtime_execs
        "${bundle}/Contents/MacOS/TribeVPN"
        "${bundle}/Contents/MacOS/Tribe-service"
        "${bundle}/Contents/MacOS/amneziawg-go"
        "${bundle}/Contents/MacOS/openvpn"
        "${bundle}/Contents/MacOS/tun2socks"
    )
    # The outer app signature owns the main executable and its resource seal.  Signing that
    # executable as a standalone nested item first makes codesign traverse the not-yet-sealed
    # Contents/MacOS/pf resources and fail.  Only real helper executables are nested code; the
    # main executable is signed exactly once with the outer bundle below.
    set(runtime_nested_execs
        "${bundle}/Contents/MacOS/Tribe-service"
        "${bundle}/Contents/MacOS/amneziawg-go"
        "${bundle}/Contents/MacOS/openvpn"
        "${bundle}/Contents/MacOS/tun2socks"
    )
    foreach(runtime_exec IN LISTS runtime_execs)
        if(NOT EXISTS "${runtime_exec}")
            message(FATAL_ERROR "Required staged executable is missing: ${runtime_exec}")
        endif()
    endforeach()

    get_filename_component(_tribe_source_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
    if(NOT CPACK_TRIBE_QT_LIB_DIR
       OR NOT EXISTS "${CPACK_TRIBE_QT_LIB_DIR}/QtCore.framework")
        message(FATAL_ERROR "CPack lost the configured Qt Framework root")
    endif()
    if(NOT CPACK_TRIBE_INSTALL_EPOCH MATCHES "^[1-9][0-9]*$")
        message(FATAL_ERROR "CPack lost the monotonic Tribe install epoch")
    endif()
    execute_process(
        COMMAND /bin/bash "${_tribe_source_root}/deploy/tribe/bundle-daemon-qt.sh"
                "${bundle}/Contents/MacOS"
                "${bundle}/Contents/Frameworks"
                "${CPACK_TRIBE_QT_LIB_DIR}"
                app
        RESULT_VARIABLE _tribe_app_daemon_closure_result
    )
    if(NOT _tribe_app_daemon_closure_result EQUAL 0)
        message(FATAL_ERROR "Failed to stage the app-visible macOS daemon Qt closure")
    endif()
    execute_process(
        COMMAND /bin/bash "${_tribe_source_root}/deploy/tribe/sanitize-macos-app.sh"
                "${bundle}"
        RESULT_VARIABLE _tribe_sanitize_result
    )
    if(NOT _tribe_sanitize_result EQUAL 0)
        message(FATAL_ERROR "Failed to sanitize the final staged macOS app")
    endif()

    # The sanitizer removes unsupported SQL plugins and escaping LC_RPATHs.
    # Compute the signing set only after those mutations.
    file(GLOB_RECURSE sanitized_subdirs LIST_DIRECTORIES true "${bundle}/*")
    set(frameworks ${sanitized_subdirs})
    list(FILTER frameworks INCLUDE REGEX [[.*\.framework$]])
    file(GLOB_RECURSE dylibs "${bundle}/*.dylib")
    set(nested_files "${frameworks}" "${dylibs}" "${runtime_nested_execs}")
    if(NOT nested_files)
        message(FATAL_ERROR "No nested macOS runtime code was staged for signing")
    endif()

    set(_tribe_dsym_output "$ENV{TRIBE_MACOS_DSYM_OUTPUT_DIR}")
    if(NOT IS_ABSOLUTE "${_tribe_dsym_output}")
        message(FATAL_ERROR
            "macOS productbuild requires an absolute detached dSYM output directory")
    endif()
    if(NOT CPACK_TRIBE_SOURCE_DIR OR NOT EXISTS "${CPACK_TRIBE_SOURCE_DIR}"
       OR NOT CPACK_TRIBE_BUILD_DIR OR NOT EXISTS "${CPACK_TRIBE_BUILD_DIR}")
        message(FATAL_ERROR "CPack lost source/build roots for the path privacy gate")
    endif()
    execute_process(
        COMMAND /bin/bash "${_tribe_source_root}/deploy/tribe/prepare-macos-symbols.sh"
                "${bundle}" "${_tribe_dsym_output}"
                "${CPACK_TRIBE_SOURCE_DIR}" "${CPACK_TRIBE_BUILD_DIR}"
        RESULT_VARIABLE _tribe_symbols_result
    )
    if(NOT _tribe_symbols_result EQUAL 0)
        message(FATAL_ERROR
            "Failed to create detached symbols or reject private build paths")
    endif()

    find_program(_tribe_python3 NAMES python3 REQUIRED)
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env PYTHONDONTWRITEBYTECODE=1
                "${_tribe_python3}"
                "${_tribe_source_root}/metadata/check_macos_engine_artifact.py"
                --app "${bundle}"
                --lock "${_tribe_source_root}/metadata/engine-lock.json"
        RESULT_VARIABLE _tribe_engine_identity_result
    )
    if(NOT _tribe_engine_identity_result EQUAL 0)
        message(FATAL_ERROR
            "Staged macOS AWG/Xray identity or side-effect gate failed")
    endif()

    include(${CMAKE_CURRENT_LIST_DIR}/util/codesign.cmake)
    codesign_sign_files("${nested_files}" "${CODESIGN_SIGNATURE}" "${CODESIGN_KEYCHAIN}")
    set(_tribe_team_requirement
        [[anchor apple generic and certificate leaf[subject.OU] = "Q7DVH5MCWF" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists]])
    foreach(_tribe_nested_code IN LISTS nested_files)
        execute_process(
            COMMAND "${CODESIGN_COMMAND}" --verify --strict --verbose=2
                    -R=${_tribe_team_requirement} "${_tribe_nested_code}"
            RESULT_VARIABLE _tribe_nested_verify_result
            ERROR_VARIABLE _tribe_nested_verify_error
        )
        if(NOT _tribe_nested_verify_result EQUAL 0)
            message(FATAL_ERROR
                "Nested code does not satisfy the Tribe Developer Team requirement: "
                "${_tribe_nested_code}: ${_tribe_nested_verify_error}")
        endif()
    endforeach()

    # The privileged tarball must contain the already-signed helper/runtime
    # bytes. It is then covered as a resource by the containing app signature.
    execute_process(
        COMMAND /bin/bash
            "${_tribe_source_root}/deploy/tribe/prepare-macos-service-payload.sh"
            "${bundle}"
            "${CODESIGN_SIGNATURE}"
            "${CODESIGN_KEYCHAIN}"
            "${CPACK_TRIBE_INSTALL_EPOCH}"
        RESULT_VARIABLE _tribe_payload_result
    )
    if(NOT _tribe_payload_result EQUAL 0)
        message(FATAL_ERROR "Failed to seal the signed macOS daemon payload")
    endif()

    # Qt's QML engine needs the reviewed hardened-runtime exceptions. Signing
    # the outer bundle through the generic helper silently dropped them.
    set(_tribe_entitlements "${_tribe_source_root}/deploy/tribe/tribe-app.entitlements")
    if(NOT EXISTS "${_tribe_entitlements}")
        message(FATAL_ERROR "Reviewed Tribe app entitlements are missing")
    endif()
    execute_process(
        COMMAND "${CODESIGN_COMMAND}" --force --verbose --timestamp --options runtime
                --entitlements "${_tribe_entitlements}"
                --sign "${CODESIGN_SIGNATURE}" --keychain "${CODESIGN_KEYCHAIN}"
                "${bundle}"
        RESULT_VARIABLE _tribe_app_sign_result
        ERROR_VARIABLE _tribe_app_sign_error
    )
    if(NOT _tribe_app_sign_result EQUAL 0)
        message(FATAL_ERROR "TribeVPN.app codesign failed: ${_tribe_app_sign_error}")
    endif()
    execute_process(
        COMMAND "${CODESIGN_COMMAND}" --verify --deep --strict --verbose=2
                -R=${_tribe_team_requirement} "${bundle}"
        RESULT_VARIABLE _tribe_app_verify_result
        ERROR_VARIABLE _tribe_app_verify_error
    )
    if(NOT _tribe_app_verify_result EQUAL 0)
        message(FATAL_ERROR "TribeVPN.app signature verification failed: ${_tribe_app_verify_error}")
    endif()
    execute_process(
        COMMAND "${CODESIGN_COMMAND}" -d --entitlements :- "${bundle}"
        RESULT_VARIABLE _tribe_entitlements_result
        OUTPUT_VARIABLE _tribe_signed_entitlements_stdout
        ERROR_VARIABLE _tribe_signed_entitlements_stderr
    )
    string(CONCAT _tribe_signed_entitlements
        "${_tribe_signed_entitlements_stdout}" "${_tribe_signed_entitlements_stderr}")
    foreach(_required_entitlement
            com.apple.security.cs.allow-jit
            com.apple.security.cs.allow-unsigned-executable-memory
            com.apple.security.cs.disable-library-validation)
        if(NOT _tribe_entitlements_result EQUAL 0
           OR NOT _tribe_signed_entitlements MATCHES "${_required_entitlement}")
            message(FATAL_ERROR "Signed TribeVPN.app lost entitlement ${_required_entitlement}")
        endif()
    endforeach()
endif()
