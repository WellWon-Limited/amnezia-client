if(NOT DEFINED SIGNTOOL_SUBJECT_NAME)
    set(SIGNTOOL_SUBJECT_NAME "$ENV{SIGNTOOL_SUBJECT_NAME}")
endif()
if(NOT DEFINED NOTARYTOOL_KEYCHAIN_PROFILE)
    set(NOTARYTOOL_KEYCHAIN_PROFILE "$ENV{NOTARYTOOL_KEYCHAIN_PROFILE}")
endif()
if(NOT DEFINED NOTARYTOOL_KEYCHAIN)
    set(NOTARYTOOL_KEYCHAIN "$ENV{NOTARYTOOL_KEYCHAIN}")
endif()

if(WIN32)
    if (SIGNTOOL_SUBJECT_NAME)
        include(${CMAKE_CURRENT_LIST_DIR}/util/signtool.cmake)
        foreach(PACKAGE_FILE IN LISTS CPACK_PACKAGE_FILES)
            signtool_sign_files("${PACKAGE_FILE}" "${SIGNTOOL_SUBJECT_NAME}")
        endforeach()
    endif()
endif()

if(APPLE)
    if(NOT NOTARYTOOL_KEYCHAIN_PROFILE)
        message(FATAL_ERROR "macOS release requires a validated notarytool keychain profile")
    endif()
    if(NOT NOTARYTOOL_KEYCHAIN OR NOT EXISTS "${NOTARYTOOL_KEYCHAIN}")
        message(FATAL_ERROR "macOS release requires the explicit notarization keychain")
    endif()
    if(NOT CPACK_PACKAGE_FILES)
        message(FATAL_ERROR "macOS release produced no package to notarize")
    endif()
    include(${CMAKE_CURRENT_LIST_DIR}/util/notarytool.cmake)
    find_program(SPCTL_COMMAND spctl REQUIRED)
    find_program(PKGUTIL_COMMAND pkgutil REQUIRED)
    foreach(file IN LISTS CPACK_PACKAGE_FILES)
        if(NOT EXISTS "${file}")
            message(FATAL_ERROR "macOS package is missing before notarization: ${file}")
        endif()
        execute_process(
            COMMAND "${PKGUTIL_COMMAND}" --check-signature "${file}"
            RESULT_VARIABLE _tribe_pkg_signature_result
            OUTPUT_VARIABLE _tribe_pkg_signature_output
            ERROR_VARIABLE _tribe_pkg_signature_error
        )
        string(CONCAT _tribe_pkg_signature_evidence
            "${_tribe_pkg_signature_output}" "${_tribe_pkg_signature_error}")
        if(NOT _tribe_pkg_signature_result EQUAL 0
           OR NOT _tribe_pkg_signature_evidence MATCHES
                "Developer ID Installer:.*\\(Q7DVH5MCWF\\)")
            message(FATAL_ERROR
                "macOS package lacks the expected Tribe Developer ID Installer signature")
        endif()
        notarize_and_staple_file(
            "${file}" "${NOTARYTOOL_KEYCHAIN_PROFILE}" "${NOTARYTOOL_KEYCHAIN}")
        execute_process(
            COMMAND "${SPCTL_COMMAND}" --assess --type install --verbose=2 "${file}"
            RESULT_VARIABLE _tribe_spctl_result
            ERROR_VARIABLE _tribe_spctl_error
        )
        if(NOT _tribe_spctl_result EQUAL 0)
            message(FATAL_ERROR "notarized macOS package failed spctl: ${_tribe_spctl_error}")
        endif()
    endforeach()
endif()
