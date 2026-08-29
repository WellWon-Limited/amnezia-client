find_program(XCRUN_COMMAND xcrun REQUIRED)

function(notarize_file file profile keychain)
    set(args
        --keychain-profile ${profile}
        --keychain ${keychain}
        --wait
        --timeout 30m
    )

    set(cmd ${XCRUN_COMMAND} notarytool submit ${args} ${file})
    message(STATUS "Submitting ${file} to Apple notarization with keychain profile ${profile}")

    execute_process(COMMAND ${cmd}
        RESULT_VARIABLE result
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        string(REPLACE "\n" "\n  " error "  ${error}")
        message(FATAL_ERROR "notarytool failed:\n${error}")
    endif()
endfunction()

function(staple_file file)
    set(cmd ${XCRUN_COMMAND} stapler staple ${file})

    list(JOIN cmd " " cmd_str)
    message(STATUS ${cmd_str})

    execute_process(COMMAND ${cmd}
        RESULT_VARIABLE result
        ERROR_VARIABLE error
    )
    if(NOT result EQUAL 0)
        string(REPLACE "\n" "\n  " error "  ${error}")
        message(FATAL_ERROR "stapler failed:\n${error}")
    endif()

    execute_process(COMMAND ${XCRUN_COMMAND} stapler validate ${file}
        RESULT_VARIABLE validate_result
        ERROR_VARIABLE validate_error
    )
    if(NOT validate_result EQUAL 0)
        string(REPLACE "\n" "\n  " validate_error "  ${validate_error}")
        message(FATAL_ERROR "stapler validation failed:\n${validate_error}")
    endif()
endfunction()


function(notarize_and_staple_file file profile keychain)
    notarize_file("${file}" "${profile}" "${keychain}")
    staple_file("${file}")
endfunction()
