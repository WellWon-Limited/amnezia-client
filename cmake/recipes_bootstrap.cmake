find_program(CONAN_COMMAND "conan" REQUIRED
    HINTS
        "${CMAKE_SOURCE_DIR}/.venv/bin"
        "/opt/homebrew/bin"
)

# Every configure exports the same local recipes into one Conan cache.  CMake
# can configure several ABI/architecture build trees concurrently, while Conan
# recipe export is not safe to run concurrently against that shared cache.
# Serialize the whole bootstrap and fail closed on every Conan command: an
# ignored export failure can otherwise silently consume a stale remote binary.
if(DEFINED ENV{CONAN_HOME} AND NOT "$ENV{CONAN_HOME}" STREQUAL "")
    set(_tribe_conan_home "$ENV{CONAN_HOME}")
elseif(DEFINED ENV{HOME} AND NOT "$ENV{HOME}" STREQUAL "")
    set(_tribe_conan_home "$ENV{HOME}/.conan2")
else()
    message(FATAL_ERROR "CONAN_HOME or HOME is required for serialized recipe bootstrap")
endif()
file(MAKE_DIRECTORY "${_tribe_conan_home}")
file(LOCK "${_tribe_conan_home}/tribe-recipes-bootstrap.lock"
    GUARD FILE TIMEOUT 600 RESULT_VARIABLE _tribe_conan_lock_result)
if(NOT _tribe_conan_lock_result STREQUAL "0")
    message(FATAL_ERROR
        "Could not lock the shared Conan recipe cache: ${_tribe_conan_lock_result}")
endif()

function(tribe_conan_checked description)
    execute_process(
        COMMAND "${CONAN_COMMAND}" ${ARGN}
        RESULT_VARIABLE _tribe_conan_result
        OUTPUT_VARIABLE _tribe_conan_stdout
        ERROR_VARIABLE _tribe_conan_stderr
    )
    if(NOT _tribe_conan_result EQUAL 0)
        string(STRIP "${_tribe_conan_stdout}" _tribe_conan_stdout)
        string(STRIP "${_tribe_conan_stderr}" _tribe_conan_stderr)
        message(FATAL_ERROR
            "Conan ${description} failed (${_tribe_conan_result})\n"
            "stdout: ${_tribe_conan_stdout}\n"
            "stderr: ${_tribe_conan_stderr}")
    endif()
endfunction()

file(GLOB_RECURSE LOCAL_RECIPES "${CMAKE_SOURCE_DIR}/recipes/*/conanfile.py")
list(REMOVE_ITEM LOCAL_RECIPES "${CMAKE_SOURCE_DIR}/recipes/go/conanfile.py")
foreach(RECIPE ${LOCAL_RECIPES})
    get_filename_component(RECIPE_DIR ${RECIPE} DIRECTORY)
    tribe_conan_checked("recipe export: ${RECIPE_DIR}" export "${RECIPE_DIR}")
endforeach()

# FIXME(ygurov): export all versions declared on recipies_bootstrap call
tribe_conan_checked("go recipe export 1.26.0"
    export "${CMAKE_SOURCE_DIR}/recipes/go" --version 1.26.0)
tribe_conan_checked("go recipe export 1.23.12"
    export "${CMAKE_SOURCE_DIR}/recipes/go" --version 1.23.12)

tribe_conan_checked("remote configuration"
    remote add amnezia
    "https://artifactory.amnezia.org/artifactory/api/conan/client-prebuilts" --force)
