project(websocket_app CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_PREFIX_PATH}/lib/cmake")

file(GLOB WEBSOCKET_APP_SRC
        "*.cpp"
        )

set(WEBSOCKET_APP_PROJECT_NAME websocket_app)
add_executable(${WEBSOCKET_APP_PROJECT_NAME} ${WEBSOCKET_APP_SRC})

set_target_properties(${WEBSOCKET_APP_PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
set_target_properties(${WEBSOCKET_APP_PROJECT_NAME} PROPERTIES CXX_STANDARD ${CMAKE_CXX_STANDARD})

#set warnings and runtime library
if (MSVC)
    if(STATIC_CRT)
        target_compile_options(${PROJECT_NAME} PRIVATE "/MT$<$<CONFIG:Debug>:d>")
    else()
        target_compile_options(${PROJECT_NAME} PRIVATE "/MD$<$<CONFIG:Debug>:d>")
    endif()
    target_compile_options(${WEBSOCKET_APP_PROJECT_NAME} PRIVATE /W4 /WX)
else ()
    target_compile_options(${WEBSOCKET_APP_PROJECT_NAME} PRIVATE -Wall -Wno-long-long -pedantic -Werror)
endif ()


if (CMAKE_BUILD_TYPE STREQUAL "" OR CMAKE_BUILD_TYPE MATCHES Debug)
    target_compile_definitions(${WEBSOCKET_APP_PROJECT_NAME} PRIVATE "-DDEBUG_BUILD")
endif ()

target_include_directories(${WEBSOCKET_APP_PROJECT_NAME} PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)

target_link_libraries(${WEBSOCKET_APP_PROJECT_NAME} aws-crt-cpp)

if (BUILD_SHARED_LIBS AND NOT WIN32)
    message(INFO " mqtt5 app will be built with shared libs, but you may need to set LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib to run the application")
endif()

install(TARGETS ${WEBSOCKET_APP_PROJECT_NAME}
        EXPORT ${WEBSOCKET_APP_PROJECT_NAME}-targets
        COMPONENT Runtime
        RUNTIME
        DESTINATION bin
        COMPONENT Runtime)
