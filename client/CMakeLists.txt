cmake_minimum_required(VERSION 3.20)
project(RemoteClient LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(/utf-8 /W4 /permissive-)

# 静态链接 MSVC 运行时
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(RemoteClient WIN32
    src/main.cpp
    src/Json.cpp
    src/StubCore.cpp
    src/PluginLoader.cpp
    src/NetworkFix.cpp
    src/AntiHook.cpp
)

target_include_directories(RemoteClient PRIVATE src include)
target_link_libraries(RemoteClient PRIVATE
    ws2_32 iphlpapi wininet urlmon advapi32 shlwapi ntdll crypt32
)

# 插件目录
set(PLUGIN_DIR ${CMAKE_BINARY_DIR}/plugins)
file(MAKE_DIRECTORY ${PLUGIN_DIR})

# 编译后自动复制插件目录
add_custom_command(TARGET RemoteClient POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:RemoteClient>/plugins"
)
