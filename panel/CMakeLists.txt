cmake_minimum_required(VERSION 3.20)
project(C2Panel LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS
    Quick QuickControls2 QuickWidgets Network
)

# ═══ C++ Backend ═══
add_executable(C2Panel
    src/qml_main.cpp
    src/ApiClient.cpp
    src/AgentModel.cpp
    src/McpBridge.cpp
    qml/qml.qrc
)

target_link_libraries(C2Panel PRIVATE
    Qt6::Quick Qt6::QuickControls2 Qt6::QuickWidgets Qt6::Network
)

target_include_directories(C2Panel PRIVATE src)
