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

if(MSVC)
    # 源码含中文：不指定 /utf-8 时 MSVC 按系统代码页(936)解释，
    # 界面上的中文会变成乱码（编得过、只是字错）
    target_compile_options(C2Panel PRIVATE /utf-8 /Zc:__cplusplus /permissive-)
endif()

# ═══ 遗留 QtWidgets 面板（默认关闭）═══
# src/ 下还有一套 QtWidgets 实现（MainWindow/AgentListWidget/... 约 1100 行），
# 与 QML 版功能重复，且各自定义了 main()。它们原本完全游离于构建之外，
# 谁"顺手补进构建"就会撞出 LNK2005（main 重复定义）。
# 这里用显式开关隔开，默认不编译，需要时 -DPANEL_LEGACY_WIDGETS=ON。
option(PANEL_LEGACY_WIDGETS "构建遗留的 QtWidgets 版面板" OFF)
if(PANEL_LEGACY_WIDGETS)
    find_package(Qt6 REQUIRED COMPONENTS Widgets)
    add_executable(C2PanelWidgets
        src/main.cpp
        src/AgentListWidget.cpp
        src/MainWindow.cpp
        src/FileExplorerWidget.cpp
        src/McpPanelWidget.cpp
        src/ShellTerminalWidget.cpp
        src/TaskOrchestratorWidget.cpp
    )
    target_link_libraries(C2PanelWidgets PRIVATE Qt6::Widgets Qt6::Network)
    target_include_directories(C2PanelWidgets PRIVATE src)
    if(MSVC)
        target_compile_options(C2PanelWidgets PRIVATE /utf-8 /Zc:__cplusplus /permissive-)
    endif()
endif()
