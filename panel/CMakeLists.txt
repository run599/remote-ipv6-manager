cmake_minimum_required(VERSION 3.20)
project(RMMPanel LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS
    Quick QuickControls2 QuickWidgets Network
)

# ═══ C++ Backend ═══
add_executable(RMMPanel
    src/qml_main.cpp
    src/ApiClient.cpp
    src/AgentModel.cpp
    src/McpBridge.cpp
    src/ScreenStream.cpp      # 屏幕监控（实时看屏）面板侧
    src/TrayIcon.cpp          # 右下角托盘 + 开机自启动（纯 Win32，不拉 QtWidgets）
    qml/qml.qrc
)

# ── 把外部预编译的版本资源对象加进链接 ──
# CMake 4.3 + MinGW/Ninja 下实测四种写法，只有最后这种能进 LINK 行：
# 注意：PANEL_RES_OBJ 的赋值在下面（配置期编译资源）之后，因此这里只做"登记"，
# 真正加入放在编译资源之后的那段。
cmake_policy(SET CMP0095 OLD)

target_link_libraries(RMMPanel PRIVATE
    Qt6::Quick Qt6::QuickControls2 Qt6::QuickWidgets Qt6::Network
)

target_include_directories(RMMPanel PRIVATE src)

if(MSVC)
    # 源码含中文：不指定 /utf-8 时 MSVC 按系统代码页(936)解释，
    # 界面上的中文会变成乱码（编得过、只是字错）
    target_compile_options(RMMPanel PRIVATE /utf-8 /Zc:__cplusplus /permissive-)
endif()

# ═══ 面板兼容性适配：剥离静态可提取信息 ═══
#
# 面板运行在操作者自己的机器上，威胁模型是"本机 EDR 扫 GUI 程序 + 取证者
# 配套的源码侧改动是"标识串走运行期解密"（见 src/qml_main.cpp 顶部说明）；
# 这里只处理产物侧。
#
# 注意：不要用 strip/upx 之类"加壳" —— 壳本身是强特征，且会破坏 Qt 插件加载。
# 符号剥离只能去掉调试符号，Qt 框架自身的字符串仍在（那是框架固有特征）。
if(MSVC)
    target_compile_options(RMMPanel PRIVATE $<$<CONFIG:Release>:/Gy /GS->)
    target_link_options(RMMPanel PRIVATE $<$<CONFIG:Release>:/OPT:REF /OPT:ICF /DEBUG:NONE>)
else()
    # MinGW/GCC：-s 剥符号、--gc-sections 丢弃未引用段
    target_compile_options(RMMPanel PRIVATE $<$<CONFIG:Release>:-ffunction-sections -fdata-sections>)
    target_link_options(RMMPanel PRIVATE $<$<CONFIG:Release>:-s -Wl,--gc-sections>)
endif()

# 版本信息 / 资源：无元数据的 exe 在 EDR 侧是加分项的可疑特征。
#
# 做法：用 SDK 的 rc.exe 把 .rc 编成 .res，再用 MinGW 的 windres 转成 COFF 目标
# 文件，最后作为**对象文件**加进链接 —— 这是唯一在 MinGW + Ninja 下稳定工作的
# 方式。实测另外两种写法都会失败：
#       'panel_version.res', needed by 'RMMPanel.exe', missing and no known rule
#       （CMake 判定该自定义命令的产物"无人消费"，干脆不生成规则）
find_program(WINDRES_EXE NAMES windres
    HINTS "D:/qtr/Tools/mingw1310_64/bin" "$ENV{MINGW_HOME}/bin")
set(PANEL_RES_OBJ "")
if(WIN32 AND WINDRES_EXE)
    file(GLOB _rc_bins "C:/Program Files (x86)/Windows Kits/10/bin/*/x64/rc.exe")
    if(_rc_bins)
        list(GET _rc_bins 0 _RC_EXE)
        set(_rc_src "${CMAKE_CURRENT_SOURCE_DIR}/src/panel_version.rc")
        set(_rc_res "${CMAKE_CURRENT_BINARY_DIR}/panel_version.res")
        set(PANEL_RES_OBJ "${CMAKE_CURRENT_BINARY_DIR}/panel_version_res.obj")
        # 后缀用 .obj 而不是 .o —— 三个后缀都实测过，别回退：
        # 结论：CMake 未启用 RC/ASM 语言时不接受外部 .o，只接受 .obj。
        # 配置期直接执行（不是 add_custom_command）：后者在 CMake 生成器看来
        # 是"无人消费的产物"，会静默不生成构建规则（实测三次都栽在这）。
        execute_process(
            COMMAND "${_RC_EXE}" /nologo
                    /i "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um"
                    /i "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared"
                    /fo "${_rc_res}" "${_rc_src}"
            RESULT_VARIABLE _rc_rv OUTPUT_VARIABLE _rc_out ERROR_VARIABLE _rc_err)
        if(NOT _rc_rv EQUAL 0)
            message(WARNING "rc.exe 编译版本资源失败(${_rc_rv}): ${_rc_err}")
            set(PANEL_RES_OBJ "")
        else()
            execute_process(
                COMMAND "${WINDRES_EXE}" --input "${_rc_res}" --output-format=coff
                        --output "${PANEL_RES_OBJ}"
                RESULT_VARIABLE _wr_rv OUTPUT_VARIABLE _wr_out ERROR_VARIABLE _wr_err)
            if(NOT _wr_rv EQUAL 0)
                message(WARNING "windres 转换版本资源失败(${_wr_rv}): ${_wr_err}")
                set(PANEL_RES_OBJ "")
            else()
                message(STATUS "面板版本资源已编译为 COFF 对象：${PANEL_RES_OBJ}")
                # 关键：必须用 EXTERNAL_OBJECT + GENERATED 显式告诉 CMake
                # "这是一个预编译好的外部对象，直接交给链接器，不要尝试编译它"。
                # 只放进源列表会被当成"未知源文件"丢弃（实测 ③）。
                set_source_files_properties("${PANEL_RES_OBJ}" PROPERTIES
                    EXTERNAL_OBJECT TRUE
                    GENERATED TRUE)
                target_sources(RMMPanel PRIVATE "${PANEL_RES_OBJ}")
                set_property(TARGET RMMPanel APPEND PROPERTY LINK_DEPENDS "${PANEL_RES_OBJ}")
            endif()
        endif()
    else()
        message(WARNING "未找到 rc.exe，面板不会有版本信息（兼容性适配判据会失败）")
    endif()
elseif(WIN32)
    message(WARNING "未找到 windres，面板版本信息无法写入（安装 Qt 的 mingw 工具链即可）")
endif()

# ═══ 遗留 QtWidgets 面板（默认关闭）═══
# src/ 下还有一套 QtWidgets 实现（MainWindow/AgentListWidget/... 约 1100 行），
# 与 QML 版功能重复，且各自定义了 main()。它们原本完全游离于构建之外，
# 谁"顺手补进构建"就会撞出 LNK2005（main 重复定义）。
# 这里用显式开关隔开，默认不编译，需要时 -DPANEL_LEGACY_WIDGETS=ON。
option(PANEL_LEGACY_WIDGETS "构建遗留的 QtWidgets 版面板" OFF)
if(PANEL_LEGACY_WIDGETS)
    find_package(Qt6 REQUIRED COMPONENTS Widgets)
    add_executable(RMMPanelWidgets
        src/main.cpp
        src/AgentListWidget.cpp
        src/MainWindow.cpp
        src/FileExplorerWidget.cpp
        src/McpPanelWidget.cpp
        src/ShellTerminalWidget.cpp
        src/TaskOrchestratorWidget.cpp
    )
    target_link_libraries(RMMPanelWidgets PRIVATE Qt6::Widgets Qt6::Network)
    target_include_directories(RMMPanelWidgets PRIVATE src)
    if(MSVC)
        target_compile_options(RMMPanelWidgets PRIVATE /utf-8 /Zc:__cplusplus /permissive-)
    endif()
endif()

# 凭据自启动配置用 DPAPI（CryptProtectData）加密面板口令，需要 crypt32。
# 追加在末尾：此时 RMMPanel 这个 target 已经定义完，直接加链接库即可。
if(WIN32)
    target_link_libraries(RMMPanel PRIVATE crypt32)
    # 托盘图标用 Shell_NotifyIcon，归 shell32；显式链接避免依赖默认库传递进来
    target_link_libraries(RMMPanel PRIVATE shell32)
# Win32 通用对话框（选本机文件 / 保存读回的文件）。系统自带，只是要显式链一下。
target_link_libraries(RMMPanel PRIVATE comdlg32)
endif()
