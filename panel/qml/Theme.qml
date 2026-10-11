pragma Singleton
import QtQuick

// ═══════════════════════════════════════════════════════════════════════════
// Theme.qml —— 面板设计系统
//
// 设计说明：
//   · 双主题（默认暗色）。控制台这类界面暗色更耐看、也更像"工具"，
//     但操作者习惯亮色，所以做成可切换而不是二选一。切换只改 Theme.dark，
//     其余令牌全是它的绑定，全界面自动跟随。
//   · 暗色底色用 #0E1116 / #171B22 这类"近黑但有蓝味"的层次，不用纯 #000 ——
//     纯黑会让卡片边框和阴影完全消失，层级感全丢。
//   · 不用 MultiEffect（QtQuick.Effects）做阴影：那会多一个 QML 模块依赖，
//     而 windeployqt 是按 --qmldir 扫到的 import 决定拷哪些模块的，
//     漏拷就是运行期整页加载失败。阴影改用叠层半透明描边实现，零依赖。
//   · 旧的令牌名（accent / bgSecondary / textPrimary / radiusS …）全部保留：
//     四个页签都在用，删一个就是一片 QML 报错。
// ═══════════════════════════════════════════════════════════════════════════

QtObject {
    id: theme

    // ── 主题开关 ──
    // 可写：顶栏按钮直接 Theme.dark = !Theme.dark，所有令牌跟着重算。
    property bool dark: true

    // ── 主色 ──
    // 暗色下要把蓝提亮一档：同一个 #0A84FF 放在深底上会显得发闷、对比度不足。
    readonly property color accent:      dark ? "#4C9AFF" : "#0A84FF"
    readonly property color accentHover: dark ? "#74B2FF" : "#0070E0"
    readonly property color accentPress: dark ? "#3B87E8" : "#0064CC"
    // 主色的"淡底"版本：选中态背景、chip 底色都用它，避免大面积高饱和色
    readonly property color accentSoft:  dark ? Qt.rgba(76/255, 154/255, 255/255, 0.16)
                                              : Qt.rgba(10/255, 132/255, 255/255, 0.10)
    readonly property color accentLine:  dark ? Qt.rgba(76/255, 154/255, 255/255, 0.32)
                                              : Qt.rgba(10/255, 132/255, 255/255, 0.24)
    // 品牌渐变（Logo / 登录页左栏）
    readonly property color brand2:      dark ? "#8B5CF6" : "#5856D6"

    // ── 背景层级 ──
    readonly property color bgPrimary:   dark ? "#12161D" : "#F5F5F7"
    readonly property color bgSecondary: dark ? "#1B202A" : "#FFFFFF"
    readonly property color bgTertiary:  dark ? "#252C38" : "#E5E5EA"
    readonly property color bgElevated:  dark ? "#262E3A" : "#FFFFFF"   // 悬浮/输入框
    readonly property color bgSunken:    dark ? "#10141A" : "#EFEFF2"   // 终端/列表凹陷区

    // ── 描边与分隔 ──
    readonly property color cardBorder:  dark ? Qt.rgba(1, 1, 1, 0.07) : Qt.rgba(0, 0, 0, 0.06)
    readonly property color cardBorderHi: dark ? Qt.rgba(1, 1, 1, 0.14) : Qt.rgba(0, 0, 0, 0.12)
    readonly property color divider:     dark ? Qt.rgba(1, 1, 1, 0.06) : Qt.rgba(0, 0, 0, 0.05)

    // ── 交互态 ──
    readonly property color hoverBg:     dark ? Qt.rgba(1, 1, 1, 0.05) : Qt.rgba(0, 0, 0, 0.035)
    readonly property color pressBg:     dark ? Qt.rgba(1, 1, 1, 0.09) : Qt.rgba(0, 0, 0, 0.06)
    readonly property color selectedBg:  accentSoft
    readonly property color focusRing:   accentLine

    // ── 文字层级 ──
    readonly property color textPrimary:   dark ? "#E8ECF2" : "#1D1D1F"
    readonly property color textSecondary: dark ? "#9AA4B2" : "#86868B"
    readonly property color textTertiary:  dark ? "#69727F" : "#AEAEB2"
    readonly property color textOnAccent:  "#FFFFFF"

    // ── 语义色 ──
    readonly property color green:  dark ? "#3DDC84" : "#34C759"
    readonly property color orange: dark ? "#FFB340" : "#FF9F0A"
    readonly property color red:    dark ? "#FF6B6B" : "#FF453A"
    readonly property color blue:   accent

    // ── 语义色淡底（状态胶囊用）──
    readonly property color greenSoft:  dark ? Qt.rgba(61/255, 220/255, 132/255, 0.14) : Qt.rgba(52/255, 199/255, 89/255, 0.12)
    readonly property color orangeSoft: dark ? Qt.rgba(255/255, 179/255, 64/255, 0.14) : Qt.rgba(255/255, 159/255, 10/255, 0.12)

    // ── 阴影（叠层描边用）──
    readonly property real  shadowOpacity: dark ? 0.55 : 0.16
    readonly property int   shadowLayers: 3

    // ── 圆角 ──
    readonly property int radiusS:  6
    readonly property int radiusM:  10
    readonly property int radiusL:  14
    readonly property int radiusXL: 18
    readonly property int radiusPill: 999

    // ── 间距 ──
    readonly property int spacingXS: 4
    readonly property int spacingS:  8
    readonly property int spacingM:  12
    readonly property int spacingL:  16
    readonly property int spacingXL: 24
    readonly property int spacingXXL: 32

    // ── 字号 ──
    readonly property int fsDisplay: 26
    readonly property int fsTitle:   17
    readonly property int fsBody:    13
    readonly property int fsSmall:   11
    readonly property int fsMono:    12
    readonly property int fsTiny:    10

    // ── 字体 ──
    // 只用 Windows 必装的族名，避免"设计稿上好看、换机就变宋体"。
    readonly property string fontUI:   "Segoe UI"
    readonly property string fontMono: "Consolas"

    // ── 动效 ──
    readonly property int durFast: 110
    readonly property int durMed:  190
    readonly property int durSlow: 320
    readonly property int easeOut: Easing.OutCubic

    // ── 常用尺寸 ──
    readonly property int topBarHeight:  56
    readonly property int footerHeight:  30
    readonly property int sidebarWidth:  268
    readonly property int controlHeight: 34
    readonly property int rowHeight:     58
}
