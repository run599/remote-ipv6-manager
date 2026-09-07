pragma Singleton
import QtQuick

QtObject {
    // ═══ 主色调 ═══
    property color accent:       "#0A84FF"
    property color accentHover:  "#0070E0"

    // ═══ 背景层级 ═══
    property color bgPrimary:    "#F5F5F7"
    property color bgSecondary:  "#FFFFFF"
    property color bgTertiary:   "#E5E5EA"

    // ═══ 文字层级 ═══
    property color textPrimary:   "#1D1D1F"
    property color textSecondary: "#86868B"
    property color textTertiary:  "#AEAEB2"

    // ═══ 语义色 ═══
    property color green:    "#34C759"
    property color orange:   "#FF9F0A"
    property color red:      "#FF453A"

    // ═══ 圆角 ═══
    property int radiusS: 6
    property int radiusM: 10
    property int radiusL: 12

    // ═══ 间距 ═══
    property int spacingXS: 4
    property int spacingS:  8
    property int spacingM:  12
    property int spacingL:  16
    property int spacingXL: 24
}
