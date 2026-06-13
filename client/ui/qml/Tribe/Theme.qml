pragma Singleton

import QtQuick

// AVPN: Tribe VPN design tokens (UI-DESIGN.md §2). Single source of truth for our overlay UI.
// Night-sky + azure + glass. NO hardcoded hex anywhere else in Tribe/* — read this singleton.
QtObject {
    id: theme

    // ─── Color (night-sky + blue #3e80ed — основная палитра, 2026-06) ───────────
    readonly property QtObject color: QtObject {
        // backgrounds (deepest → page)
        readonly property color bg900: "#050B14"   // самый глубокий (рамка)
        readonly property color bg800: "#0A111D"   // база экрана
        readonly property color bg700: "#0E1728"
        // surfaces (slate)
        readonly property color surface1: "#16202F"  // card / field / list row
        readonly property color surface2: "#1E293B"  // hover / elevated (slate-800)
        readonly property color surface3: "#28344A"  // toggle-off / flag tile
        // glass overlays
        readonly property color glass: Qt.rgba(1, 1, 1, 0.04)
        readonly property color glassStrong: Qt.rgba(1, 1, 1, 0.07)
        // borders
        readonly property color border: Qt.rgba(1, 1, 1, 0.08)
        readonly property color border2: Qt.rgba(1, 1, 1, 0.14)
        readonly property color border3: Qt.rgba(1, 1, 1, 0.22)
        // accent (blue #7ca2d0, из утверждённой палитры night-sky)
        readonly property color accent: "#7CA2D0"
        readonly property color accentBright: "#A5C1E2"   // hover
        readonly property color accentDeep: "#5E84B3"
        readonly property color accentGlow: Qt.rgba(0x7C / 255, 0xA2 / 255, 0xD0 / 255, 0.35)
        // primary-button gradient stops
        readonly property color gradTop: "#5A9BF2"
        readonly property color gradBottom: "#3068D6"
        // text
        readonly property color text1: "#F1F5F9"   // headings
        readonly property color text2: "#94A3B8"   // body (slate-400)
        readonly property color text3: "#64748B"   // captions (slate-500)
        readonly property color textDisabled: "#3A4352"
        // connection states (ONLY for connection status)
        readonly property color connected: "#41C28C"
        readonly property color warning: "#E2A53C"   // connecting / expiring
        readonly property color danger: "#E2625C"    // disconnected / error
        // CTA-gold — НАМЕРЕННОЕ исключение из night-sky (как warning): монетизационный
        // призыв «Получить ключ» при исчерпании триала. Контраст ради конверсии. // AVPN
        readonly property color cta: "#E8B23A"        // CTA gradient top
        readonly property color ctaDeep: "#C8922A"    // CTA gradient bottom
        // badge alpha fills
        readonly property color badgeOn: Qt.rgba(0x41 / 255, 0xC2 / 255, 0x8C / 255, 0.16)
        readonly property color badgeWarn: Qt.rgba(0xE2 / 255, 0xA5 / 255, 0x3C / 255, 0.16)
        readonly property color badgeOff: Qt.rgba(0xE2 / 255, 0x62 / 255, 0x5C / 255, 0.16)
        readonly property color chipSelected: Qt.rgba(0x3E / 255, 0x80 / 255, 0xED / 255, 0.12)
        readonly property color focusRing: Qt.rgba(0x3E / 255, 0x80 / 255, 0xED / 255, 0.18)
        // nav bar (translucent + blur)
        readonly property color nav: Qt.rgba(0x0A / 255, 0x11 / 255, 0x1D / 255, 0.95)
    }

    // ─── Typography ───────────────────────────────────────────────────────────
    // Families resolved from bundled fonts (see fontLoaders). Fallbacks keep preview alive
    // before fonts are bundled.
    readonly property FontLoader _manrope: FontLoader { source: "qrc:/fonts/Manrope-VariableFont_wght.ttf" }
    readonly property FontLoader _inter: FontLoader { source: "qrc:/fonts/Inter-VariableFont.ttf" }
    readonly property FontLoader _mono: FontLoader { source: "qrc:/fonts/JetBrainsMono-VariableFont_wght.ttf" }

    readonly property QtObject font: QtObject {
        readonly property string display: theme._manrope.status === FontLoader.Ready ? theme._manrope.name : "Manrope"
        readonly property string body: theme._inter.status === FontLoader.Ready ? theme._inter.name : "Inter"
        readonly property string mono: theme._mono.status === FontLoader.Ready ? theme._mono.name : "JetBrains Mono"

        // sizes (px)
        readonly property int displayXl: 56
        readonly property int displayL: 36
        readonly property int h1: 28
        readonly property int h2: 22
        readonly property int h3: 18
        readonly property int bodyL: 18
        readonly property int bodyM: 16
        readonly property int bodyS: 14
        readonly property int caption: 12
        readonly property int monoData: 13
        // weights
        readonly property int wRegular: Font.Normal      // 400
        readonly property int wMedium: Font.Medium       // 500
        readonly property int wSemibold: Font.DemiBold   // 600
        readonly property int wBold: Font.Bold           // 700
        readonly property int wExtra: Font.ExtraBold      // 800
        // tracking
        readonly property real trackTight: -0.02   // display (relative; apply as letterSpacing * pixelSize)
        readonly property real trackCaption: 0.14
    }

    // ─── Spacing (base-4 scale) ───────────────────────────────────────────────
    readonly property QtObject space: QtObject {
        readonly property int xs: 4
        readonly property int sm: 8
        readonly property int md: 12
        readonly property int lg: 16
        readonly property int xl: 24
        readonly property int xxl: 32
        readonly property int x3: 48
        readonly property int x4: 64
    }

    // ─── Radii ────────────────────────────────────────────────────────────────
    readonly property QtObject radius: QtObject {
        readonly property int sm: 8     // fields / chips
        readonly property int md: 12    // buttons / rows / ipbox
        readonly property int lg: 16    // cards
        readonly property int xl: 20
        readonly property int pill: 999
    }

    // ─── Depth / glow (one shadow philosophy — blur+glass for the rest) ────────
    readonly property QtObject glow: QtObject {
        readonly property real radius: 24
        readonly property real spread: -8
        readonly property color color: theme.color.accentGlow
        // SignalRing core: 0 0 50px -6px
        readonly property real coreRadius: 50
        readonly property real coreSpread: -6
    }
    readonly property QtObject blur: QtObject {
        readonly property int card: 10
        readonly property int button: 8
        readonly property int nav: 18
    }

    // ─── Motion ───────────────────────────────────────────────────────────────
    readonly property QtObject motion: QtObject {
        readonly property int fast: 160     // buttons, toggles
        readonly property int normal: 220
        readonly property int slow: 360
        // honored by SignalRing breathing etc.; UI sets to 0 when reduceMotion
        property bool reduceMotion: false
    }
}
