import QtQuick
import QtQuick.Shapes

import ".."   // Theme

// AVPN (рассылки P-ANN v2): векторная stroke-иконка по строковому ключу из
// server-driven контента (блок feature). Таблица path'ов — ЗЕРКАЛО админки
// (tribe-backend admin-ui/js/views/announcements.js, const ICONS): новый ключ
// добавлять В ОБА места, иначе превью соврёт. Неизвестный ключ → пусто
// (forward-compat: рассылка новее клиента не ломает рендер).
// Стиль Tabler/Lucide: сетка 24, stroke 2, round cap/join.
Item {
    id: root

    property string icon: ""
    property color tint: Theme.color.accent
    property real weight: 2      // stroke width in the 24 grid (scales with the icon, like SVG)

    implicitWidth: 24
    implicitHeight: 24

    readonly property var paths: ({
        "tap": "M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z M13 13l6 6",
        "zap": "M13 2 3 14h9l-1 8 10-12h-9l1-8z",
        "refresh": "M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8 M21 3v5h-5",
        "globe": "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M2 12h20 M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z",
        "shield": "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
        "shield-check": "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9 11.5l2 2 4-4",
        "eye-off": "M9.88 9.88a3 3 0 1 0 4.24 4.24 M10.73 5.08A10.4 10.4 0 0 1 12 5c7 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.68 M6.61 6.61A13.5 13.5 0 0 0 2 12s3 7 10 7a9.7 9.7 0 0 0 5.39-1.61 M2 2l20 20",
        "user-x": "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M9 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z M17 8l5 5 M22 8l-5 5",
        "lock": "M5 11h14a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-8a1 1 0 0 1 1-1z M8 11V7a4 4 0 0 1 8 0v4",
        "bell": "M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9 M10.3 21a1.94 1.94 0 0 0 3.4 0",
        "gift": "M20 12v10H4V12 M2 7h20v5H2z M12 22V7 M12 7H7.5a2.5 2.5 0 0 1 0-5C11 2 12 7 12 7z M12 7h4.5a2.5 2.5 0 0 0 0-5C13 2 12 7 12 7z",
        "star": "M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z",
        "check": "M20 6 9 17l-5-5",
        "x": "M18 6 6 18 M6 6l12 12",
        "clock": "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M12 6v6l4 2",
        "wifi": "M5 13a10 10 0 0 1 14 0 M8.5 16.5a5 5 0 0 1 7 0 M2 8.8a15 15 0 0 1 20 0 M12 20h.01",
        "rocket": "M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0 M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5",
        // Scanner keys (artboard vpn-scanner-kit.js P, Lucide), added 16.11 - mirror them into the admin ICONS
        // table (backend repo, admin-ui/js/views/announcements.js) per the rule above.
        "radar": "M19.07 4.93A10 10 0 0 0 6.99 3.34 M4 6h.01 M2.29 9.62A10 10 0 1 0 21.31 8.35 M16.24 7.76A6 6 0 1 0 8.23 16.67 M12 18h.01 M17.99 11.66A6 6 0 0 1 15.77 16.67 M10 12a2 2 0 1 0 4 0a2 2 0 1 0 -4 0 M13.41 10.59l5.66-5.66",
        "users": "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M5 7a4 4 0 1 0 8 0a4 4 0 1 0 -8 0 M22 21v-2a4 4 0 0 0-3-3.87 M16 3.13a4 4 0 0 1 0 7.75",
        "wifi-off": "M12 20h.01 M8.5 16.429a5 5 0 0 1 7 0 M5 12.859a10 10 0 0 1 5.17-2.69 M19 12.859a10 10 0 0 0-2.007-1.523 M2 8.82a15 15 0 0 1 4.177-2.643 M22 8.82a15 15 0 0 0-11.288-3.764 M2 2l20 20",
        "alert-circle": "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M12 7v6 M12 16.5h.01",
        "shield-x": "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M9.5 9.5l5 5 M14.5 9.5l-5 5",
        "check-mark": "M5 12.5L9.5 17L19 7",   // the «Авто» card's check (PageServersTribe)
        "chevron-down": "M6 9l6 6 6-6",
        "chevron-up": "M6 15l6-6 6 6",
        "chevron-right": "M9 18l6-6-6-6",   // the Scanner's country choice rows (owner 24.11), app only like the keys above
        "info-circle": "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z M12 16v-4 M12 8h.01",
        "check-circle": "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Z M9 12l2 2 4-4",
        "alert-triangle": "M21.73 18l-8-14a2 2 0 0 0-3.46 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z M12 9v4 M12 17h.01",
        // the Scanner's network chip on a mobile network (Lucide «signal»), owner 18.11 - app only, like the keys above
        "cellular": "M2 20h.01 M7 20v-4 M12 20v-8 M17 20V8 M22 4v16",
        // Support's «Проверить подключение и отправить отчёт» (variant B, 18.11): the former Doctor button's glyph
        "activity": "M22 12h-4l-3 9L9 3l-3 9H2",
        // the Scanner's count badge «228» (owner 25.11: a server icon and the number; Lucide «server») - app only
        "server": "M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z M4 14h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2z M6 6h.01 M6 18h.01"
    })
    readonly property string pathD: paths[icon] || ""

    Shape {
        width: 24
        height: 24
        visible: root.pathD !== ""
        preferredRendererType: Shape.CurveRenderer
        // path в сетке 24 → масштаб под фактический размер компонента
        transform: Scale { xScale: root.width / 24; yScale: root.height / 24 }

        ShapePath {
            strokeColor: root.tint
            fillColor: "transparent"
            strokeWidth: root.weight
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: root.pathD }
        }
    }
}
