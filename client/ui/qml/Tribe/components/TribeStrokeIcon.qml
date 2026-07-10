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
        "clock": "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20z M12 6v6l4 2",
        "wifi": "M5 13a10 10 0 0 1 14 0 M8.5 16.5a5 5 0 0 1 7 0 M2 8.8a15 15 0 0 1 20 0 M12 20h.01",
        "rocket": "M4.5 16.5c-1.5 1.26-2 5-2 5s3.74-.5 5-2c.71-.84.7-2.13-.09-2.91a2.18 2.18 0 0 0-2.91-.09z M12 15l-3-3a22 22 0 0 1 2-3.95A12.88 12.88 0 0 1 22 2c0 2.72-.78 7.5-6 11a22.35 22.35 0 0 1-4 2z M9 12H4s.55-3.03 2-4c1.62-1.08 5 0 5 0 M12 15v5s3.03-.55 4-2c1.08-1.62 0-5 0-5"
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
            strokeWidth: 2
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: root.pathD }
        }
    }
}
