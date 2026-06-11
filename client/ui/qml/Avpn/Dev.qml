pragma Singleton
import QtQuick

// AVPN: dev/админ-состояние приложения (НЕ дизайн-токены — те в Theme.qml).
// adminMode показывает скрытые элементы для разработчиков/админов:
// мост в Amnezia-UI (PageAccountAvpn), диагностика и т.п.
// Переключается щитом слева от шестерёнки на Connect-экране.
QtObject {
    property bool adminMode: false
}
