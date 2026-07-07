pragma Singleton
import QtQuick

// AVPN: dev/админ-состояние приложения (НЕ дизайн-токены — те в Theme.qml).
// adminMode показывает скрытые элементы для разработчиков/админов:
// мост в Amnezia-UI (PageAccountTribe), диагностика и т.п.
// Переключается щитом слева от шестерёнки на Connect-экране.
QtObject {
    property bool adminMode: false
    // полный интерфейс Amnezia (ванильный TabBar + их страницы) вместо Tribe-UI;
    // вход — иконка «А» на Connect (видна в adminMode), выход — кнопка «‹ Tribe»
    property bool amneziaMode: false
    // «Панель администратора» внизу настроек (бенч соединения и будущие тест-инструменты).
    // Релиз: карточка видна ТОЛЬКО устройствам с серверным is_admin (TribeEngine.isAdminDevice,
    // devices.is_admin в бэкенде). Этот флаг — локальный dev-override для превью с диска
    // (AVPN_QML_SRC), где движка нет: включить true руками, НЕ коммитить.
    property bool adminPanelVisible: false
}
