pragma Singleton
import QtQuick

// AVPN: dev/админ-состояние приложения (НЕ дизайн-токены — те в Theme.qml).
// adminMode показывает скрытые dev-элементы (иконка пула нод на Connect и т.п.).
// UI-переключателя НЕТ: включается ТОЛЬКО правкой этого файла в dev-превью с диска
// (AVPN_QML_SRC). true НЕ коммитить — в проде обязан быть false.
QtObject {
    property bool adminMode: false
    // полный интерфейс Amnezia (ванильный TabBar + их страницы) вместо Tribe-UI.
    // Runtime-входа нет (requestAmnezia не эмитится) — включать только правкой файла
    // в dev-превью; выход — плавающая кнопка «‹ Tribe» (PageStart).
    property bool amneziaMode: false
    // «Панель администратора» внизу настроек (бенч соединения и будущие тест-инструменты).
    // Релиз: карточка видна ТОЛЬКО устройствам с серверным is_admin (TribeEngine.isAdminDevice,
    // devices.is_admin в бэкенде). Этот флаг — локальный dev-override для превью с диска
    // (AVPN_QML_SRC), где движка нет: включить true руками, НЕ коммитить.
    property bool adminPanelVisible: false
}
