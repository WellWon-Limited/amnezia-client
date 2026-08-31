#ifndef PAGECONTROLLER_H
#define PAGECONTROLLER_H

#include <QObject>
#include <QQmlEngine>

#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/controllers/settingsController.h"
#include "core/controllers/serversController.h"
#include "ui/utils/pageEnum.h"

class PageController : public QObject
{
    Q_OBJECT
public:
    explicit PageController(ServersController* serversController, SettingsController* settingsController,
                            QObject *parent = nullptr);

    Q_PROPERTY(int safeAreaTopMargin READ getSafeAreaTopMargin NOTIFY safeAreaTopMarginChanged)
    Q_PROPERTY(int safeAreaBottomMargin READ getSafeAreaBottomMargin NOTIFY safeAreaBottomMarginChanged)
    Q_PROPERTY(int imeHeight READ getImeHeight NOTIFY imeHeightChanged)
    // AVPN (iOS, 2026-07-12): ЖИВАЯ высота клавиатуры по кадрам анимации (presentationLayer
    // трекера keyboardLayoutGuide, применяется в afterAnimating). imeHeight = ЦЕЛЬ (лайаут,
    // меняется один раз на показ/скрытие), imeShift = текущая позиция (для GPU-трансформов
    // чата на время анимации). −1 = живого трекинга нет (Android/десктоп/iOS<15).
    Q_PROPERTY(qreal imeShift READ getImeShift NOTIFY imeShiftChanged)

#ifdef Q_OS_IOS
    // AVPN (2026-07-12): высота клавиатуры из НАТИВНОГО UIKeyboardWillShow/WillHide
    // (AvpnKeyboardFix.mm → Avpn_onKeyboardFrame) — приходит в момент СТАРТА анимации
    // клавиатуры; Qt-путь (keyboardRectangleChanged) сообщал позже, и композер выезжал
    // с опозданием («клавиатура появляется, потом поле» — жалоба). Qt-путь остаётся фолбэком.
    void avpnSetImeHeight(int h);
    void avpnSetImeShift(qreal v); // живая позиция (per-frame, afterAnimating)
    // Фазовая синхронизация: подписка на QQuickWindow::afterAnimating (применение высоты
    // трекера keyboardLayoutGuide в начале кадра — синфазно с отрисовкой клавиатуры).
    void avpnHookQuickWindow();
#endif

public slots:
    bool isStartPageVisible();
    QString getPagePath(PageLoader::PageEnum page);

    void closeWindow();
    void hideWindow();
    void keyPressEvent(Qt::Key key);

    unsigned int getInitialPageNavigationBarColor();
    void updateNavigationBarColor(const int color);

    void showOnStartup();
    bool shouldStartMinimized() const;

    bool isTriggeredByConnectButton();
    void setTriggeredByConnectButton(bool trigger);

    void closeApplication();

    void setDrawerDepth(const int depth);
    int getDrawerDepth() const;
    int incrementDrawerDepth();
    int decrementDrawerDepth();

    bool isEdgeToEdgeEnabled();
    int getStatusBarHeight();
    int getNavigationBarHeight();
    int getSafeAreaTopMargin();
    int getSafeAreaBottomMargin();
    int getImeHeight();
    qreal getImeShift() const { return m_imeShift; } // AVPN: живая позиция клавиатуры (iOS)

private slots:
    void onShowErrorMessage(amnezia::ErrorCode errorCode);

signals:
    void goToPage(PageLoader::PageEnum page, bool slide = true);
    void goToStartPage();
    void goToPageHome();
    void goToPageSettings();
    void goToPageViewConfig();
    void goToPageSettingsServerServices();
    void goToPageSettingsBackup();
    void goToShareConnectionPage(QString headerText, QString configContentHeaderText, QString configCaption, QString configExtension,
                                 QString configFileName);

    void closePage();

    void restorePageHomeState(bool isContainerInstalled = false);

    void showErrorMessage(amnezia::ErrorCode);
    void showErrorMessage(const QString &errorMessage);
    void showNotificationMessage(const QString &message);

    void showBusyIndicator(bool visible);
    void disableControls(bool disabled);
    void disableTabBar(bool disabled);

    void hideMainWindow();
    void raiseMainWindow();

    void showPassphraseRequestDrawer();
    void passphraseRequestDrawerClosed(QString passphrase);

    void unsupportedConnectDrawerRequested();

    void escapePressed();
    void closeTopDrawer();

    void showChangelogDrawer();
    void imeHeightChanged(int height);
    void imeShiftChanged(); // AVPN: живая позиция клавиатуры (см. imeShift)
    void safeAreaTopMarginChanged();
    void safeAreaBottomMarginChanged();

private:
    ServersController* m_serversController;
    SettingsController* m_settingsController;

    bool m_isTriggeredByConnectButton;

    int m_drawerDepth = 0;

    mutable int m_cachedStatusBarHeight = -1;
    mutable int m_cachedNavigationBarHeight = -1;
    mutable bool m_cachedEdgeToEdgeEnabled = false;
    mutable bool m_edgeToEdgeCached = false;
    int m_imeHeight = 0;
    qreal m_imeShift = -1; // AVPN: −1 = живого покадрового трекинга нет
};

#endif
