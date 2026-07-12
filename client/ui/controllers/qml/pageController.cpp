#include "pageController.h"

#include "ui/utils/converter.h"
#include "core/utils/errorStrings.h"
#if defined(MACOS_NE)
#include "platforms/ios/ios_controller.h"
#endif

#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS) || defined(MACOS_NE)
    #include <QGuiApplication>
#else
    #include <QApplication>
#endif

#ifdef Q_OS_ANDROID
    #include "platforms/android/android_controller.h"
#endif
#if defined Q_OS_MAC
    #include "ui/utils/macosUtil.h"
#endif

// AVPN: нативный iOS safe-area inset (AvpnSafeArea.mm) — Qt даёт 0 при ExpandedClientAreaHint.
#ifdef Q_OS_IOS
    #include <QInputMethod> // AVPN: высота клавиатуры для imeHeight (см. конструктор)
    #include <QQuickWindow> // AVPN: фазовая синхронизация — применение высоты в afterAnimating
    #include <QRectF>       // AVPN: keyboardRectangle() — без включения тип только forward-declared
    #include <QTimer>       // AVPN: отложенный анти-сдвиг окна (см. конструктор)
extern "C" int avpnSafeAreaTop();
extern "C" int avpnSafeAreaBottom();
extern "C" void Avpn_resetKeyboardScroll();         // AVPN: сброс авто-сдвига окна (AvpnKeyboardFix.mm)
extern "C" void Avpn_installKeyboardScrollKiller(); // AVPN: observer UIKeyboard* → сброс на каждом событии

// AVPN (2026-07-12): нативный willShow/willHide-репорт высоты клавиатуры (AvpnKeyboardFix.mm)
// — синхронный старт подъёма композера с анимацией клавиатуры. Уведомления UIKit приходят
// на main thread (= GUI-поток Qt) — прямой вызов безопасен.
static PageController *s_avpnPageController = nullptr;
static QQuickWindow *s_avpnQuickWindow = nullptr;
extern "C" void Avpn_onKeyboardFrame(double height)
{
    if (s_avpnPageController)
        s_avpnPageController->avpnSetImeHeight(qMax(0, qRound(height)));
}
// ФАЗОВАЯ СИНХРОНИЗАЦИЯ: displaylink трекера клавиатуры будит рендер Qt; высота
// применяется в afterAnimating (начало кадра) — поле и клавиатура рисуются синфазно.
extern "C" double Avpn_currentKeyboardHeight(void); // AvpnKeyboardFix.mm (−1 = нет трекинга)
extern "C" void Avpn_pokeQtFrame(void)
{
    if (s_avpnQuickWindow)
        s_avpnQuickWindow->update(); // main thread (см. tick displaylink) — безопасно
}
extern "C" int Avpn_qtFrameHooked(void)
{
    return s_avpnQuickWindow != nullptr;
}
#endif

PageController::PageController(ServersController* serversController, SettingsController* settingsController,
                               QObject *parent)
    : QObject(parent), m_serversController(serversController), m_settingsController(settingsController)
{
#ifdef Q_OS_ANDROID
    auto initialPageNavigationBarColor = getInitialPageNavigationBarColor();
    AndroidController::instance()->setNavigationBarColor(initialPageNavigationBarColor);

    connect(AndroidController::instance(), &AndroidController::imeInsetsChanged, this, [this](int heightDp) {
        m_imeHeight = heightDp;
        emit imeHeightChanged(heightDp);
        emit safeAreaBottomMarginChanged();
    });
    connect(AndroidController::instance(), &AndroidController::systemBarsInsetsChanged, this, [this](int navBarHeightDp, int statusBarHeightDp) {
        m_cachedNavigationBarHeight = navBarHeightDp;
        m_cachedStatusBarHeight = statusBarHeightDp;
        emit safeAreaBottomMarginChanged();
        emit safeAreaTopMarginChanged();
    });
#endif

#ifdef Q_OS_IOS
    // AVPN (Support-чат, 2026-07-10): imeHeight питался ТОЛЬКО с Android (imeInsetsChanged) —
    // на iOS всегда 0, поэтому при клавиатуре навбар не скрывался и iOS выталкивала весь UI
    // (вкл. нижнее меню) вверх. Высота клавиатуры — из QInputMethod::keyboardRectangle
    // (координаты окна = логические px; окно fullscreen). Скрыта → rect пустой → 0.
    // Гаситель ставим на нативные UIKeyboard*-уведомления: наш observer регистрируется
    // ПОЗЖЕ Qt-плагина → выполняется после их scroll() в том же уведомлении, до кадра.
    // Указатель — ДО install: observers сразу репортят высоту через Avpn_onKeyboardFrame.
    s_avpnPageController = this;
    Avpn_installKeyboardScrollKiller();
    // Фолбэк-путь через Qt (основной — нативный willShow-репорт, он приходит в момент
    // СТАРТА анимации клавиатуры; Qt сообщает позже — композер выезжал с опозданием).
    QInputMethod *im = QGuiApplication::inputMethod();
    connect(im, &QInputMethod::keyboardRectangleChanged, this, [this, im]() {
        // Фолбэк ТОЛЬКО когда нет покадрового трекинга (iOS <15 / трекер не поднялся):
        // при живом трекинге этот поздний репорт дёргал бы margin мимо фазы кадра.
        if (Avpn_currentKeyboardHeight() < 0)
            avpnSetImeHeight(qMax(0, qRound(im->keyboardRectangle().height())));
    });
    avpnHookQuickWindow(); // afterAnimating: применение высоты трекера в начале кадра
#endif

#if defined Q_OS_MACX
    connect(this, &PageController::raiseMainWindow, []() {
        setDockIconVisible(true);
    });
    connect(this, &PageController::hideMainWindow, []() {
        setDockIconVisible(false);
    });
#endif

    connect(this, qOverload<ErrorCode>(&PageController::showErrorMessage), this, &PageController::onShowErrorMessage);
    
    m_isTriggeredByConnectButton = false;
}

#ifdef Q_OS_IOS
// AVPN: подключение к кадру Qt Quick. Окно может ещё не существовать при создании
// контроллера (QML грузится позже) — ретраим, пока не появится.
void PageController::avpnHookQuickWindow()
{
    QQuickWindow *qw = nullptr;
    const auto wins = QGuiApplication::allWindows();
    for (QWindow *w : wins) {
        qw = qobject_cast<QQuickWindow *>(w);
        if (qw)
            break;
    }
    if (!qw) {
        QTimer::singleShot(500, this, [this]() { avpnHookQuickWindow(); });
        return;
    }
    s_avpnQuickWindow = qw;
    // afterAnimating = GUI-поток, начало каждого кадра (до синхронизации сцены):
    // высота, применённая здесь, рисуется В ЭТОМ ЖЕ кадре — синфазно с клавиатурой.
    connect(qw, &QQuickWindow::afterAnimating, this, [this]() {
        const double h = Avpn_currentKeyboardHeight();
        if (h >= 0)
            avpnSetImeHeight(qRound(h));
    });
}

// AVPN: единая точка обновления высоты клавиатуры (нативный willShow-репорт + Qt-фолбэк).
void PageController::avpnSetImeHeight(int h)
{
    if (h == m_imeHeight)
        return;
    const bool wasZero = (m_imeHeight == 0);
    m_imeHeight = h;
    emit imeHeightChanged(h);
    emit safeAreaBottomMarginChanged();
    // Трекер keyboardLayoutGuide шлёт высоту ПОКАДРОВО — страховочные сбросы взводим
    // только на переходе 0→клавиатура, а не 60 раз в секунду.
    if (!wasZero)
        return;
    // АНТИ-СДВИГ (2026-07-11, билды 75–77): QIOSInputContext на показ клавиатуры уводит
    // root view вверх через layer.sublayerTransform (наш margin + их сдвиг = «чёрная
    // дыра» высотой с клавиатуру). Мягкие способы НЕ работают: их пере-проверка
    // (update→ImeState::update) диффит ЛОКАЛЬНЫЙ прямоугольник курсора в поле — он не
    // меняется, когда наш layout поднимает поле целиком. Сбрасываем трансформ напрямую
    // (AvpnKeyboardFix.mm). Несколько тиков — их scroll() ставится на willShow и
    // анимируется; одиночный сброс переигрывался бы этой анимацией.
    if (h > 0) {
        for (const int delayMs : {60, 250, 650})
            QTimer::singleShot(delayMs, this, []() { Avpn_resetKeyboardScroll(); });
    }
}
#endif

bool PageController::isStartPageVisible()
{
    return m_serversController->getServersCount() == 0;
}

QString PageController::getPagePath(PageLoader::PageEnum page)
{
    QMetaEnum metaEnum = QMetaEnum::fromType<PageLoader::PageEnum>();
    QString pageName = metaEnum.valueToKey(static_cast<int>(page));
    // dev hot-reload: грузить страницы с диска, если задан AVPN_QML_SRC (правка QML → ui-reload без пересборки)
    const QByteArray qmlSrc = qgetenv("AVPN_QML_SRC");
    if (!qmlSrc.isEmpty())
        return "file://" + QString::fromUtf8(qmlSrc) + "/Pages2/" + pageName + ".qml";
    return "qrc:/ui/qml/Pages2/" + pageName + ".qml";
}

void PageController::closeWindow()
{
#if defined(Q_OS_ANDROID) || defined(Q_OS_IOS)
    qApp->quit();
#else
    emit hideMainWindow();
#endif
}

void PageController::hideWindow()
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->minimizeApp();
#endif
}

void PageController::keyPressEvent(Qt::Key key)
{
    switch (key) {
    case Qt::Key_Back:
    case Qt::Key_Escape: {
        if (m_drawerDepth) {
            emit closeTopDrawer();
            decrementDrawerDepth();
        } else {
            emit escapePressed();
        }
        break;
    }
    default: return;
    }
}

unsigned int PageController::getInitialPageNavigationBarColor()
{
    if (m_serversController->getServersCount()) {
        return 0xFF1C1D21;
    } else {
        return 0xFF0E0E11;
    }
}

void PageController::updateNavigationBarColor(const int color)
{
#ifdef Q_OS_ANDROID
    AndroidController::instance()->setNavigationBarColor(color);
#endif
}

void PageController::showOnStartup()
{
    if (!m_settingsController->isStartMinimizedEnabled()) {
        emit raiseMainWindow();
    } else {
#if defined(Q_OS_WIN) || (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID))
        emit hideMainWindow();
#elif defined(Q_OS_MACX)
        setDockIconVisible(false);
#endif
    }
}

bool PageController::isTriggeredByConnectButton()
{
    return m_isTriggeredByConnectButton;
}

void PageController::setTriggeredByConnectButton(bool trigger)
{
    m_isTriggeredByConnectButton = trigger;
}

void PageController::closeApplication()
{
    qApp->quit();
}

void PageController::setDrawerDepth(const int depth)
{
    if (depth >= 0) {
        m_drawerDepth = depth;
    }
}

int PageController::getDrawerDepth() const
{
    return m_drawerDepth;
}

int PageController::incrementDrawerDepth()
{
    return ++m_drawerDepth;
}

int PageController::decrementDrawerDepth()
{
    if (m_drawerDepth == 0) {
        return m_drawerDepth;
    } else {
        return --m_drawerDepth;
    }
}

bool PageController::isEdgeToEdgeEnabled()
{
#ifdef Q_OS_ANDROID
    if (!m_edgeToEdgeCached) {
        m_cachedEdgeToEdgeEnabled = AndroidController::instance()->isEdgeToEdgeEnabled();
        m_edgeToEdgeCached = true;
    }
    return m_cachedEdgeToEdgeEnabled;
#else
    return false;
#endif
}

int PageController::getStatusBarHeight()
{
#ifdef Q_OS_ANDROID
    if (m_cachedStatusBarHeight < 0) {
        m_cachedStatusBarHeight = AndroidController::instance()->getStatusBarHeight();
    }
    return m_cachedStatusBarHeight;
#else
    return 0;
#endif
}

int PageController::getNavigationBarHeight()
{
#ifdef Q_OS_ANDROID
    if (m_cachedNavigationBarHeight < 0) {
        m_cachedNavigationBarHeight = AndroidController::instance()->getNavigationBarHeight();
    }
    return m_cachedNavigationBarHeight;
#else
    return 0;
#endif
}

int PageController::getSafeAreaTopMargin()
{
#ifdef Q_OS_ANDROID
    if (isEdgeToEdgeEnabled()) {
        int height = getStatusBarHeight();
        int result = height > 0 ? height : 40;
        return result;
    }
#endif
#ifdef Q_OS_IOS
    return avpnSafeAreaTop(); // AVPN: реальный инсет выреза/Dynamic Island из UIKit
#endif
    return 0;
}

int PageController::getSafeAreaBottomMargin()
{
#ifdef Q_OS_ANDROID
    if (isEdgeToEdgeEnabled()) {
        if (m_imeHeight > 0) {
            return 0;
        }
        
        int height = getNavigationBarHeight();
        int result = height > 0 ? height : 56;
        return result;
    }
#endif
#ifdef Q_OS_IOS
    return avpnSafeAreaBottom(); // AVPN: реальный нижний инсет (home-индикатор) из UIKit
#endif
    return 0;
}

int PageController::getImeHeight()
{
    return m_imeHeight;
}

void PageController::onShowErrorMessage(ErrorCode errorCode)
{
    const auto fullErrorMessage = errorString(errorCode);
    const auto errorMessage = fullErrorMessage.mid(fullErrorMessage.indexOf(". ") + 1); // remove ErrorCode %1.
    const auto errorUrl = QStringLiteral("troubleshooting/error-codes/#error-%1-%2").arg(static_cast<int>(errorCode)).arg(utils::enumToString(errorCode).toLower());
    // AVPN: код ошибки красным (токен danger #E2625C из Tribe/Theme.qml) + текст с новой строки.
    // Qt игнорирует style= у <a> (красит в Text.linkColor) — цвет задаём через <font color>.
    const auto fullMessage = QStringLiteral("<a href=\"%1\"><font color=\"#E2625C\">ErrorCode: %2</font></a><br>%3").arg(errorUrl).arg(static_cast<int>(errorCode)).arg(errorMessage);

    emit showErrorMessage(fullMessage);
}
