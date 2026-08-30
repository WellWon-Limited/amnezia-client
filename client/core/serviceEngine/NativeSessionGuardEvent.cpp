#include "NativeSessionGuardEvent.h"

#include <QSet>
#include <QUuid>

namespace avpn {
namespace {

bool parseCanonicalTokenPart(const QJsonValue &value, quint64 &out)
{
    out = 0;
    if (!value.isString()) return false;
    const QString text = value.toString();
    if (text.isEmpty() || text.size() > 20
        || (text.size() > 1 && text.startsWith(QLatin1Char('0')))) return false;
    bool ok = false;
    const quint64 parsed = text.toULongLong(&ok, 10);
    if (!ok || parsed == 0 || QString::number(parsed) != text) return false;
    out = parsed;
    return true;
}

bool canonicalRuntimeUuid(const QString &value)
{
    const QUuid uuid(value);
    return !uuid.isNull() && uuid.toString(QUuid::WithoutBraces).toLower() == value;
}

bool safeGuardOpaque(const QString &value, bool mayBeEmpty = false)
{
    if (value.isEmpty()) return mayBeEmpty;
    if (value.size() > 200) return false;
    for (const QChar ch : value) {
        const ushort code = ch.unicode();
        const bool asciiAlphaNumeric = (code >= 'A' && code <= 'Z')
            || (code >= 'a' && code <= 'z') || (code >= '0' && code <= '9');
        if (!asciiAlphaNumeric && ch != QLatin1Char('-') && ch != QLatin1Char('_')
            && ch != QLatin1Char(':') && ch != QLatin1Char('.')) return false;
    }
    return true;
}

bool schemaOne(const QJsonValue &value)
{
    return value.isDouble() && value.toDouble() == 1.0;
}

} // namespace

bool parseNativeSessionGuardEvent(const QJsonObject &event,
                                  ConnectionGuardEvent &parsed,
                                  QString &error)
{
    parsed = {};
    error.clear();
    static const QSet<QString> exactKeys = {
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("operation"),
        QStringLiteral("session"), QStringLiteral("kind"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason"),
    };
    const QStringList eventKeys = event.keys();
    if (QSet<QString>(eventKeys.cbegin(), eventKeys.cend()) != exactKeys
        || event.value(QStringLiteral("type"))
               != QLatin1String("native_session_guard_v1")
        || !schemaOne(event.value(QStringLiteral("schema")))) {
        error = QStringLiteral("native session guard event schema mismatch");
        return false;
    }
    quint64 operationValue = 0, sessionValue = 0;
    if (!parseCanonicalTokenPart(event.value(QStringLiteral("operation")), operationValue)
        || !parseCanonicalTokenPart(event.value(QStringLiteral("session")), sessionValue)) {
        error = QStringLiteral("native session guard event token invalid");
        return false;
    }
    const QString kind = event.value(QStringLiteral("kind")).toString();
    const QString policyText = event.value(QStringLiteral("policy_sha256")).toString();
    const QByteArray policy = QByteArray::fromHex(policyText.toLatin1());
    const QString outer = event.value(QStringLiteral("outer_session_id")).toString();
    const QString expected = event.value(
        QStringLiteral("expected_runtime_session_id")).toString();
    const QString reason = event.value(QStringLiteral("reason")).toString();
    if (policy.size() != 32 || QString::fromLatin1(policy.toHex()) != policyText
        || !canonicalRuntimeUuid(expected) || reason.size() > 96) {
        error = QStringLiteral("native session guard event identity invalid");
        return false;
    }
    for (const QChar ch : reason) {
        if (ch.unicode() < 0x20 || ch.unicode() > 0x7e) {
            error = QStringLiteral("native session guard event reason invalid");
            return false;
        }
    }

    ConnectionGuardEventKind eventKind;
    if (kind == QLatin1String("armed")) eventKind = ConnectionGuardEventKind::Armed;
    else if (kind == QLatin1String("arm_rejected"))
        eventKind = ConnectionGuardEventKind::ArmRejected;
    else if (kind == QLatin1String("released"))
        eventKind = ConnectionGuardEventKind::Released;
    else if (kind == QLatin1String("release_rejected"))
        eventKind = ConnectionGuardEventKind::ReleaseRejected;
    else if (kind == QLatin1String("lost")) eventKind = ConnectionGuardEventKind::Lost;
    else {
        error = QStringLiteral("native session guard event kind unsupported");
        return false;
    }
    const bool outerMayBeEmpty = eventKind == ConnectionGuardEventKind::ArmRejected;
    if (!safeGuardOpaque(outer, outerMayBeEmpty)) {
        error = QStringLiteral("native session guard outer identity invalid");
        return false;
    }
    parsed = {{operationValue, sessionValue}, eventKind, policy, outer, reason, expected};
    return true;
}

bool parseNativeSessionGuardRecoveryReceipt(const QJsonObject &receipt,
                                            NativeGuardRecoveryReceipt &parsed,
                                            QString &error)
{
    parsed = {};
    error.clear();
    static const QSet<QString> exactKeys = {
        QStringLiteral("type"), QStringLiteral("schema"), QStringLiteral("action"),
        QStringLiteral("kind"), QStringLiteral("operation"), QStringLiteral("session"),
        QStringLiteral("policy_sha256"), QStringLiteral("outer_session_id"),
        QStringLiteral("expected_runtime_session_id"), QStringLiteral("reason"),
    };
    const QStringList receiptKeys = receipt.keys();
    if (QSet<QString>(receiptKeys.cbegin(), receiptKeys.cend()) != exactKeys
        || receipt.value(QStringLiteral("type"))
               != QLatin1String("native_session_guard_recovery_v1")
        || !schemaOne(receipt.value(QStringLiteral("schema")))) {
        error = QStringLiteral("native guard recovery receipt schema mismatch");
        return false;
    }
    const QString actionText = receipt.value(QStringLiteral("action")).toString();
    const QString kindText = receipt.value(QStringLiteral("kind")).toString();
    NativeGuardRecoveryAction action;
    NativeGuardRecoveryKind kind;
    if (actionText == QLatin1String("adopt")) {
        action = NativeGuardRecoveryAction::Adopt;
        if (kindText == QLatin1String("adopted")) kind = NativeGuardRecoveryKind::Adopted;
        else if (kindText == QLatin1String("rejected"))
            kind = NativeGuardRecoveryKind::Rejected;
        else {
            error = QStringLiteral("native guard recovery adopt kind invalid");
            return false;
        }
    } else if (actionText == QLatin1String("stop")) {
        action = NativeGuardRecoveryAction::Stop;
        if (kindText == QLatin1String("stopped_released"))
            kind = NativeGuardRecoveryKind::StoppedReleased;
        else if (kindText == QLatin1String("rejected"))
            kind = NativeGuardRecoveryKind::Rejected;
        else {
            error = QStringLiteral("native guard recovery stop kind invalid");
            return false;
        }
    } else {
        error = QStringLiteral("native guard recovery action invalid");
        return false;
    }

    QJsonObject identity{
        {QStringLiteral("type"), QStringLiteral("native_session_guard_v1")},
        {QStringLiteral("schema"), 1},
        {QStringLiteral("operation"), receipt.value(QStringLiteral("operation"))},
        {QStringLiteral("session"), receipt.value(QStringLiteral("session"))},
        // Recovery receipts describe an existing lease. `armed` has the same strict non-empty
        // outer identity grammar and lets us reuse the single typed identity parser.
        {QStringLiteral("kind"), QStringLiteral("armed")},
        {QStringLiteral("policy_sha256"), receipt.value(QStringLiteral("policy_sha256"))},
        {QStringLiteral("outer_session_id"), receipt.value(QStringLiteral("outer_session_id"))},
        {QStringLiteral("expected_runtime_session_id"),
         receipt.value(QStringLiteral("expected_runtime_session_id"))},
        {QStringLiteral("reason"), receipt.value(QStringLiteral("reason"))},
    };
    ConnectionGuardEvent typedIdentity;
    if (!parseNativeSessionGuardEvent(identity, typedIdentity, error)) return false;
    parsed = {action, kind, typedIdentity};
    return true;
}

} // namespace avpn
