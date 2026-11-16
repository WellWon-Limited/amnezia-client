// Unit check for avpn::ApkUpdate (Android in-app update: URL guard, inspect parsing, verdict,
// installer status texts). Standalone (QtCore only), no network, no device.
// Run: build_apk_update_policy.sh
#include "../ApkUpdatePolicy.h"

#include <QUrl>
#include <cstdio>

static int g_fail = 0;
#define CHECK(cond, name)                                                                          \
    do {                                                                                           \
        if (cond) {                                                                                \
            std::printf("OK   %s\n", name);                                                        \
        } else {                                                                                   \
            std::printf("FAIL %s\n", name);                                                        \
            ++g_fail;                                                                              \
        }                                                                                          \
    } while (0)

int main()
{
    using namespace avpn::ApkUpdate;

    // --- URL guard: only https, only our host, only an .apk path ---
    CHECK(urlAllowed(QUrl("https://tribevpn.com/dl/TribeVPN.apk")), "stable link allowed");
    CHECK(urlAllowed(QUrl("https://tribevpn.com/dl/TribeVPN-5.1.110-140.apk")), "versioned link allowed");
    CHECK(urlAllowed(QUrl("https://TRIBEVPN.COM/dl/TribeVPN.apk")), "host is case-insensitive");
    CHECK(!urlAllowed(QUrl("http://tribevpn.com/dl/TribeVPN.apk")), "plain http rejected");
    CHECK(!urlAllowed(QUrl("https://evil.example/dl/TribeVPN.apk")), "foreign host rejected");
    CHECK(!urlAllowed(QUrl("https://tribevpn.com.evil.example/TribeVPN.apk")), "suffix trick rejected");
    CHECK(!urlAllowed(QUrl("https://cdn.tribevpn.com/TribeVPN.apk")), "subdomain rejected");
    CHECK(!urlAllowed(QUrl("https://tribevpn.com/dl/TribeVPN.exe")), "non-apk path rejected");
    CHECK(!urlAllowed(QUrl("https://user@tribevpn.com/dl/TribeVPN.apk")), "userinfo rejected");
    CHECK(!urlAllowed(QUrl("https://tribevpn.com:8443/dl/TribeVPN.apk")), "non-default port rejected");
    CHECK(!urlAllowed(QUrl()), "empty url rejected");
    CHECK(!urlAllowed(QUrl("https://play.google.com/store/apps/details?id=com.tribevpn.client")),
          "Play fallback link is not an APK");

    // --- inspect line from Kotlin: ok|package|versionCode|versionName|signerMatch ---
    ApkInfo a = parseInspect(QStringLiteral("ok|com.tribevpn.client|2179|5.1.110.140|1"));
    CHECK(a.parsed && a.packageName == "com.tribevpn.client" && a.versionCode == 2179
              && a.versionName == "5.1.110.140" && a.signerMatches,
          "full inspect line parsed");
    ApkInfo b = parseInspect(QStringLiteral("ok|com.tribevpn.client|2179|5.1.110.140|0"));
    CHECK(b.parsed && !b.signerMatches, "signer mismatch flag parsed");
    CHECK(!parseInspect(QStringLiteral("err|parse")).parsed, "error line -> not parsed");
    CHECK(!parseInspect(QStringLiteral("ok|com.tribevpn.client|x|5.1.110|1")).parsed, "bad code -> not parsed");
    CHECK(!parseInspect(QStringLiteral("ok|com.tribevpn.client|2179")).parsed, "short line -> not parsed");
    CHECK(!parseInspect(QString()).parsed, "empty -> not parsed");

    // --- verdict ---
    const QString own = QStringLiteral("com.tribevpn.client");
    CHECK(verdict(a, own, 2178, QStringLiteral("5.1.110")) == Verdict::Ok, "newer, same signer, expected version -> ok");
    CHECK(verdict(a, own, 2178, QStringLiteral("5.1.110.140")) == Verdict::Ok, "full expected version -> ok");
    CHECK(verdict(a, own, 2178, QString()) == Verdict::Ok, "no expected version -> version not pinned");
    CHECK(verdict(a, own, 2178, QStringLiteral("5.1.11")) == Verdict::WrongVersion,
          "5.1.110 does not satisfy expected 5.1.11 (component boundary)");
    CHECK(verdict(a, own, 2178, QStringLiteral("5.1.111")) == Verdict::WrongVersion, "other version -> wrong version");
    CHECK(verdict(a, own, 2179, QStringLiteral("5.1.110")) == Verdict::NotNewer, "same code -> not newer");
    CHECK(verdict(a, own, 2180, QStringLiteral("5.1.110")) == Verdict::NotNewer, "older code -> not newer");
    CHECK(verdict(b, own, 2178, QStringLiteral("5.1.110")) == Verdict::WrongSigner, "other signer -> rejected");
    CHECK(verdict(a, QStringLiteral("org.antivpn.client"), 2178, QString()) == Verdict::WrongPackage,
          "other package -> rejected");
    CHECK(verdict(parseInspect(QStringLiteral("err|parse")), own, 2178, QString()) == Verdict::Unreadable,
          "unparsed -> unreadable");
    // Signer is checked before version: a foreign-signed APK never reaches the installer even if newer.
    ApkInfo c = parseInspect(QStringLiteral("ok|com.tribevpn.client|2100|5.1.90.120|0"));
    CHECK(verdict(c, own, 2178, QString()) == Verdict::WrongSigner, "signer reported before version");

    // --- human texts: every verdict but Ok and every installer failure has a text ---
    for (Verdict v : {Verdict::Unreadable, Verdict::WrongPackage, Verdict::NotNewer, Verdict::WrongVersion,
                      Verdict::WrongSigner})
        CHECK(!verdictText(v).isEmpty(), "verdict text present");
    CHECK(verdictText(Verdict::Ok).isEmpty(), "ok has no failure text");
    CHECK(installStatusText(kStatusAborted) != installStatusText(kStatusFailure), "cancel reads differently from failure");
    for (int s : {kStatusFailure, kStatusBlocked, kStatusAborted, kStatusInvalid, kStatusConflict, kStatusStorage,
                  kStatusIncompatible, 42})
        CHECK(!installStatusText(s).isEmpty(), "installer status text present");

    // --- size cap ---
    CHECK(sizeAllowed(78'454'138), "75 MB allowed");
    CHECK(!sizeAllowed(kMaxApkBytes + 1), "over cap rejected");
    CHECK(sizeAllowed(-1), "unknown length is allowed (checked while receiving)");

    if (g_fail) {
        std::printf("FAILED: %d\n", g_fail);
        return 1;
    }
    std::printf("ALL OK\n");
    return 0;
}
