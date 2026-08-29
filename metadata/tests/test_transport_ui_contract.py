import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class TransportUiContractTests(unittest.TestCase):
    def test_requested_mode_is_not_presented_as_runtime_fact(self) -> None:
        selector = source("client/ui/qml/Tribe/components/TribeTransportSelector.qml")
        connect = source("client/ui/qml/Tribe/Pages/PageConnectTribe.qml")
        self.assertIn('property string mode: "auto"', selector)
        self.assertIn("signal modeRequested(string mode)", selector)
        self.assertIn("TribeConnection.actualTransport", connect)
        self.assertIn("transport: root.actualTransport", connect)
        self.assertIn("verification: root.verificationState", connect)
        self.assertIn("currentCatalogLocation", connect)
        self.assertIn("selectedCatalogLocation", connect)
        self.assertIn("Для следующего подключения", connect)

    def test_forced_transport_scopes_availability_ranking_and_history(self) -> None:
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        self.assertIn('root.modeAvailable("awg")', servers)
        self.assertIn('root.modeAvailable("xray")', servers)
        self.assertIn('connectionMode === "awg" ? awgQuality', servers)
        self.assertIn('connectionMode !== "xray"', servers)
        self.assertIn('connectionMode !== "awg"', servers)
        self.assertIn("age_anchor_catalog_age", servers)

    def test_transport_selector_remains_visible_on_legacy_awg_pool(self) -> None:
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        self.assertIn('id: transportSelector', servers)
        self.assertIn('? String(TribeConnection.connectionMode || "auto")\n                                               : "awg"', servers)
        self.assertIn('awgAvailable: root.useCatalog ? root.modeAvailable("awg") : true', servers)
        self.assertIn('xrayAvailable: root.useCatalog && root.modeAvailable("xray")', servers)
        self.assertIn('qsTr("Для этого режима пока нет доступных серверов")', servers)
        self.assertNotIn('visible: root.useCatalog\n            mode: root.connectionMode', servers)

    def test_rootless_preview_cannot_claim_catalog_v2_authority(self) -> None:
        engine = source("client/core/serviceEngine/AvpnEngineQml.cpp")
        guard = engine.index("if (offlineRoots.isEmpty())")
        composition = engine.index("m_catalogRuntime = new CatalogProductRuntime")
        self.assertLess(guard, composition)
        self.assertIn('QStringLiteral("catalog_v2_build_trust_unavailable")', engine)
        self.assertIn("catalog-v2 composition skipped; offline root unavailable", engine)

    def test_quality_hints_are_neutral_and_green_requires_fresh_receipt(self) -> None:
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        connect = source("client/ui/qml/Tribe/Pages/PageConnectTribe.qml")
        badge = source("client/ui/qml/Tribe/components/TribeTransportBadge.qml")
        self.assertIn("barColor: root.useCatalog ? Theme.color.accent", servers)
        self.assertIn("predicted_quality", servers)
        self.assertIn("прогноз %1%", servers)
        self.assertIn("TribeConnection.verified === true", connect)
        self.assertIn('rawVerificationState === "verified" && !receiptFresh', connect)
        self.assertIn('readonly property bool verified: verification === "verified"', badge)

    def test_primary_ui_is_version_neutral_and_failures_are_actionable(self) -> None:
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        connect = source("client/ui/qml/Tribe/Pages/PageConnectTribe.qml")
        page_start = source("client/ui/qml/Pages2/PageStart.qml")
        doctor = source("client/ui/qml/Tribe/components/TribeDoctorSheet.qml")
        self.assertNotIn("Amnezia v%1", servers)
        self.assertIn("showCatalogActionError", connect)
        self.assertIn("catalogErrorTextProvider.failureText", page_start)
        self.assertIn("v2ActionMessage", doctor)
        self.assertIn("TribeConnection.refreshCatalog()", servers)
        self.assertIn("Список серверов пока недоступен", servers)

    def test_transport_controls_have_keyboard_and_accessibility_contracts(self) -> None:
        selector = source("client/ui/qml/Tribe/components/TribeTransportSelector.qml")
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        connect = source("client/ui/qml/Tribe/Pages/PageConnectTribe.qml")
        doctor = source("client/ui/qml/Tribe/components/TribeDoctorSheet.qml")
        self.assertIn("Accessible.RadioButton", selector)
        self.assertIn("Accessible.onPressAction", servers)
        self.assertIn("Keys.onSpacePressed", servers)
        self.assertIn("Accessible.onPressAction", connect)
        self.assertIn("Keys.onSpacePressed", connect)
        self.assertIn("Accessible.name: primaryLabel.text", doctor)
        self.assertIn("id: retryCatalogButton", servers)

    def test_verified_age_uses_rollback_aware_facade_anchor(self) -> None:
        facade = source("client/core/serviceEngine/CatalogConnectionFacade.cpp")
        self.assertIn('QStringLiteral("age_anchor_catalog_age")', facade)
        self.assertIn("catalog.issuedAt.toUTC().secsTo(nowUtc)", facade)

    def test_signed_directory_keeps_public_locations_separate_from_shortlist(self) -> None:
        facade = source("client/core/serviceEngine/CatalogConnectionFacade.cpp")
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        self.assertIn("catalog.locationDirectory->locations", facade)
        self.assertIn('QStringLiteral("temporarily_unavailable")', facade)
        self.assertIn('QStringLiteral("retained_pin")', facade)
        self.assertIn("Выбранная локация временно недоступна", servers)
        self.assertIn("row.retainedPin === true", servers)

    def test_location_directory_copy_is_translated(self) -> None:
        servers = source("client/ui/qml/Tribe/Pages/PageServersTribe.qml")
        english = source("client/translations/tribe/tribe_en.ts")
        spanish = source("client/translations/tribe/tribe_es.ts")
        phrases = (
            "Выбранная локация",
            "Выбранная локация временно недоступна. Выбор сохранён",
            "AWG · оценка %1%",
            "AWG · прогноз %1%",
            "Xray · оценка %1%",
            "Xray · прогноз %1%",
        )
        for phrase in phrases:
            self.assertIn(f'qsTr("{phrase}")', servers)
            self.assertIn(f"<source>{phrase}</source>", english)
            self.assertIn(f"<source>{phrase}</source>", spanish)


if __name__ == "__main__":
    unittest.main()
