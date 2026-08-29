import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


def source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class MacServicePromptContractTests(unittest.TestCase):
    def test_each_service_change_has_an_explicit_user_facing_reason(self) -> None:
        header = source("client/core/serviceEngine/MacServiceInstaller.h")
        implementation = source("client/core/serviceEngine/MacServiceInstaller.mm")
        engine = source("client/core/serviceEngine/AvpnEngineQml.cpp")

        for reason in ("FirstInstall", "Update", "Repair"):
            self.assertIn(reason, header)
            self.assertIn(f"MacServiceInstallReason::{reason}", implementation)
            self.assertIn(f"MacServiceInstallReason::{reason}", engine)

        for action in (
            "Установить службу",
            "Обновить службу",
            "Восстановить службу",
        ):
            self.assertIn(action, implementation)

        self.assertIn("аккаунт и настройки сохранятся", implementation)
        self.assertIn("macOS запросит пароль администратора", implementation)

    def test_confirmation_is_in_process_and_precedes_privileged_update(self) -> None:
        implementation = source("client/core/serviceEngine/MacServiceInstaller.mm")
        engine = source("client/core/serviceEngine/AvpnEngineQml.cpp")

        self.assertIn("[[NSAppleScript alloc] initWithSource:src]", implementation)
        self.assertNotIn('QProcess::execute("osascript"', implementation)
        confirmation = engine.index("macInstallServiceConfirm(installReason")
        privileged_run = engine.index("macInstallServiceRun(&ierr)")
        self.assertLess(confirmation, privileged_run)


if __name__ == "__main__":
    unittest.main()
