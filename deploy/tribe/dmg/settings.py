# dmgbuild-настройки DMG Tribe VPN (вызов из make-macos-dist.sh, шаг 8).
# Координаты согласованы с фоном background.html/background.tiff — менять парой.
# Запуск: python3 -m dmgbuild -s settings.py -D app="<путь к Tribe VPN.app>" "Tribe VPN" out.dmg
import os.path

app = defines.get("app", "Tribe VPN.app")  # noqa: F821
app_name = os.path.basename(app)
# dmgbuild exec-ит settings без __file__ — путь к dmg-каталогу фиксируем от чекаута
here = defines.get("dmgdir", os.path.expanduser("~/amnezia-client/deploy/tribe/dmg"))  # noqa: F821

format = "UDZO"
size = None
files = [(app, app_name)]
symlinks = {"Applications": "/Applications"}

# иконка тома — бренд-иконка приложения
icon = os.path.join(here, "..", "..", "..", "client", "images", "app.icns")

background = os.path.join(here, "background.tiff")
window_rect = ((200, 120), (660, 400))
default_view = "icon-view"
show_status_bar = False
show_tab_view = False
show_toolbar = False
show_pathbar = False
show_sidebar = False

icon_size = 112
text_size = 12
icon_locations = {
    app_name: (170, 263),
    "Applications": (490, 263),
}
