# tribe-xray-geo (Tribe recipe)

One pinned, cut `geoip.dat` + `geosite.dat` pair for every Tribe Xray runner, so upstream
provider profiles route the same way on every platform and a missing file can never make the core
fall back to some other copy.

## Source and content (1.0.0)

| | geosite.dat | geoip.dat |
|---|---|---|
| Source | v2fly/domain-list-community `20260827152101` `dlc.dat` | v2fly/geoip `202608050239` `geoip.dat` |
| Source sha256 | `ba1adf51d4d724abbc157c53234a02bda00c94cdb8211709682e51a6855520b7` (2 283 258 B) | `c67bd077eb102cec74fab759b73d17f99275f56af10a87c14d9fd983508f5ce1` (23 080 744 B) |
| Tags kept | `private`, `category-ru`, `tiktok`, `speedtest`, `youtube` | `private`, `ru` |
| Cut sha256 | `c0afbbc3b8c307e3fe5700ea941ba258319508f545cfa0e6b75a154520622162` (31 940 B) | `c13c6463b5203768a94693d176d97f3e9b3fff93ecd288b6c215908baec0faee` (346 427 B) |

The source releases are the ones `../amnezia-libxray` embeds in the Android AAR (full files), so
`category-ru` is the same list everywhere. The desktop service's Loyalsoldier files
(`../v2ray-rules-dat`) are a different `category-ru` and are to be replaced by this pair.

`tool/` cuts with the Xray core's own protobuf types (`common/geodata` of amnezia-xray-core
v1.261101.0): entries sorted by tag, deterministic encoding, every entry byte-identical to the
source entry, a missing tag is an error. `build()` then runs `tool/geo_test.go` against the output
through the core's own asset loader and matchers (every tag loads; `yandex.ru`, `www.gosuslugi.ru`
in `category-ru`; `www.youtube.com`, `www.tiktok.com`, `www.speedtest.net`, `localhost` in their
tags; `10.1.2.3`, `192.168.1.1`, `fd00::1` in `geoip:private`; `77.88.8.8` in `geoip:ru`;
`8.8.8.8` in neither; `geosite:cn`, `geoip:cn` absent) and compares both files with the locks in
`conanfile.py`. Package: `geo/geosite.dat`, `geo/geoip.dat`, `geo/SHA256SUMS`, `geo/MANIFEST.json`.

Changing the tag set or the source release changes the backend contract (`required_geo` of the
upstream normalizer: a profile needing any other tag is withheld) and the lock hashes: bump the
version and update both locks deliberately.

## Install path contract

CMake variables (`find_package(tribe-xray-geo)`, target `tribe::xray-geo`):
`TRIBE_XRAY_GEO_DIR`, `TRIBE_XRAY_GEOSITE_DAT_PATH`, `TRIBE_XRAY_GEOIP_DAT_PATH`,
`TRIBE_XRAY_GEO_SHA256SUMS_PATH`, `TRIBE_XRAY_GEOSITE_SHA256`, `TRIBE_XRAY_GEOIP_SHA256`,
`TRIBE_XRAY_GEOSITE_TAGS`, `TRIBE_XRAY_GEOIP_TAGS`, `TRIBE_XRAY_GEO_VERSION`.

- **iOS packet tunnel (appex).** Both files are plain resources at the top of the appex bundle
  (`<appex>/geosite.dat`, `<appex>/geoip.dat`, file names unchanged). The extension passes
  `Bundle.main.resourcePath` (the appex's own resource directory) as `datDir` to
  `LibXrayRunXray(datDir, configPath, maxMemory)`. Never pass NULL/empty: libxray sets
  `xray.location.asset` to the given value even when empty, and the core then looks in the
  current directory (`common/platform/others.go`), so every `geosite:`/`geoip:` rule fails.
  The bundle is signed and read-only, which is what the core needs.
- **Desktop service (macOS, Windows, Linux).** Both files sit in the same directory as
  `Tribe-service` (the daemon's executable directory), same file names:
  `service/server/CMakeLists.txt` copies `TRIBE_XRAY_GEO*_PATH` next to the service (and installs
  them on Windows/Linux), on macOS also `tribe-xray-geo.sha256` (build tree only). The daemon
  leaves `xray.location.asset` unset, so the core reads them from the executable directory; on
  macOS/Linux a missing file would fall back to `/usr/local/share/xray/`, `/usr/share/xray/`,
  `/opt/share/xray/` (a Homebrew xray could change routing), so `Xray::startXray` refuses a config
  that needs a file missing next to the binary (`service/server/xrayassets.h`).
- **macOS packaging.** `deploy/tribe/make-svc-payload.sh` (step 4 of `make-macos-dist.sh`)
  refuses a pair that does not match `tribe-xray-geo.sha256`, packs `geoip.dat`, `geosite.dat`
  and `geo.sha256` into `tribe-svc.tar.gz`, adds both files to the service marker (`VERSION` /
  `tribe-svc.version`) and writes the app resource `tribe-svc-geo.sha256`.
  `tribe-svc-install.sh` verifies the pair before touching the running service and installs it
  with tmp + `mv`. The app checks the installed pair with
  `MacServiceInstaller::macUpstreamGeoPresent()` (hashes from `tribe-svc-geo.sha256`).

## Build

```sh
conan export recipes/go --version 1.27.4
conan create recipes/tribe-xray-geo        # data only: package id independent of settings
```
