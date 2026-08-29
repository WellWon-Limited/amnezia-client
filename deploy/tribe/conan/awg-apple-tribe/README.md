# AWG Apple recipe migration

The former `conanfile.py` in this directory pinned the external Tribe fork at
AWG 3.0.1 and included an unsafe unknown-key parser override. It is
intentionally retired.

Apple release builds now use the single reproducible recipe at
`recipes/awg-apple/conanfile.py` (`awg-apple/3.1.4-tribe.3`). That recipe starts
from the immutable upstream v3.1.4 archive and applies the checksum-pinned local
Tribe DNS-forwarding/warmup/rebind patch. The top-level `conanfile.py` is the
only production consumer and requires that exact package version.

Do not restore or export the old fork recipe. Export/build the repository recipe
through the normal top-level Conan graph so `metadata/engine-lock.json` and the
artifact gates are enforced.
