GUI release builds use Qt 6.8.4
===============================

Release builds of `qbit-qt` now use Qt 6.8.4 instead of Qt 6.7.3. This fixes
a crash on macOS when quitting the GUI after an accessibility client, such as
VoiceOver or a UI automation tool, had inspected its windows. The crash was a
use-after-free in Qt's macOS accessibility cache (QTBUG-134784). Qt 6.8.4
includes the upstream fix, and the build also applies a later Qt fix for a
related use-after-free (QTBUG-149612).

Saved GUI settings and window layouts are read and written as before.
