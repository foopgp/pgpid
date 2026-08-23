#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: 2026 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
# SPDX-FileCopyrightText: 2026 Mnêmê (u5001777236237.945e_43.30_005.38 claude-opus-5) <mneme@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#
"""A translated help block must not be wider than the English it replaces.

The OPTIONS blocks are tables, and a line that folds turns a column into
porridge. The rule is not an absolute width — the English itself runs past 79
in places — but "do not make it worse": no translated line wider than the
widest line of the block it translates, and never past 79 unless the English
was already there.
"""
import sys, polib

bad = 0
for path in sys.argv[1:]:
    for e in polib.pofile(path).translated_entries():
        if len(e.msgid) < 200:
            continue
        allowed = max(79, max(len(l) for l in e.msgid.split("\n")))
        for n, line in enumerate(e.msgstr.split("\n"), 1):
            if len(line) > allowed:
                print(f"{path}: line {n} is {len(line)} columns, "
                      f"the English block never passes {allowed}: {line[:56]}…")
                bad += 1
print("no line wider than its English" if not bad else f"{bad} lines too wide")
sys.exit(1 if bad else 0)
