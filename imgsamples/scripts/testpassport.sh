#!/bin/bash
#
# SPDX-FileCopyrightText: 2021-2025 Jean-Jacques Brucker (u4sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#

cd $(dirname "$0")/..

for i in *.jpg *.JPG *.png ; do
	echo $i
	../bin/pgpid-gen $i < <( echo 1 ; sleep 5 ; killall pgpid-gen )
done
