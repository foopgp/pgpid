#!/bin/bash
#
# SPDX-FileCopyrightText: 2021-2025 Jean-Jacques Brucker (u4=sRyUhEbNU5OwyLEjfSwaXAe_42.17-002.76) <jjbrucker@foopgp.org>
#
# SPDX-License-Identifier: GPL-3.0-only
#


if [ "$1" ] && (("$1" > 0 )) ; then
	max=$1
else
	echo "Usage: $0 MAX_NUM_IMAGES" >&2
	exit 2
fi

k=0
for ((j=0;j<max;)) ; do
	if ((k++ >= 20*max - 1 )) ; then
		echo "reach maximum attempt: $k. Exiting." >&2
		exit 10
	fi
	num=$((RANDOM%400))$((RANDOM%1000))
	if curl -s -I "https://www.consilium.europa.eu/prado/images/$num.jpg" | grep "content-type: image/" ; then
		wget "https://www.consilium.europa.eu/prado/images/$num.jpg"
		((j++))
	else
		printf " %6d.jpg seems not to be an image. " $num >&2
		for ((i=O;i<j;i++)) do echo -n "." >&2 ; done ; echo >&2
	fi
done


