#!/bin/bash
#
# Copyright © 2021 by Friends Of OpenPGP organization.
#          Confidential - All Right Reserved
#
# Extract MRZ data and photo from ID documents (eg: International Passeports)
# to generate OpenPGP certificates and keys to be imported for multiple applications (mail, chat, vote, etc.).
# May also move or copy 3 importante keys (SC, E and A) to OpenPGP Security hardware (nitrokeys, yubikeys, etc.)
#

set -e

PROGNAME="$(basename "$0")"
VERSION="0.0.1"

### Default option values: ###
FACE_MARGE_WIDTH="25/100"
FACE_MARGE_HEIGHT="50/100"
OUTPATH="$PWD"


usage="Usage: $0 [OPTIONS...] IMAGES...
"
helpmsg="$usage
If $PROGNAME succeed, it will create a subdirectories containing all generated files.
Options:
    -o, --output-path PATH   emplacement for generated subdirs and files (default: $OUTPATH )
    -h, --help               show this help and exit
    -V, --version            show version and exit
"

_step() {
	echo "$(date +"%T"): $PROGNAME: $@ ..."
}

for ((i=0;$#;)) ; do
case "$1" in
    -o|--output*) shift ; OUTPATH="$1" ; ( cd "$OUTPATH" && touch . ) ;;
    -h|--h*) echo "$helpmsg" ; exit ;;
    -V|--vers*) echo "$0 $VERSION" ; exit ;;
    --) shift ; break ;;
    -*) echo -e "Error: Unrecognized option $1\n$helpmsg" >&2 ; exit 2 ;;
    *) break ;;
esac
shift
done

_onexit() {
	[[ -d "$TMPDIR" ]] && rm -rvf "$TMPDIR"
}

######################## tmpdir ##############################

if ! TMPDIR=$(mktemp -d -t "$PROGNAME".XXXXXX) ; then
	echo "Error: Can not create a safe temporary directory." # | logger -s -p user.notice -t "$PROGNAME" --id=$$
	exit 1
fi

trap _onexit EXIT


[[ "$1" ]] || { echo -e "$usage" >&2 ; exit 1 ; }
#scanimage -l 2 -t 2 -x 120 -y 170 --mode Color --resolution 200 --format=tiff > tmpimg.tiff

while [[ "$1" ]] ; do
	f="$1"
	shift
	facep=$(facedetect --best "$f")
	if ! [[ "$facep" ]] ; then
		_step "Warning:" "No face detected, skipping $f" >&2
		continue
	fi
	read px py sx sy etc <<<"$facep"
	_step "$f face -> position: +$px+$py  size: ${sx}x$sy"

#	set -x

	if ! mrz=($(gm convert -crop +0+$((py+sy+sy*FACE_MARGE_HEIGHT)) "$f" - | tesseract --tessdata-dir tessdata/ -l mrz - - | sed 's/[^0-9A-Z<]*//g' | grep -m1 -A2 "<<")) ; then
		_step "Warning:" "No machine-readable zone detected, skipping $f" >&2
		continue
	fi
	if [[ ${mrz[0]:0:1} != P ]] ; then
		_step "Warning:" "$PROGNAME yet only support passport (conforming ISO/IEC 7501-1)" >&2
		continue
	fi

	declare -A passport=(
		[type]=${mrz[0]:0:2}
		[country]=${mrz[0]:2:3}
		[name]=${mrz[0]:5}
		[number]=${mrz[1]:0:9}
	)

	echo "$OUTPATH/${mrz[0]//</_}"
	for i in "${!passport[@]}";do printf "[$i] -> ${passport[$i]}\n";done

	# gm convert -crop 390x470+27+235 FPassport0001.png face.jpg
done

exit 0
