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
LOGLEVEL=5
LOGEXITPRIO=crit

declare -A loglevels=(
[emerg]=0
[alert]=1
[crit]=2
[error]=3
[err]=3
[warning]=4
[notice]=5
[info]=6
[debug]=7)


usage="Usage: $0 [OPTIONS...] IMAGES...
"
helpmsg="$usage
If $PROGNAME succeed, it will create a subdirectories containing all generated files.
Options:
    -o, --output-path PATH   emplacement for generated subdirs and files (default: $OUTPATH )
    -l, --log-level LEVEL    log verbosity. 7 means max verbosity (...|warning|notice|info|debug) (default: $LOGLEVEL )
    -L, --log-exit PRIORITY  log exit priority: emerg|alert|crit|err|warning|... (default: $LOGEXITPRIO )
    -h, --help               show this help and exit
    -V, --version            show version and exit
"

_log() {
	local priority=$1
	shift
	if ((loglevels[$priority] > $LOGLEVEL)) ; then
		[[ "$1" ]] || cat >/dev/null
	else
		logger -p "$priority" --stderr --no-act --id=$$ -t "$PROGNAME" -- "$@"
	fi
	((loglevels[$priority] > loglevels[$LOGEXITPRIO] )) || exit $((8+loglevels[$priority]))
}

for ((i=0;$#;)) ; do
case "$1" in
    -o|--output*) shift ; OUTPATH="$1" ; ( cd "$OUTPATH" && touch . ) ;;
    -l|--log-l*) shift ; LOGLEVEL="$1" ; [[ "$LOGLEVEL" == [0-9] ]] || { echo -e "Error: log-level out of range [0-7]" ; exit 2 ; } ;;
    -L|--log-e*) shift ; LOGEXITPRIO="$1" ; grep -q "\<$LOGEXITPRIO\>" <<<${!loglevels[@]} || { echo -e "Error: log-exit is none of ${!loglevels[@]}" ; exit 2 ; } ;;
    -h|--h*) echo "$helpmsg" ; exit ;;
    -V|--vers*) echo "$0 $VERSION" ; exit ;;
    --) shift ; break ;;
    -*) echo -e "Error: Unrecognized option $1\n$helpmsg" >&2 ; exit 2 ;;
    *) break ;;
esac
shift
done

_checkdigit() {
	local char sum=0 weight=(7 3 1)
	for ((i=0;i<${#1};i++)) ; do
		char=${1:$i:1}
		case $char in
			[0-9]) ((sum+=char*${weight[$((i%3))]})) ;;
			[A-Z]) ((sum+=($(printf "%d" "'$char'")-55)*${weight[$((i%3))]})) ;;
		esac
	done

	if ! [[ "$2" ]] ; then
		echo $((sum%10))
	else
		(( sum%10 == $2 ))
		return $?
	fi
}

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
	echo
	f="$1"
	shift


	facep=$(facedetect --best -- "$f" 2> >(_log notice) || true )
	if ! [[ "$facep" ]] ; then
		_log err "Error: No face detected in $f" >&2
		continue
	fi
	read px py sx sy etc <<<"$facep"
	_log info "$f face -> position: +$px+$py  size: ${sx}x$sy"


	if ! mrz=($(gm convert -crop +0+$((py+sy+sy*FACE_MARGE_HEIGHT)) "$f" - 2> >(_log notice) | tesseract --tessdata-dir tessdata/ -l mrz - - 2> >(_log notice) | sed 's/[^0-9A-Z<]*//g' | grep -m1 -A2 "<<")) ; then
		_log err "Error: No machine-readable zone detected in $f" >&2
		continue
	fi
	if [[ ${mrz[0]:0:1} != P ]] ; then
		_log debug "mrz[0]= \"${mrz[0]}\""
		_log warning "Warning: $f: unsupported. (not an ISO/IEC 7501-1 passport)" >&2
		continue
	fi

	declare -A passport=(
		[type]=${mrz[0]:0:2}
		[country]=${mrz[0]:2:3}
		[all_names]=${mrz[0]:5}
		[number]=${mrz[1]:0:9}
		[check_number]=${mrz[1]:9:1}
		[nationality]=${mrz[1]:10:3}
		[date_of_birth]=${mrz[1]:13:6}
		[check_date_of_birth]=${mrz[1]:19:1}
		[sex]=${mrz[1]:20:1}
		[expiration_date]=${mrz[1]:21:6}
		[check_expiration_date]=${mrz[1]:27:1}
		[personal_number]=${mrz[1]:28:14}
		[check_personal_number]=${mrz[1]:42:1}
		[check_composite]=${mrz[1]:43:1}
		[checked_composite]=$(_checkdigit "${mrz[1]:0:10}${mrz[1]:13:7}${mrz[1]:21:20}")
		[valid_composite]=$(_checkdigit "${mrz[1]:0:10}${mrz[1]:13:7}${mrz[1]:21:20}" "${mrz[1]:43:1}" && echo true || echo false )
	)

	passport[valid_date_of_birth]=$(_checkdigit "${passport[date_of_birth]}" "${passport[check_date_of_birth]}" && echo true || echo false )
	passport[valid_expiration_date]=$(_checkdigit "${passport[expiration_date]}" "${passport[check_expiration_date]}" && echo true || echo false )
	passport[valid_personal_number]=$(_checkdigit "${passport[personal_number]}" "${passport[check_personal_number]}" && echo true || echo false )

	for i in "${!passport[@]}";do printf "[$i] -> ${passport[$i]}\n"; done | _log debug
	_log info "$OUTPATH/${mrz[0]//</_}"

	# gm convert -crop 390x470+27+235 FPassport0001.png face.jpg
done

exit 0
