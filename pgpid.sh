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


### Default option values ###

FACE_MARGE_WIDTH="25/100"
FACE_MARGE_HEIGHT="50/100"
OUTPATH="$PWD"
LOGLEVEL=5
LOGEXITPRIO=crit
OUTPUTJSON=false
LOGGERSYSLOG="--no-act"


### Constants ###

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


### Handling options ###

usage="Usage: $0 [OPTIONS...] IMAGES...
"
helpmsg="$usage
If $PROGNAME succeed, it will create a subdirectories containing all generated files.
Options:
    -o, --output-path PATH   emplacement for generated subdirs and files (current: $OUTPATH )
    -L, --log-exit PRIORITY  log exit priority: emerg|alert|crit|err|warning|... (current: $LOGEXITPRIO )
    -v, --verbose            increase log verbosity: ...<notice<info<debug  (default: [notice]=5)
    -q, --quiet              decrease log verbosity: ...<err<warning<notice<...  (default: [notice]=5)
    -s, --syslog             write also logs to the system logs
    -j, --json               don't generate OpenPGP stuff, but only output json (like 'mrz' from PassportEye)
    -h, --help               show this help and exit
    -V, --version            show version and exit
"

for ((i=0;$#;)) ; do
case "$1" in
    -o|--output*) shift ; OUTPATH="$1" ; ( cd "$OUTPATH" && touch . ) ;;
#    -l|--log-l*) shift ; LOGLEVEL="$1" ; [[ "$LOGLEVEL" == [0-9] ]] || { echo -e "Error: log-level out of range [0-7]" ; exit 2 ; } ;;
    -L|--log-e*) shift ; LOGEXITPRIO="$1" ; grep -q "\<$LOGEXITPRIO\>" <<<${!loglevels[@]} || { echo -e "Error: log-exit \"$LOGEXITPRIO\" is none of: ${!loglevels[@]}" ; exit 2 ; } ;;
    -v|--verb*) ((LOGLEVEL++)) ;;
    -q|--quiet) ((LOGLEVEL--)) ;;
    -s|--syslog) unset LOGGERSYSLOG ;;
    -j|--json) OUTPUTJSON=true ;;
    -h|--h*) echo "$helpmsg" ; exit ;;
    -V|--vers*) echo "$0 $VERSION" ; exit ;;
    --) shift ; break ;;
    -*) echo -e "Error: Unrecognized option $1\n$helpmsg" >&2 ; exit 2 ;;
    *) break ;;
esac
shift
done


### functions ###

_log() {
	local priority=$1
	shift
	if ((loglevels[$priority] > $LOGLEVEL)) ; then
		[[ "$1" ]] || cat >/dev/null
	else
		logger -p "$priority" --stderr $LOGGERSYSLOG --id=$$ -t "$PROGNAME" -- "$@"
	fi
	((loglevels[$priority] > loglevels[$LOGEXITPRIO] )) || exit $((8+loglevels[$priority]))
}

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
		[[ "$2" == $((sum%10)) ]]
		return $?
	fi
}

_onexit() {
	[[ -d "$TMPDIR" ]] && rm -rvf "$TMPDIR" | _log info
}

_outputjson() {
	local notstarted=true
	printf "{\n"
	for i in "${!passport[@]}"; do
		$notstarted || printf ",\n"
		notstarted=false
		#TODO: Prevent eventual '"' in ${passport[$i]} (even if it means that passport is invalid)
		printf "  \"$i\": \"${passport[$i]//$'\n'/}\""
	done
	printf "\n}\n"
}


### Init ###

TMPDIR=$(mktemp -d -t "$PROGNAME".XXXXXX) || log crit "crit: Can not create a safe temporary directory."

trap _onexit EXIT


[[ "$1" ]] || { echo -e "$usage" >&2 ; exit 1 ; }
#scanimage -l 2 -t 2 -x 120 -y 170 --mode Color --resolution 200 --format=tiff > tmpimg.tiff


### Run ###

while [[ "$1" ]] ; do
	f="$1"
	shift


	facep=$(facedetect --best -- "$f" 2> >(_log notice) || true )
	if ! [[ "$facep" ]] ; then
		_log err "Error: No face detected in $f"
		continue
	fi
	read px py sx sy etc <<<"$facep"
	mx=$((sx*$FACE_MARGE_WIDTH))
	my=$((sy*$FACE_MARGE_HEIGHT))
	_log info "$f face -> position: +$px+$py  size: ${sx}x$sy  marges: +${mx}+$my"


	if ! mrz=($(gm convert -crop +0+$((py+sy+my)) "$f" - 2> >(_log notice) | tesseract --tessdata-dir tessdata/ -l mrz - - 2> >(_log notice) | sed 's/[^0-9A-Z<]*//g' | grep -m1 -A2 "<<")) ; then
		_log err "$f: No machine-readable zone detected"
		continue
	fi
	_log debug "mrz[0]= \"${mrz[0]}\""
	if [[ ${mrz[0]:0:1} != P ]] ; then
		_log debug "mrz[0]= \"${mrz[0]}\""
		_log err "$f: unsupported. (not an ISO/IEC 7501-1 passport)"
		continue
	fi
	_log debug "mrz[1]= \"${mrz[1]}\""
	if [[ ${#mrz[0]} != 44 ]] || [[ ${#mrz[1]} != 44 ]] ; then
		_log err "$f: Invalid MRZ lenght ${#mrz[0]} ${#mrz[1]}"
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
		[composite]="${mrz[1]:0:10}${mrz[1]:13:7}${mrz[1]:21:20}"
		[check_composite]=${mrz[1]:43:1}
	)

	for ch in number date_of_birth expiration_date personal_number composite ; do
		passport[checked_$ch]=$(_checkdigit "${passport[$ch]}")
		passport[valid_$ch]=$( [[ ${passport[checked_$ch]} == ${passport[check_$ch]} ]] && echo true || echo false )
		${passport[valid_$ch]} || _log warning "OBI WAN KENOBI ??? $ch checksum -> ${passport[check_$ch]}. Should be ${passport[checked_$ch]}."
	done

	passport[names]=$(echo $(echo "${passport[all_names]#*<<}" | tr '<' ' ') )
	passport[surname]=$(echo $(echo "${passport[all_names]%%<<*}" | tr '<' ' ') )
	passport[filename]=$f
	passport[face_scan_64url]=$(gm convert -crop $((sx+mx))x$((sy+my))+$((px-(mx/2)))+$((py-(my/2))) "$f" - 2> >(_log warning) | basenc --base64url)
	if ((${#passport[face_scan_64url]} < 2048 )) ; then
		_log warning "$outdir/face.jpg: too small (${#passport[face_scan_64url]} < 2048)"
		unset passport[face_scan_64url]
	elif ((${#passport[face_scan_64url]} > (1<<16) )) ; then
		_log warning "$outdir/face.jpg: too big (${#passport[face_scan_64url]} > $((1<<16)))"
		unset passport[face_scan_64url]
	fi

	if $OUTPUTJSON ; then
		_outputjson
		continue
	fi

	#for i in "${!passport[@]}"; do printf "[$i] -> ${passport[$i]}\n"; done | _log debug

	outdir="$OUTPATH/${mrz[0]//</_}"
	mkdir -p "$outdir"

	cp -bvf "$f" "$outdir/document.orig" 2> >(_log warning) | _log info
	_outputjson > "$outdir/passport.json" 2> >(_log crit)

done

exit 0
