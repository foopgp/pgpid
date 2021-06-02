#!/bin/bash
#
# Copyright © 2021 by Friends Of OpenPGP organization.
#          Confidential - All Right Reserved
#
# Extract MRZ data and photo from ID documents (eg: International Passeports)
# to generate OpenPGP certificates and keys to be imported for multiple applications (mail, chat, vote, etc.).
# May also move or copy 3 importante keys (SC, E and A) to OpenPGP Security hardware (nitrokeys, yubikeys, etc.)
#

PGPI_NAME="$(basename $(readlink -f "$BASH_SOURCE") )"
PGPI_VERSION="0.0.1"

### Default option values ###

if [[ "$BASH_SOURCE" == "$0" ]] ; then
	# run as a script
	set -e
	_exit="exit"
	LOGEXITPRIO=crit
	LOGLEVEL=5
else
	# run as a library (source $0)
	_exit="return"
	LOGEXITPRIO=emerg
	LOGLEVEL=6
fi

OUTPATH="$PWD"
OUTPUTJSON=false
LOGGERSYSLOG="--no-act"


### Constants (read only) ###

declare -r \
FACE_MARGIN_WIDTH="25/100" \
FACE_MARGIN_HEIGHT="50/100" \
TESSDATADIR="$(dirname "$0")/data/" \
GEOLIST_CENTROID="$(dirname "$0")/data/geolist_centroid.txt" \

declare -A -r loglevels=(
[emerg]=0
[alert]=1
[crit]=2
[error]=3 # deprecated synonym for err
[err]=3
[warning]=4
[notice]=5
[info]=6
[debug]=7)


### Handling options ###

usage="Usage: $BASH_SOURCE [OPTIONS...] IMAGES...
"
helpmsg="$usage
If $PGPI_NAME succeed, it will create a subdirectories containing all generated files.
Options:
    -o, --output-path PATH   emplacement for generated subdirs and files (current: $OUTPATH )
    -L, --log-exit PRIORITY  log exit priority: emerg|alert|crit|err|warning|... (current: $LOGEXITPRIO )
    -v, --verbose            increase log verbosity: ...<notice[5]<info[6]<debug[7]  (current: $LOGLEVEL)
    -q, --quiet              decrease log verbosity: ...<err[3]<warning[4]<notice[5]<...  (current: $LOGLEVEL)
    -s, --syslog             write also logs to the system logs
    -j, --json               don't generate OpenPGP stuff, but only output json (like 'mrz' from PassportEye)
    -h, --help               show this help and exit
    -V, --version            show version and exit
"

for ((i=0;$#;)) ; do
case "$1" in
    -o|--output*) shift ; OUTPATH="$1" ; ( cd "$OUTPATH" && touch . ) ;;
#    -l|--log-l*) shift ; LOGLEVEL="$1" ; [[ "$LOGLEVEL" == [0-9] ]] || { echo -e "Error: log-level out of range [0-7]" >&2 ; $_exit 2 ; } ;;
    -L|--log-e*) shift ; LOGEXITPRIO="$1" ; grep -q "\<$LOGEXITPRIO\>" <<<${!loglevels[@]} || { echo -e "Error: log-exit \"$LOGEXITPRIO\" is none of: ${!loglevels[@]}" >&2 ; $_exit 2 ; } ;;
    -v|--verb*) ((LOGLEVEL++)) ;;
    -q|--quiet) ((LOGLEVEL--)) ;;
    -s|--syslog) unset LOGGERSYSLOG ;;
    -j|--json) OUTPUTJSON=true ;;
    -h|--h*) echo "$helpmsg" ; $_exit ;;
    -V|--vers*) echo "$PGPI_NAME $PGPI_VERSION" ; $_exit ;;
    --) shift ; break ;;
    -*) echo -e "Error: Unrecognized option $1\n$helpmsg" >&2 ; $_exit 2 ;;
    *) break ;;
esac
shift
done


### functions ###

_log() {
# Argument $1: warning|error|err|info|debug|notice|alert|crit|emerg
# Arguments $2..n: message to format and write on stderr and eventually syslog
# If there is no argument $2..., read message from stdin
# Exit if $1 is greater than $LOGEXITPRIO.
	local priority=$1
	shift
	if ((loglevels[$priority] > $LOGLEVEL)) ; then
		[[ "$1" ]] || cat >/dev/null
	else
		logger -p "$priority" --stderr $LOGGERSYSLOG --id=$$ -t "$PGPI_NAME" -- "$@"
	fi
	((loglevels[$priority] > loglevels[$LOGEXITPRIO] )) || exit $((8+loglevels[$priority]))
}

mrz_checkdigit() {
# Argument $1: [0-9A-Z<] +* string to check
# Arguments $2 (optionnal): expected result
# If there is no argument $2: stdout <- calculated check digit
# else return non-zero if $2 differs from calculated check digit.
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

mrz_analyse() {
	local ch mrz=("$@")
	local -A doc

	_log debug "mrz[0]= \"${mrz[0]}\""
	if [[ ${mrz[0]:0:1} != P ]] ; then
		_log debug "mrz[0]= \"${mrz[0]}\""
		_log warning "$FUNCNAME: unsupported. (not an ISO/IEC 7501-1 passport)"
		return 1
	fi
	_log debug "mrz[1]= \"${mrz[1]}\""
	if [[ ${#mrz[0]} != 44 ]] || [[ ${#mrz[1]} != 44 ]] ; then
		_log warning "$FUNCNAME: Invalid MRZ lenght ${#mrz[0]} ${#mrz[1]}"
		return 2
	fi

	doc=(
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
		doc[checked_$ch]=$(mrz_checkdigit "${doc[$ch]}")
		doc[valid_$ch]=$( [[ ${doc[checked_$ch]} == ${doc[check_$ch]} ]] && echo true || echo false )
		${doc[valid_$ch]} || _log warning "OBI WAN KENOBI ??? $ch checksum -> ${doc[check_$ch]}. Should be ${doc[checked_$ch]}."
	done

	doc[names]=$(echo $(echo "${doc[all_names]#*<<}" | tr '<' ' ') )
	doc[surname]=$(echo $(echo "${doc[all_names]%%<<*}" | tr '<' ' ') )
	declare -p doc | sed 's,^[^=]*=,,'
}

_gen_mrzudid4() {
	#WARNING: mrz data may be irrelevant to generate udid4. eg:
	#         * Surname or given names may be incomplete (cut bc exceed mrz size)
	#         * Surname or given names may differs from those given at birth (marriage, gender change, etc.)
	#         * Surname or given names transliteration may have change over time
	#         * Year of birtdate is not written with 4 digit (and people may live longer than 100 years)
	#         * Humans may have done error on birthdate, surname or given names.

	local c iso name tohash1 tohash2
	if ! tohash1=$(grep -o "[A-Z]\{1,32\}<<[A-Z]\{1,32\}<[A-Z]\{0,32\}<" <<<"${DOCUMENT[all_names]}" ) ; then
		_log err "$FUNCNAME: no complete surname and given names extracted from ${DOCUMENT[all_names]}"
		return 1
	fi
	_log debug "$FUNCNAME: names: $tohash1"
	if ! tohash2=$(date --date "$(($(date +"%y%m%d") < DOCUMENT[date_of_birth] ? 19 : 20))${DOCUMENT[date_of_birth]}" +"%Y-%m-%d" ) ; then
		_log err "$FUNCNAME: can't reformart birthdate ${DOCUMENT[date_of_birth]}"
		return 2
	fi
	_log debug "$FUNCNAME: birthdate: $tohash2"
	if ! read c iso name < <(grep "	${DOCUMENT[nationality]}	" data/geolist_centroid.txt) ; then
		_log err "$FUNCNAME: no \"${DOCUMENT[nationality]}\" in $GEOLIST_CENTROID"
		return 3
	fi
	_log debug "$FUNCNAME: $c $iso $name"
	echo "$(printf "$tohash1$tohash2" | md5sum | xxd -r -p | basenc --base64url | sed 's/==$//')$c"
}

pgpi_tojson() {
	local notstarted=true
	local -n aa=$1
	printf "{\n"
	for i in "${!aa[@]}"; do
		$notstarted || printf ",\n"
		notstarted=false
		#TODO: Prevent eventual '"' in ${DOCUMENT[$i]} (even if it means that DOCUMENT is invalid)
		#TODO: Maybe use and depend on "jq". cf. https://stackoverflow.com/questions/44792241/constructing-a-json-hash-from-a-bash-associative-array
		printf "  \"$i\": \"${aa[$i]//$'\n'/\\\\n}\""
	done
	printf "\n}\n"
}



_chooseinlist() {
# Argument 1: Prompt before the list
# Argument 2(optionnal): if argument 2 is a number>0, it indicates the number of item by line - defaut: 3.
# Arguments 2,3...n : items to choose
# Return the number of the choosen item, 0 if no items.

	local ret=0 nperline=3 n
	echo -n "$1"
	shift
	(($1>0)) && nperline=$1 && shift
	n=$#
	for ((i=0;$#;)) ; do
		if ((i%nperline)) ; then
			echo -en "\t\t"
		else
			echo -en "\n\t"
		fi
		echo -en "$((++i))) $1"
		shift
	done
	echo
	while ! ((ret)) || ((ret<1 || ret>n)) ; do
		read -p "Reply (1-$n) ? " ret
	done
	return $ret
}

# Do nothing else if sourced
[[ "$BASH_SOURCE" == "$0" ]] || $_exit


### Init ###

#_onexit() {
#	[[ -d "$TMPDIR" ]] && rm -rvf "$TMPDIR" | _log info
#}
#
#TMPDIR=$(mktemp -d -t "$PGPI_NAME".XXXXXX) || log crit "crit: Can not create a safe temporary directory."
#
#trap _onexit EXIT

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
	mx=$((sx*$FACE_MARGIN_WIDTH))
	my=$((sy*$FACE_MARGIN_HEIGHT))
	_log info "$f face -> position: +$px+$py  size: ${sx}x$sy  marges: +${mx}+$my"


	if ! mrz=($(gm convert -crop +0+$((py+sy+my)) "$f" - 2> >(_log notice) | tesseract --tessdata-dir "$TESSDATADIR" -l mrz - - 2> >(_log notice) | sed 's/[^0-9A-Z<]*//g' | grep -m1 -A2 "<<")) ; then
		_log err "$f: No machine-readable zone detected"
		continue
	fi

	unset DOCUMENT
	if ! declare -A DOCUMENT=$(mrz_analyse "${mrz[@]}") ; then
		_log err "$f: Invalid or unsupported machine-readable zone"
		continue
	fi

	DOCUMENT[filename]=$f
	DOCUMENT[face_scan_64url]=$(gm convert -crop $((sx+mx))x$((sy+my))+$((px-(mx/2)))+$((py-(my/2))) "$f" jpeg:- 2> >(_log warning) | basenc --base64url --wrap 0 )
	if ((${#DOCUMENT[face_scan_64url]} < 2048 )) ; then
		_log warning "$outdir/face.jpg: too small (${#DOCUMENT[face_scan_64url]} < 2048)"
		unset DOCUMENT[face_scan_64url]
	elif ((${#DOCUMENT[face_scan_64url]} > (1<<16) )) ; then
		_log warning "$outdir/face.jpg: too big (${#DOCUMENT[face_scan_64url]} > $((1<<16)))"
		unset DOCUMENT[face_scan_64url]
	fi
	if ! DOCUMENT[udid4_auto]=$(_gen_mrzudid4) ; then
		_log warning "can't generate an udid4 from mrz data"
		unset DOCUMENT[udid4_auto]
	fi

	if $OUTPUTJSON ; then
		pgpi_tojson DOCUMENT
		continue
	fi

	#for i in "${!DOCUMENT[@]}"; do printf "[$i] -> ${DOCUMENT[$i]}\n"; done | _log debug

	outdir="$OUTPATH/${mrz[0]//</_}"
	mkdir -p "$outdir"

	cp -bvf "$f" "$outdir/document.orig" 2> >(_log warning) | _log info
	pgpi_tojson DOCUMENT > "$outdir/document.json" 2> >(_log crit)
done

exit 0
