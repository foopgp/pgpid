#!/bin/bash

set -e

source "$(dirname "$0")/../pgpid-gen" --version

declare -a a=([0]="tableau" [1]="anormal" [2]="où tout" [3]="se suit" [12]="très anormal" [13]=$'form\ffeed...' [15]=$'back\bspace...' [21]="avec\\t des tab\\r" [22]=$'avec\t des tab\r' [42]=$'ça\ndevient\\\nsa/crément"\nle b\'del')

diff -us <(sed -n '/^{$/,${p;/}/q}' "$0") <(pgpi_json_from_var a)

exit $?
{
	"0": "tableau",
	"1": "anormal",
	"2": "où tout",
	"3": "se suit",
	"12": "très anormal",
	"13": "form\ffeed...",
	"15": "back\bspace...",
	"21": "avec\\t des tab\\r",
	"22": "avec\t des tab\r",
	"42": "ça\ndevient\\\nsa\/crément\"\nle b'del"
}
