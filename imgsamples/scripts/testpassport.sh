#!/bin/bash

cd $(dirname "$0")/..

for i in *.jpg *.JPG *.png ; do
	echo $i
	../bin/pgpid-gen $i < <( echo 1 ; sleep 5 ; killall pgpid-gen )
done
