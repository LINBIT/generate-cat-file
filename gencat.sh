#!/bin/bash

# from catgen:
#  -o, --out
#        output cat file
#  -h, --hwid
#        hwid (example: PNP0F13)
#  -O, --OS
#        OS string (default: 7X64,8X64,10X64)
#  -A, --OSAttr
#        OSAttr string (default: 2:6.1,2:6.2,2:6.4)

function usage_and_exit() {
	echo Usage: "$0 -o <output-file> [-h <hardware-id>] [-O OS string] [-A OS attribute string] file1 [ file2 ... ]"
	exit 1
}

EXEC_DIR=$( dirname $0 )

OUTPUT_CAT_FILE=-
HARDWARE_ID=windrbd
OS_STRING=7X64,8X64,10X64
OS_ATTR=2:6.1,2:6.2,2:6.4

args=$( getopt o:h:O:A: $* )
if [ $? -ne 0 ]
then
	usage_and_exit
fi

set -- $args

for arg
do
	case "$arg"
	in
		-o)
			OUTPUT_CAT_FILE=$2
			shift
			shift
			;;
		-h)
			HARDWARE_ID=$2
			shift
			shift
			;;
		-O)
			OS_STRING=$2
			shift
			shift
			;;
		-A)
			OS_ATTR=$2
			shift
			shift
			;;
		--)
			shift
			break
			;;
	esac
done

if [ $# -eq 0 ]
then
	usage_and_exit
fi

i=0
for f in $*
do
	if [ ! -f $f ]
	then
		echo "$f: not a regular file"
		exit 1
	fi

	if $EXEC_DIR/strip-pe-image $f > /dev/null 2>/dev/null
	then
		images[$i]=$( basename $f ):$( $EXEC_DIR/strip-pe-image $f | sha1sum | cut -d' ' -f 1 ):PE
	else
		images[$i]=$( basename $f ):$( cat $f | sha1sum | cut -d' ' -f 1 )
	fi
	i=$[ $i+1 ]
done

$EXEC_DIR/generate-cat-file -A $OS_ATTR -O $OS_STRING -h $HARDWARE_ID ${images[*]}
