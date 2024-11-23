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
	echo Usage: "$0 -o <output-file> [-h <hardware-ids>] [-O OS string] [-A OS attribute string] file1 [ file2 ... ]"
	exit 1
}

EXEC_DIR=$( dirname $0 )

OUTPUT_CAT_FILE=-
HARDWARE_IDS=windrbd
OS_STRING=7X64,8X64,10X64
OS_ATTR=2:6.1,2:6.2,2:6.4
DRY_RUN=0

args=$( getopt do:h:O:A: $* )
if [ $? -ne 0 ]
then
	usage_and_exit
fi

set -- $args

for arg
do
	case "$arg"
	in
		-d)
			DRY_RUN=1
			shift
			;;
		-o)
			OUTPUT_CAT_FILE=$2
			shift
			shift
			;;
		-h)
			HARDWARE_IDS=$2
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
		images[$i]=$( basename $f ):$( $EXEC_DIR/strip-pe-image $f | sha1sum | cut -d' ' -f 1 | tr [:lower:] [:upper:] ):PE
	else
		images[$i]=$( basename $f ):$( cat $f | sha1sum | cut -d' ' -f 1 | tr [:lower:] [:upper:] )
	fi
	i=$[ $i+1 ]
done

IFS=$'\n' sorted_images=($(sort -t: -k2 <<<"${images[*]}"))
unset IFS

if [ $DRY_RUN -eq 1 ]
then
	echo $EXEC_DIR/generate-cat-file -A $OS_ATTR -O $OS_STRING -h $HARDWARE_IDS ${sorted_images[*]}
	exit 0
fi

if [ $OUTPUT_CAT_FILE == '-' ]
then
	$EXEC_DIR/generate-cat-file -A $OS_ATTR -O $OS_STRING -h $HARDWARE_IDS ${sorted_images[*]}
else
	$EXEC_DIR/generate-cat-file -A $OS_ATTR -O $OS_STRING -h $HARDWARE_IDS ${sorted_images[*]} > $OUTPUT_CAT_FILE
fi
