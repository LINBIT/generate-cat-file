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

OUTPUT_CAT_FILE=-
HARDWARE_ID=windrbd
OS_STRING=7X64,8X64,10X64
OS_ATTR=2:6.1,2:6.2,2:6.4

args=$( getopt o:h:O:A: $* )
if [ $? -ne 0 ]
then
echo $#
	echo Usage: "$0 -o <output-file> [-h <hardware-id>] [-O OS string] [-A OS attribute string] file1 [ file2 ... ]"
	exit 1
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
		--)
			shift
			break
			;;
	esac
done

echo "$# arguments remaining"
echo " -o is $OUTPUT_CAT_FILE"

i=0
for f in $*
do
	echo File is $f ...
	if ./strip-pe-image $f > /dev/null 2>/dev/null
	then
		images[$i]=$( basename $f ):$( ./strip-pe-image $f | sha1sum | cut -d' ' -f 1 ):PE
	else
		images[$i]=$( basename $f ):$( cat $f | sha1sum | cut -d' ' -f 1 )
	fi
	i=$[ $i+1 ]
done

echo ${images[*]}
