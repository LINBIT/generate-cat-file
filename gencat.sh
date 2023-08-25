#!/bin/bash

# from catgen:
#  -o, --out
#        output cat file
#  -d, --drv-path
#        dir containing files
#  -i, --inf-file
#        parse inf file
#  -h, --hwid
#        hwid (example: PNP0F13)
#  -O, --OS
#        OS string (default: 7X64,8X64,10X64)
#  -A, --OSAttr
#        OSAttr string (default: 2:6.1,2:6.2,2:6.4)

i=0
for f in $*
do
	if ./strip-pe-image $f > /dev/null 2>/dev/null
	then
		images[$i]=$( basename $f ):$( ./strip-pe-image $f | sha1sum | cut -d' ' -f 1 ):PE
	else
		images[$i]=$( basename $f ):$( cat $f | sha1sum | cut -d' ' -f 1 )
	fi
	i=$[ $i+1 ]
done

echo ${images[*]}
