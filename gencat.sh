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
#
#
# Followed is a lists of OS string and OS attribute values, taken from various .cat files of Intel drivers for chipset and ethernet in November 2024
# Also there are no values for Win NT 4.0, 98 and ME - their attributes slightly different and may require additional data
#
# OS string
#   x32 (x86, IA-32)
#     2000,XPX86,Server2003X86,VistaX86,Server2008X86,7X86,8X86,_v63
#     _v100,_v100_RS1,_v100_RS3,_v100_RS4,_v100_19H1
# 
#   x64 (AMD64, x86-x64)
#     XPX64,Server2003X64,VistaX64,Server2008X64,7X64,Server2008R2X64,8X64,Server2012X64,_v63_X64,_v63_Server_X64
#     _v100_X64,Server_v100_X64,_v100_X64_RS1,Server_v100_X64_RS1,_v100_X64_RS2,_v100_X64_RS3,_v100_X64_RS4,_v100_X64_RS5,Server_v100_X64_RS5,_v100_X64_19H1,_v100_X64_Vb,Server_v100_X64_21H2,_v100_X64_21H2
#     _v100_X64_22H2,_v100_X64_24H2,Server_v100_X64_24H2
# 
#   itanium (IA-64)
#     Server2003IA64,Server2008IA64,Server2008R2IA64
# 
# OS attributes (basically it's a version of the NT Kernel)
#   2:5.00,2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0
#
#
# How to build OS string for Win10+
#   Basic "formula" looks like this: [Server] + _v100 + [_X64] + [_Vb]
#     Server  - an optional prefix, used for server versions of Windows
#     _v100   - a mandatory string, denotes compatibility with Windows 10+ (as for 2024)
#     _X64    - an optional suffix, denotes 64-bit version of OS, however, in 2024 most of the systems are 64-bits
#                 last 32-bit client version of Windows is Windows 10 (32-bit can be updated to 22H2, Vanadium are last for OEMs)
#                 last 32-bit server version of Windows is Windows Server 2008 (Vista Server)
#                 since Windows 8.1, 32-bit OS are implicitly specified by omitting the _X64 suffix, but before they were explicitly specified by the X86 suffix
#                 additionally you may try _ARM64 suffix, however, and like IA64, it has not been researched at all, so it's up to you
#     _Vb     - an optional suffix, denotes minimum version of Windows 10 or 11
#                 for Windows 10 it's a short codename, e.g. _RS2 (Redstone 2)
#                 for Windows 11 it's a "version", e.g. _22H2 (Windows 11 22H2 aka Windows 11 Nickel, released in 2nd half of 2022)
#               there few references for these suffixes (and only suffixes)
#                 https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_versions
#                 https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/get-product-data#list-of-operating-system-codes
#   Examples:
#     _v100_RS2 - 32-bit Windows 10 Redstone 2
#     _v100_X64_Vb - 64-bit Windows 10 Vibranium family
#     _v100_ARM64_19H1 - arm 64-bit Windows 10 19H1 (not tested)
#     Server_v100_X64_RS5 - 64-bit Windows Server 2019
#     _v100_X64_21H2 - 64-bit Windows 11 21H2 Cobalt (should be, there is ambiguous with the Windows 10 Vibranium family)
#     _v100_X64_22H2 - 64-bit Windows 11 22H2 Nickel
#     Server_v100_ARM64_21H2 - arm 64-bit Windows Server 2022 (example, not tested + unofficial)
#     Server_v100_ARM64_24H2 - arm 64-bit Windows Server 2025 (not tested + officially the first ARM64 Server)

function usage_and_exit() {
	echo Usage: "$0 -o <output-file> [-h <hardware-ids>] [-O OS string] [-A OS attribute string] [-T <generation-time>] [-G <cat-guid>] file1 [ file2 ... ]"
	echo See comment inside this .sh file for list of OS string and OS attributes
	exit 1
}

EXEC_DIR=$( dirname $0 )

OUTPUT_CAT_FILE=-
HARDWARE_IDS=windrbd
OS_STRING=7X64,8X64,_v100_X64
OS_ATTR=2:6.1,2:6.2,2:10.0
GEN_TIME="-T 230823140713Z"
CAT_GUID=
DRY_RUN=0

args=$( getopt do:h:O:A:T:G: $* )
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
		-T)
			GEN_TIME="-T $2"
			shift
			shift
			;;
		-G)
			CAT_GUID="-G $2"
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
	echo $EXEC_DIR/generate-cat-file $CAT_GUID $GEN_TIME -A $OS_ATTR -O $OS_STRING -h $HARDWARE_IDS ${sorted_images[*]}
	exit 0
fi

if [ $OUTPUT_CAT_FILE == '-' ]
then
	$EXEC_DIR/generate-cat-file $CAT_GUID $GEN_TIME -A $OS_ATTR -O $OS_STRING -h $HARDWARE_IDS ${sorted_images[*]}
else
	$EXEC_DIR/generate-cat-file $CAT_GUID $GEN_TIME -A $OS_ATTR -O $OS_STRING -h $HARDWARE_IDS ${sorted_images[*]} > $OUTPUT_CAT_FILE
fi
