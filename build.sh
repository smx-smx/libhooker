#!/bin/bash
# Copyright 2015 Smx

export normal='tput sgr0'
export bold='setterm -bold'

export red='printf \033[00;31m'
export green='printf \033[00;32m'
export yellow='printf \033[00;33m'
export blue='printf \033[00;34m'
export purple='printf \033[00;35m'
export cyan='printf \033[00;36m'
export lightgray='printf \033[00;37m'
export lred='printf \033[01;31m'
export lgreen='printf \033[01;32m'
export lyellow='printf \033[01;33m'
export lblue='printf \033[01;34m'
export lpurple='printf \033[01;35m'
export lcyan='printf \033[01;36m'
export white='printf \033[01;37m'

#don't use jobs atm
#MAKE_JOBS=$(grep processor /proc/cpuinfo | wc -l)
MAKE_JOBS=1

gen_cmd=""
build_cmd=""
color_cmd=""

CONF_OS=""

function _pushd(){
	pushd "$@" >/dev/null 2>&1
}

function _popd(){
	popd "$@" > /dev/null 2>&1
}

function negate(){
	echo -ne $(($1^1))
}

function cmd_exists(){
	type -p "$1" &>/dev/null
	if [ `negate $?` -eq 0 ]; then
		if [ -e "$1" ] && [ ! -d "$1" ]; then
			echo -ne 1;
		else
			echo -ne 0;
		fi
	fi
}

function verbose_dry(){
	$white; echo -e "$1"; $normal
}

function verbose(){
	verbose_dry "$1"
	$1
}

function info(){
	$cyan; echo -e "$1"; $normal
}

function ok(){
	$lgreen; echo -e "$1"; $normal
}

function warn(){
	$lyellow; echo "WARNING: ${1}"; $normal
}

function error(){
	$lred; echo "ERROR: ${1}"; $normal
}

function progress(){
	$purple; echo -e "$1"; $normal
}

function err_exit(){
	error "$1"
	exit 1
}

function rmcolor(){
	echo -ne "$1" | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[m|K]//g"
}

function premake_parser(){
	while read line; do
		text="$(rmcolor "$line")"
		case "$line" in
			"Running action "*)
				progress "$text"
				;;
			"Generating "*)
				$cyan; echo "$text"; $normal
				;;
			"Done.")
				ok "$text"
				;;
			*)
				echo "$line"
				;;
		esac
	done
}

make_fatal=0
function make_parser(){
	in_prj=0
	while read line; do
		if [ $make_fatal -eq 1 ]; then
			echo -e "$line"
			return
		fi
		text="$(rmcolor "$line")"
		case "$line" in
			*====*Building*)
				$yellow; echo "$text"; $normal
				in_prj=1
				;;
			"Creating "*)
				text=$(echo $text | sed 's/Creating\ //g')
				info "[GEN] \t $text"
				in_prj=1
				;;
			*Cleaning*)
				$yellow; echo "$text"; $normal
				;;
			"Linking "*)
				text=$(echo $text | sed 's/Linking\ //g')
				$lred; printf "[LD] \t $text\n"; $normal
				in_prj=0
				;;
			*)
				if [ $in_prj -eq 1 ]; then
					if [ "$(echo "$text" | grep -Eq "^.*:[0-9]+{1,}:.*$"; echo $?)" -eq 0 ]; then
						make_fatal=1
					else
						$green; printf "[CC] \t $text\n"; $normal
					fi
				else
					echo "$line"
				fi
				;;
		esac
	done
}

#### MAIN ####
cd $(dirname $0)

if ! cmd_exists "premake5" > /dev/null; then
	err_exit "premake5 missing, cannot continue"
fi

case $OSTYPE in
	linux-*)
		ok "Linux detected"
		gen_cmd="gmake"
		build_cmd="make -j${MAKE_JOBS}"
		CONF_OS="linux"
		;;
	freebsd*)
		ok "Freebsd detected"
		gen_cmd="gmake verbose=1"
		build_cmd="gmake -j${MAKE_JOBS}"
		CONF_OS="linux"
		CC=gcc5
		CXX=g++5
		export CC CXX
		;;
	*)
		err_exit "Unsupported OS '$OSTYPE'!"
		;;
esac

if [ -z "$CROSS_COMPILE" ]; then
	CROSS_COMPILE=""
fi

if [ -z "$CC" ]; then
	CC="${CROSS_COMPILE}gcc"
fi
if [ -z "$CXX" ]; then
	CXX="${CROSS_COMPILE}g++"
fi
if [ -z "$AR" ]; then
	AR="${CROSS_COMPILE}ar"
fi
if [ -z "$RANLIB" ]; then
	RANLIB="${CROSS_COMPILE}ranlib"
fi
if [ -z "$LD" ]; then
	LD="${CROSS_COMPILE}ld"
fi
if [ -z "$OBJDUMP" ]; then
	OBJDUMP="${CROSS_COMPILE}objdump"
fi
if [ -z "$READELF" ]; then
	READELF="${CROSS_COMPILE}readelf"
fi

if ! cmd_exists ${CC} || ! cmd_exists ${AR} || ! cmd_exists ${LD} || ! cmd_exists ${RANLIB}; then
		err_exit "The compiler '${CC}' doesn't exist, or the toolchain is broken"
fi

MACH="$(${CC} -dumpmachine)"

case "$1" in
	help)
		$white
		echo -e "Usage:"
		echo -e "To compile           $0"
		echo -e "To cross compile     CROSS_COMPILE=toolchain-prefix- $0"
		echo -e "To clean:            $0 clean"
		$normal
		exit 1
		;;
	clean)
		gen_cmd="clean"
		build_cmd="${build_cmd} clean"
		;;
	'')
		;;
	*)
		warn "Unrecognized command '${1}'"
		;;
esac

if [ -z $CONF_ARCH ]; then
	case $MACH in
		x86_64*)
			ok "x86_64 detected"
			CONF_ARCH="x86_64"
			;;
		i386*)
			ok "i386 detected"
			CONF_ARCH="i386"
			;;
		armv5*|arm*)
			ok "arm v5 detected"
			CONF_ARCH="armv5"
			;;
		armv7*)
			ok "arm v7 detected"
			CONF_ARCH="armv7"
			;;
		*)
			warn "Couldn't detect machine, trying AUTO 	detection..."
			CONF_ARCH="auto"
			;;
	esac
fi

progress "Generating build files..."
CROSS_COMPILE=$CROSS_COMPILE verbose "premake5 $gen_cmd" | premake_parser
if [ ! ${PIPESTATUS[0]} -eq 0 ]; then
	err_exit "premake5 failed!"
fi
progress "Running build command"
verbose "$build_cmd config=${CONF_ARCH}_${CONF_OS}" | make_parser
if [ ! ${PIPESTATUS[0]} -eq 0 ]; then
	err_exit "build failed!"
fi

case "$1" in
	clean)
		$yellow; echo "Cleaning up..."; $normal
		if [ -d "obj" ]; then
			rm -r "obj";
			if [ $(ls -1 *.make 2>/dev/null | wc -l) -gt 0 ]; then
				rm *.make
			fi
		fi
		if [ -d "bin" ] && [ $(ls -1 bin/ 2>/dev/null | wc -l) -gt 0 ]; then
			rm -r bin/*
		fi
	;;
esac
ok "All Done!"
