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

function negate(){
	echo -ne $(($1^1))
}
function cmd_exists(){
	type -p "$1" &>/dev/null
	negate $?
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
function stderr_parser(){
	while read line; do
		text="$(rmcolor "$line")"
		case "$line" in
			'')
				;;
			*)
				make_fatal=1
				echo "bad $line"
				;;
		esac
	done
}

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

if ! cmd_exists "premake5" > /dev/null; then
	err_exit "premake5 missing, cannot continue"
fi

gen_cmd=""
build_cmd=""
color_cmd=""

CONF_ARCH=""
CONF_OS=""

case $OSTYPE in
	linux-*)
		ok "Linux detected"
		gen_cmd="gmake"
		build_cmd="make"
		CONF_OS="linux"
		;;
	*)
		err_exit "Unsupported OS '$OSTYPE'!"
		;;
esac

if [ -z "$CROSS_COMPILE" ]; then
	CROSS_COMPILE=""
fi

if [ -z "$CC" ]; then
	CC="gcc"
fi

if ! cmd_exists "${CROSS_COMPILE}${CC}" > /dev/null; then
	err_exit "The specified cross compiler doesn't exist"
fi

MACH="$(${CROSS_COMPILE}${CC} -dumpmachine)"

case $MACH in 
	x86_64*)
		ok "x86_64 detected"
		CONF_ARCH="x86_64"
		;;
	i386*)
		ok "i386 detected"
		CONF_ARCH="i386"
		;;
	arm*)
		ok "arm detected"
		CONF_ARCH="arm"
		;;
	*)
		err_exit "Unsupported Architecture '$MACH'"
		;;
esac

case "$1" in
	clean)
		build_cmd="${build_cmd} clean"
		;;
	'')
		;;
	*)
		warn "Unrecognized command '${1}'"
		;;
esac

progress "Generating build files..."
verbose "premake5 $gen_cmd" | premake_parser
if [ ! $? -eq 0 ]; then
	err_exit "premake5 failed!"
fi
progress "Running build command"
verbose "$build_cmd conf=${CONF_ARCH}_${CONF_OS}" | make_parser
if [ ! $? -eq 0 ]; then
	err_exit "build failed!"
fi
ok "All Done!"