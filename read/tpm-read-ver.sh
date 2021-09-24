#!/bin/bash

####
# config

# dev/test nvindex values
TPM_NV_VERSION="0x1500020"

####
# functions

function notice() {
	echo ">>> notice: $@"
}

function warn() {
	echo ">>> warning: $@"
}

function error() {
	echo ">>> error: $@"
	exit 1
}

function error_check() {
	[[ $1 -eq 0 ]] && return
	shift
	error "$@"
}

function usage() {
	echo "usage: tpm-read-ver.sh"
	exit 1
}

####
# main

notice "TPM policy version"
tpm2_nvread -s 4 $TPM_NV_VERSION | xxd
error_check $? "failed to read from the TPM"

exit 0
