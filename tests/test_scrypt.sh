#!/bin/sh
# Copyright 2018 Google LLC
# Copyright 2009 Colin Percival
#
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYRIGHT file or at
# https://developers.google.com/open-source/licenses/bsd

# Build directory (allowing flexible out-of-tree builds).
bindir=$1

# Find script directory and load helper functions.
scriptdir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. ${scriptdir}/shared_test_functions.sh

# We need a ${bindir}.
if [ -z ${bindir} ]; then
	printf "Warning: Scrypt binary directory not given.\n"
	printf "Attempting to use default values for in-source-tree build.\n"
	bindir=".."
fi
	printf "Using scriptdir ${scriptdir}.\n"
	printf "Using bindir ${bindir}.\n"
	printf "Using bindir $(pwd ${bindir}).\n"

# Check for optional valgrind.
check_optional_valgrind

# Clean up previous directories, and create new ones.
prepare_directories

# Generate valgrind suppression file if it is required.  Must be
# done after preparing directories.
ensure_valgrind_suppression ${bindir}/tests/valgrind/potential-memleaks

# Run the test scenarios; this will exit on the first failure.
run_scenarios ${scriptdir}/??-*.sh
