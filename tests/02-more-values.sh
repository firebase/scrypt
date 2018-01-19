#!/bin/sh
# Copyright 2018 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYRIGHT file or at
# https://developers.google.com/open-source/licenses/bsd

# Tests an array of different passwords
scenario_cmd() {
	### Constants
	base64_signer_key="NkZlKPkYEFfnbh1nYTfLsbqQnQ6jyRV4itK7iUD+hjO96tsAYhBG40BVS3AuJyiwHinqc5RR3oA+lppOXPNRmw=="
	base64_salt_separator="Bw=="
	rounds=8
	mem_cost=14

	c_valgrind_min=1
	reference_file="${scriptdir}/02-more-values-passwords.good"
	setup_check_variables
	bulk_password_test
}
