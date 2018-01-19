#!/bin/sh
# Copyright 2018 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYRIGHT file or at
# https://developers.google.com/open-source/licenses/bsd

# Different key than test #2, but same salt.
# Tests accounts imported into Firebase
scenario_cmd() {
	### Constants
	base64_signer_key="U01Ba7WbeBZyY/HjvbEp+N9KkB2h/oF7uSSbBSCj803usz1GV7YIhM+LlusLiU+t3qbz8hh5PLOUSekExEY04w=="
	base64_salt_separator="Bw=="
	rounds=8
	mem_cost=14

	c_valgrind_min=1
	reference_file="${scriptdir}/03-more-values-different-key-passwords.good"
	setup_check_variables
	bulk_password_test
}
