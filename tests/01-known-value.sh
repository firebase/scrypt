#!/bin/sh
# Copyright 2018 Google LLC
#
# Use of this source code is governed by a BSD-style
# license that can be found in the COPYRIGHT file or at
# https://developers.google.com/open-source/licenses/bsd

# Basic test of ecrypting a single password
scenario_cmd() {
	### Constants
	base64_signer_key="jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=="
	base64_salt_separator="Bw=="
	rounds=8
	memcost=14

	c_valgrind_min=1

	password="hunter2"
	hashedPasswordRef="70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A=="
	base64_salt="42xEC+ixf3L2lw=="

	# Run the binary which tests known input/output strings.
	setup_check_variables
	single_password_test
}
