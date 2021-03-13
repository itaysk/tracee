#!/bin/sh

TRACEE_EBPF_EXE=${TRACEE_EBPF_EXE:="/tracee/tracee-ebpf"}
TRACEE_RULES_EXE=${TRACEE_RULES_EXE:="/tracee/tracee-rules"}

die() {
	echo $1 >&2
	exit "$2"
}

# parse_args parses the arguments passed to the entrypoint
# it first looks for subcommands, which will be executed immidiately
# then it parses flags for the default command in format '--flagname flagvalue'
# parsed flags are accessible under arg_flagname variables
# positional args are not supported
parse_args() {
	while test $# -gt 0; do
		case "$1" in
			trace)
				shift
				$TRACEE_EBPF_EXE $@
				exit "$?"
				;;
			--list)
				shift
				$TRACEE_RULES_EXE --list
				exit "$?"
				;;
			--rules)
				test $# -lt 2 && die "missing value for argument '$1'." 1
				arg_rules="$2"
				shift
				;;
			--webhook-url)
				test $# -lt 2 && die "missing value for argument '$1'." 1
				arg_webhook_url="$2"
				shift
				;;
			--webhook-content-type)
				test $# -lt 2 && die "missing value for argument '$1'." 1
				arg_webhook_content_type="$2"
				shift
				;;
			*)
				die "unknown option $1" 1
				;;
		esac
		shift
	done
}

parse_args "$@"

test -n "$arg_rules" && flag_rules="--rules=$arg_rules"
test -n "$arg_webhook_url" && flag_webhook_url="--webhook-url=$arg_webhook_url"
test -n "$arg_webhook_content_type" && flag_webhook_content_type="--webhook-content-type=$arg_webhook_content_type"

$TRACEE_EBPF_EXE --output=format:gob --security-alerts | $TRACEE_RULES_EXE --input-tracee=file:stdin --input-tracee=format:gob $flag_webhook_url $flag_webhook_content_type $flag_rules
