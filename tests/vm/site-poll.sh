#!/bin/bash
# One line of a node's view of the site's peer (#275), run on the node by
# vpn.sh's site_poll: `bash -s KEY < site-poll.sh`. The time, the node,
# the peer's endpoint, last handshake and bytes, the routes the master's
# handshakes take (table 5357), and the WAN's gateway link.
k=$1
printf '%s %s %s 5357=[%s] swwan=[%s]\n' "$(date +%s.%N)" "$(hostname)" \
    "$(sudo wg show ra dump | awk -v k="$k" '$1 == k { print "endpoint=" $3, "handshake=" $5, "rx=" $6, "tx=" $7 }')" \
    "$(ip -4 route show table 5357 | paste -sd';')" \
    "$(ip -br -4 addr show swwan 2>/dev/null | tr -s ' ')"
