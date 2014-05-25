#
# profile format (config) for sandbox.py
# 
# [fs]
#
# special vars:
#   ~ : home dir
#   
#
# [network]
#
# The following options can be used:
#
#  - kill: kill the process if it tries to connect to selected ip/port
#
#  - block: block the connection to selected ip/port
#
#  - allow: allow connections to selected ip/port
#
#  - log: allow but log connections to selected ip/port
#
# The options take an IP address, and optionally a port, separated by ':'.
# If no port is provided, any port is matched. If an IP ends with zeros,
# any IP with the same prefix will be matched.
#
# If more than one rule is matching, the most precise rule will be used.
#
# IPv6 is not supported yet.
#
[fs]
    hide: ~
    hide: /tmp
    # allow precedes hidden options
    allow: ~/.vimrc
    allow: ~/download/build
    # don't sandbox files in /var/data
    direct: /var/data

[network]
    # kill process for all unallowed connections
    kill: 0.0.0.0
    # block connections on 192.168.1.* (without killing the process)
    block: 192.168.1.0
    # allow connections on port 22 and 80, and log port 80
    # on ip 192.168.1.1
    allow: 192.168.1.1:22
    log: 192.168.1.1:80

[apparmar]
[ipc]
