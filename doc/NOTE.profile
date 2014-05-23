#
# profile format (config) for sandbox.py
# 
# special vars:
#   ~ : home dir
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
    block: all
    allow: localhost

[apparmar]
[ipc]
