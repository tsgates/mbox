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

[network]
    block: all
    allow: localhost

[apparmar]
[ipc]
