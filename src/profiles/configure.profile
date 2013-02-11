#
# profile for ./configure type program
# 
# special vars:
#   ~ : home dir
#   . : cwd dir
#   
[fs]
    hide: ~
    hide: /tmp
    allow: .

#
# naive example, we will give more freedom later
#  - block
#  - allow
# 
[network]
    block: remote
    allow: local
