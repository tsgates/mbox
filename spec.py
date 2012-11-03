
MAX_PATH = 256

O_ACCMODE  = 00000003
O_RDONLY   = 00000000
O_WRONLY   = 00000001
O_RDWR     = 00000002
O_CREAT    = 00000100	# not fcntl 
O_EXCL     = 00000200	# not fcntl 
O_NOCTTY   = 00000400	# not fcntl 
O_TRUNC    = 00001000	# not fcntl 
O_APPEND   = 00002000
O_NONBLOCK = 00004000
O_DSYNC    = 00010000	# used to be O_SYNC, see below 
O_DIRECT   = 00040000	# direct disk access hint 
O_LARGEFILE= 00100000
O_DIRECTORY= 00200000	# must be a directory
O_NOFOLLOW = 00400000	# don't follow links
O_NOATIME  = 01000000
O_CLOEXEC  = 02000000	# set close_on_exec
