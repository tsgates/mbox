#pragma once

//
// comment this to depress all debuging message
//
// ex) dbg(filter, msg), err(msg),
//     dbg(unlink, "failed:%d", error)
//

#define DEBUG
#ifdef DEBUG

 enum { dbg_welcome  = 1 };
 enum { dbg_path     = 1 };
 enum { dbg_info     = 1 };
 enum { dbg_test     = 1 };
 enum { dbg_getdents = 1 };
 enum { dbg_fatal    = 1 };

# define dbg( filter, msg, ... )                \
    do {                                        \
        if ( dbg_##filter ) {                   \
            fprintf(stderr, "%s@%d: " msg "\n",\
                    __FUNCTION__,               \
                    __LINE__,                   \
                    ##__VA_ARGS__ );            \
        }                                       \
    } while( 0 )

# define ifdbg( filter, statements )            \
    do {                                        \
        if ( dbg_##filter ) {                   \
            (statements);                       \
        }                                       \
    } while ( 0 )

# define msg( filter, msg ) dbg( filter, "%s", msg )

#else

# define dbg( filter, msg, ... )                \
    do {                                        \
    } while( 0 )

# define ifdbg( filter, statements )            \
    do {                                        \
    } while ( 0 )

# define msg( filter, msg )                     \
    do {                                        \
    } while ( 0 )
    
#endif
