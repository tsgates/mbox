from hotshot import Profile
from hotshot.stats import load as loadStats
from os import unlink
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

def runProfiler(logger, func, args=tuple(), kw={},
verbose=True, nb_func=25,
sort_by=('time',)):
    """
    Run a function in a profiler and then display the functions sorted by time.
    """
    profile_filename = "/tmp/profiler"
    prof = Profile(profile_filename)
    try:
        logger.warning("Run profiler")
        result = prof.runcall(func, *args, **kw)
        prof.close()
        logger.error("Profiler: Process data...")
        stat = loadStats(profile_filename)
        stat.strip_dirs()
        stat.sort_stats(*sort_by)

        logger.error("Profiler: Result:")
        log = StringIO()
        stat.stream = log
        stat.print_stats(nb_func)
        log.seek(0)
        for line in log:
            logger.error(line.rstrip())
        return result
    finally:
        unlink(profile_filename)

