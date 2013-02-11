import os
import sys
import re

pn = sys.argv[1]
result = []

if "octave" in pn:
    for l in open(pn):
        if l.startswith("Total time"):
            result.append(float(l.split(":")[-1]))
else:
    for l in open(pn):
        m = re.match("real[\t ]+(([0-9]+)m([0-9.]+)s)", l)
        if m:
            min = m.groups()[1]
            sec = m.groups()[2]
            result.append(float(min)*60 + float(sec))
        
print("%.1fs & %.1fs & %.1f\%% & %.1fs & %.1f\%%\\\\" \
          % (result[0], result[1], ((result[1] - result[0]) / result[0] * 100), \
                        result[2], ((result[2] - result[0]) / result[0] * 100)))