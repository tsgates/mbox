
def read_all(pn):
    ret = []
    for l in open(pn):
        if l.startswith("real"):
            ret.append(l.strip().split()[-1])
        if l.startswith("user") or l.startswith("sys"):
            ret[-1] = ret[-1] + "/" + l.strip().split()[-1]
    return ret

for v in ["3.6", "3.8"]:
    for c in ["one", "all"]:
        print "%s %s " % (v, c),
        for j in ["1", "4"]:
            results = read_all("bench-compile-kernel-v%s-%s-j%s.log" % (v, c, j))
            print results[0], results[1], "\t",
        print