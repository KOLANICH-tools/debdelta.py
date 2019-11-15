
dpkg_keeps_controls = (
    "conffiles",
    "config",
    "list",
    "md5sums",
    "postinst",
    "postrm",
    "preinst",
    "prerm",
    "shlibs",
    "templates",
)


def parse_dist(f, d):
    a = f.readline()
    p = {}
    while a:
        if a[:4] in ("Pack", "Vers", "Arch", "Stat", "Inst", "File", "Size", "MD5s"):
            a = de_n(a)
            i = a.index(":")
            assert a[i : i + 2] == ": "
            p[a[:i]] = a[i + 2 :]
        elif a == "\n":
            d[p["Package"]] = p
            p = {}
        a = f.readline()


def scan_control(p, params=None, prefix=None, info=None):
    if prefix is None:
        prefix = ""
    else:
        prefix += "/"
    
    for a in p.splitlines():
        a = de_n(a)
        if a[:4] in ("Pack", "Vers", "Arch", "Stat", "Inst", "File"):
            if info is not None:
                info.append(prefix + a)
            if params is not None:
                i = a.index(":")
                assert a[i : i + 2] == ": "
                params[prefix + a[:i]] = a[i + 2 :]


def de_n(a):
    if a and a[-1] == "\n":
        a = a[:-1]
    return a


def de_bar(a):
    if a and a[:2] == "./":
        a = a[2:]
    elif a == "/.":
        a = ""
    elif a and a[0] == "/":
        a = a[1:]
    return a
