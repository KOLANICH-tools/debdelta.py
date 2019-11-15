#!/usr/bin/python

# Copyright (C) 2006-09 Andrea Mennucci.
# License: GNU Library General Public License, version 2 or later

# main program, do stuff

from . import *
from . import _

def main(action=None):
    if os.path.dirname(sys.argv[0]) == "/usr/lib/apt/methods":
        action = None
    else:
        actions = {"delta", "patch", "deltas", "delta-upgrade", "patch-url"}

        __doc__ = doc[action] + doc_common

        # GPG signatures are required for debdelta-upgrade and debpatch
        DO_GPG = action in {"delta-upgrade", "patch"}

        #try:
        (opts, argv) = getopt.getopt(
            sys.argv[1:],
            "vkhdM:n:A",
            (
                "help",
                "info",
                "needsold",
                "dir=",
                "no-act",
                "alt=",
                "old=",
                "delta-algo=",
                "max-percent=",
                "deb-policy=",
                "clean-deltas",
                "clean-alt",
                "no-md5",
                "debug",
                "forensicdir=",
                "forensic=",
                "signing-key=",
                "accept-unsigned",
                "gpg-home=",
                "disable-feature=",
                "test",
                "format=",
                "cache",
                "timeout=",
            ),
        )
        #except getopt.GetoptError:
        #    a = sys.exc_info()[1]
        #    sys.stderr.write(sys.argv[0] + ": " + str(a) + "\n")
        #    raise SystemExit(3)

        for o, v in opts:
            if o == "-v":
                VERBOSE += 1
            elif o == "-d" or o == "--debug":
                DEBUG += 1
            elif o == "-k":
                KEEP = True
            elif o == "--no-act":
                ACT = False
            elif o == "--no-md5":
                DO_MD5 = False
            elif o == "--clean-deltas":
                CLEAN_DELTAS = True
            elif o == "--clean-alt":
                CLEAN_ALT = True
                sys.stderr.write(_("Warning, currently --clean-alt does nothing.") + "\n")
            elif o == "--needsold":
                NEEDSOLD = True
            elif o == "--delta-algo":
                USE_DELTA_ALGO = v
            elif o == "--max-percent":
                MAX_DELTA_PERCENT = int(v)
            elif o == "--deb-policy":
                DEB_POLICY = [j[0] for j in v.split(",") if j]
            elif o == "--timeout":
                if int(v) < 0:
                    sys.stderr.write(_('Error: "--timeout %s" is too small.') % v + "\n")
                    raise SystemExit(3)
                TIMEOUT = int(v)
            elif o == "-M":
                if int(v) <= 1:
                    sys.stderr.write(_('Error: "-M %s" is too small.') % v + "\n")
                    raise SystemExit(3)
                if int(v) <= 12:
                    sys.stderr.write(_('Warning: "-M %s" is quite small.') % v + "\n")
                MAXMEMORY = 1024 * 1024 * int(v)
            elif o == "-n":
                N_DELTAS = int(v)
                if N_DELTAS < 0:
                    sys.stderr.write(_("Error: -n value is negative.") + "\n")
                    raise SystemExit(3)
            elif o == "--test" and action == "deltas":
                DO_TEST = True
            elif o == "--info" and action == "patch":
                INFO = True
            elif o == "--dir":
                DIR = abspath(expanduser(v))
                if v[-2:] == "//":
                    DIR += "//"
                if not os.path.isdir(DIR):
                    sys.stderr.write(_("Error: argument of --dir is not a directory:") + " " + DIR + "\n")
                    raise SystemExit(3)

            elif o == "--forensicdir":
                FORENSICDIR = abspath(expanduser(v))
                if v[-2:] == "//":
                    FORENSICDIR += "//"
                if not os.path.isdir(FORENSICDIR):
                    sys.stderr.write(_("Error: argument of --forensicdir is not a directory:") + " " + FORENSICDIR + "\n")
                    raise SystemExit(3)

            elif o == "--forensic":
                FORENSIC = v
                if FORENSIC[:4] == "http":
                    try:
                        import poster
                    except ImportError:
                        sys.stderr.write(
                            _('To use the http forensic, you must install the package "python-poster".') + "\n"
                        )
                        raise SystemExit(3)
                if FORENSIC[:4] in ("mutt", "mail") and not os.path.exists("/usr/bin/mutt"):
                    sys.stderr.write(_('To use this forensic, you must install the package "mutt".') + "\n")
                    raise SystemExit(3)
            elif o == "--alt":
                if not (os.path.isfile(v) or os.path.isdir(v)):
                    sys.stderr.write(_("Error: argument of --alt is not a directory or a regular file:") + " " + v + "\n")
                    raise SystemExit(3)
                ALT.append(v)
            elif o == "--old" and action == "deltas":
                if not (os.path.isfile(v) or os.path.isdir(v)):
                    sys.stderr.write(_("Error: argument of --old is not a directory or a regular file:") + " " + v + "\n")
                    raise SystemExit(3)
                OLD.append(v)
            elif o == "--help" or o == "-h":
                sys.stderr.write(__doc__)
                raise SystemExit(0)
            elif (o == "--disable-feature") and action in ("delta", "deltas"):
                DISABLED_FEATURES += v.split(",")
            elif (o == "--signing-key") and action in ("delta", "deltas"):
                GPG_SIGNING_KEY = v
                DO_GPG = True
            elif (o == "--accept-unsigned" or o == "-A") and action in ("delta-upgrade", "patch"):
                DO_GPG = False
            elif o == "--gpg-home":
                GPG_HOME = abspath(expanduser(v))
                if not os.path.isdir(GPG_HOME):
                    sys.stderr.write(_("Error: --gpg-home `%s' does not exist.") % GPG_HOME)
                    raise SystemExit(3)
            elif o == "--format":  # maybe, and action in ("delta-upgrade", "patch"):
                if v not in DEB_FORMAT_LIST:
                    sys.stderr.write(_("Error: output format `%s' is unknown.") % v + "\n")
                    raise SystemExit(3)
                DEB_FORMAT = v
            elif o == "--cache":
                DO_CACHE = True
            else:
                sys.stderr.write(_("Error: option `%s' is unknown, try --help") % o + "\n")
                raise SystemExit(3)

    def act():
        "fake function that marks where the action starts"
        pass


    if action == "patch":
        if INFO:
            if len(argv) > 1 and VERBOSE:
                sys.stderr.write(" (printing info - extra arguments are ignored)\n")
            elif len(argv) == 0:
                sys.stderr.write(_("Need a filename; try --help.") + "\n")
                raise SystemExit(3)
            try:
                delta = abspath(argv[0])
                check_is_delta(delta)
                info = get_info(delta)
                for s in info:
                    if s:
                        logger.debug(" info: %r", s)
            except KeyboardInterrupt:
                puke("debpatch exited by keyboard interrupt")
                raise SystemExit(5)
            # except DebDeltaError:
                # s = sys.exc_info()[1]
                # puke("debpatch", s)
                # raise SystemExit(s.exitcode)
            #except Exception:
            #    s = sys.exc_info()[1]
            #    puke("debpatch", s)
            #    raise SystemExit(4)
            raise SystemExit(0)
        # really patch
        if len(argv) != 3:
            sys.stderr.write(_("Need 3 filenames; try --help.") + "\n")
            raise SystemExit(3)

        newdeb = abspath(argv[2])
        if newdeb == "/dev/null":
            newdeb = None

        try:
            do_patch(abspath(argv[0]), abspath(argv[1]), newdeb)
        except KeyboardInterrupt:
            puke("debpatch exited by keyboard interrupt")
            raise SystemExit(5)
        # except DebDeltaError:
            # s = sys.exc_info()[1]
            # puke("debpatch", s)
            # if s.logs:
                # forensic_send([s.logs])
            # raise SystemExit(s.exitcode)
        #except Exception:
        #    s = sys.exc_info()[1]
        #    puke("debpatch", s)
        #    raise SystemExit(4)
        raise SystemExit(0)

    elif action == "delta":
        if len(argv) != 3:
            sys.stderr.write(_("Need 3 filenames; try --help.") + "\n")
            raise SystemExit(3)

        delta = abspath(argv[2])
        try:
            r = do_delta(abspath(argv[0]), abspath(argv[1]), delta)
        except KeyboardInterrupt:
            puke("debdelta exited by keyboard interrupt")
            raise SystemExit(5)
        # except DebDeltaError:
            # s = sys.exc_info()[1]
            # puke("debdelta", s)
            # raise SystemExit(s.exitcode)
        #except Exception:
        #    s = sys.exc_info()[1]
        #    puke("debdelta", s)
        #    raise SystemExit(4)
        raise SystemExit(0)

    elif action == "deltas":
        for v in argv:
            if not (os.path.isfile(v) or os.path.isdir(v)):
                sys.stderr.write(_("Error: argument is not a directory or a regular file:") + " " + v)
                raise SystemExit(3)
        try:
            exitcode = do_deltas(argv)
        except KeyboardInterrupt:
            puke("debdeltas exited by keyboard interrupt")
            raise SystemExit(5)
        # except DebDeltaError:
            # s = sys.exc_info()[1]
            # puke("debdeltas", s)
            # raise SystemExit(s.exitcode)
        # except Exception:
            # s = sys.exc_info()[1]
            # puke("debdeltas", s)
            # raise SystemExit(4)
        raise SystemExit(exitcode)

    elif action == "delta-upgrade":
        import warnings

        warnings.simplefilter("ignore", FutureWarning)
        try:
            exitcode = delta_upgrade_(argv)
        except KeyboardInterrupt:
            puke("debdelta-upgrade exited due to keyboard interrupt")
            raise SystemExit(5)
        #except DebDeltaError:
        #    s = sys.exc_info()[1]
        #    puke("debdelta-upgrade", s)
        #    raise SystemExit(s.exitcode)
        # except Exception:
            # s = sys.exc_info()[1]
            # puke("debdelta-upgrade", s)
            # raise SystemExit(4)
        raise SystemExit(exitcode)

    elif action == "patch-url":
        config = ConfigParser.SafeConfigParser()
        config.read(["/etc/debdelta/sources.conf", expanduser("~/.debdelta/sources.conf")])

        try:
            import apt_pkg
        except ImportError:
            logger.error('ERROR!!! python module "apt_pkg" is missing. Please install python-apt')
            raise SystemExit(1)

        try:
            import apt
        except ImportError:
            logger.error(
                'ERROR!!! python module "apt" is missing. Please install a newer version of python-apt (newer than 0.6.12)'
            )
            raise SystemExit(1)

        apt_pkg.init()

        cache = apt.Cache()
        cache.upgrade(True)

        for a in argv:
            logger.info(_("Lookup %s") % a)
            p = cache[a]
            candidate = p.candidate
            origin = p.candidate.origins[0]
            arch = candidate.architecture
            if not candidate.uris:
                logger.warn(_("Sorry, cannot find an URI to download the debian package of `%s'.") % a)
                continue
            deb_uri = candidate.uri
            installed_version = p.installed.version
            candidate_version = p.candidate.version
            deb_path = deb_uri.split("/")
            deb_path = "/".join(deb_path[(deb_path.index("pool")) :])

            delta_uri_base = delta_uri_from_config(
                config,
                Origin=origin.origin,
                Label=origin.label,
                Site=origin.site,
                Archive=origin.archive,
                PackageName=p.name,
            )

            if delta_uri_base is None:
                logger.warn(_("Sorry, no source is available to upgrade `%s'.") % a)
                continue

            if installed_version == candidate_version:
                logger.warn(_("Sorry, the package `%s' is already at its newest version.") % a)
                continue

            # delta name
            delta_name = (
                p.shortname
                + "_"
                + version_mangle(installed_version)
                + "_"
                + version_mangle(candidate_version)
                + "_"
                + arch
                + ".debdelta"
            )

            delta_name = delta_base_name(p.shortname, installed_version, candidate_version, arch)

            uri = delta_uri_base + "/" + os.path.dirname(deb_path) + "/" + delta_name

            logger.info(a + " : " + uri)
        raise SystemExit(0)

    # apt method

    # still work in progress
    if os.path.dirname(sys.argv[0]) == "/usr/lib/apt/methods":
        import select
        import fcntl
        import apt
        import _thread
        import threading
        import time

        apt_cache = apt.Cache()

        log = open("/tmp/log", "a")
        log.write("  --- here we go\n")

        (hi, ho, he) = os.popen3("/usr/lib/apt/methods/http.distrib", "b", 2)

        nthreads = 3

        class cheat_apt_gen:
            def __init__(self):
                self.uri = None
                self.filename = None
                self.acquire = False

            def process(self, cmd):
                if self.uri:
                    self.filename = cmd[10:-1]
                    log.write(" download %s for %s\n" % (repr(self.uri), repr(self.filename)))
                    self.uri = None
                    self.filename = None
                    self.acquire = False
                    return cmd
                elif self.acquire:
                    self.uri = cmd[5:-1]
                    return cmd
                elif cmd[:3] == "600":
                    self.acquire = True
                else:
                    return cmd

        def copyin():
            bufin = ""
            while True:
                # print ' o'
                s = os.read(ho.fileno(), 1)
                bufin += s
                if log and bufin and (s == "" or s == "\n"):
                    log.write(" meth " + repr(bufin) + "\n")
                    bufin = ""
                if s == "":
                    _thread.interrupt_main()
                    global nthreads
                    if nthreads:
                        nthreads -= 1
                    # log.write( ' in closed \n' )
                    # return
                os.write(1, s)

        def copyerr():
            buferr = ""
            while True:
                s = os.read(he.fileno(), 1)
                buferr += s
                if log and buferr and (s == "" or s == "\n"):
                    log.write(" err " + repr(buferr) + "\n")
                    buferr = ""
                if s == "":
                    _thread.interrupt_main()
                    global nthreads
                    if nthreads:
                        nthreads -= 1
                    log.write(" err closed \n")
                    # return
                os.write(2, s)

        def copyout():
            gen = cheat_apt_gen()
            bufout = ""
            while True:
                s = os.read(0, 1)
                bufout += s
                if log and bufout and (s == "" or s == "\n"):
                    log.write(" apt " + repr(bufout) + "\n")

                    bufout = gen.process(bufout)

                    bufout = ""
                if s == "":
                    _thread.interrupt_main()
                    global nthreads
                    if nthreads:
                        nthreads -= 1
                    # log.write( ' out closed \n' )
                    # return
                os.write(hi.fileno(), s)

        tin = _thread.start_new_thread(copyin, ())
        tout = _thread.start_new_thread(copyout, ())
        terr = _thread.start_new_thread(copyerr, ())
        while nthreads > 0:
            log.write(" nthreads %d \n" % nthreads)
            try:
                while nthreads > 0:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        raise SystemExit(0)

def delta():
    return main("delta")

def patch():
    return main("patch")

def deltas():
    return main("deltas")

def delta_upgrade():
    return main("delta-upgrade")

def patch_url():
    return main("patch-url")


if __name__ == "__main__":
    delta()
