#!/usr/bin/python

# Copyright (C) 2006-09 Andrea Mennucci.
# License: GNU Library General Public License, version 2 or later

# main program, do stuff

from . import *

def main():
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
            except DebDeltaError:
                s = sys.exc_info()[1]
                puke("debpatch", s)
                raise SystemExit(s.exitcode)
            except Exception:
                s = sys.exc_info()[1]
                puke("debpatch", s)
                raise SystemExit(4)
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
        except DebDeltaError:
            s = sys.exc_info()[1]
            puke("debpatch", s)
            if s.logs:
                forensic_send([s.logs])
            raise SystemExit(s.exitcode)
        except Exception:
            s = sys.exc_info()[1]
            puke("debpatch", s)
            raise SystemExit(4)
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
        except DebDeltaError:
            s = sys.exc_info()[1]
            puke("debdelta", s)
            raise SystemExit(s.exitcode)
        except Exception:
            s = sys.exc_info()[1]
            puke("debdelta", s)
            raise SystemExit(4)
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
        except DebDeltaError:
            s = sys.exc_info()[1]
            puke("debdeltas", s)
            raise SystemExit(s.exitcode)
        except Exception:
            s = sys.exc_info()[1]
            puke("debdeltas", s)
            raise SystemExit(4)
        raise SystemExit(exitcode)

    elif action == "delta-upgrade":
        import warnings

        warnings.simplefilter("ignore", FutureWarning)
        try:
            exitcode = delta_upgrade_(argv)
        except KeyboardInterrupt:
            puke("debdelta-upgrade exited due to keyboard interrupt")
            raise SystemExit(5)
        except DebDeltaError:
            s = sys.exc_info()[1]
            puke("debdelta-upgrade", s)
            raise SystemExit(s.exitcode)
        except Exception:
            s = sys.exc_info()[1]
            puke("debdelta-upgrade", s)
            raise SystemExit(4)
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
            deb_path = string.split(deb_uri, "/")
            deb_path = string.join(deb_path[(deb_path.index("pool")) :], "/")

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
        import os
        import sys
        import select
        import fcntl
        import apt
        import thread
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
                    thread.interrupt_main()
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
                    thread.interrupt_main()
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
                    thread.interrupt_main()
                    global nthreads
                    if nthreads:
                        nthreads -= 1
                    # log.write( ' out closed \n' )
                    # return
                os.write(hi.fileno(), s)

        tin = thread.start_new_thread(copyin, ())
        tout = thread.start_new_thread(copyout, ())
        terr = thread.start_new_thread(copyerr, ())
        while nthreads > 0:
            log.write(" nthreads %d \n" % nthreads)
            try:
                while nthreads > 0:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        raise SystemExit(0)

if __name__ == "__main__":
    main()
