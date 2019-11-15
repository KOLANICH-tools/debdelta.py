
class Predictor:
    package_stats = None
    upgrade_stats = None

    def __init__(self):
        import shelve

        # self.shelve=shelve
        if os.getuid() == 0:
            basedir = "/var/lib/debdelta"
        else:
            if not os.path.exists(os.path.expanduser("~/")):
                logger.warn("(home directory does not exists, Predictor disabled)")
                return
            basedir = os.path.expanduser("~/.debdelta")

        s = os.path.join(basedir, "upgrade.db")
        if not os.path.exists(basedir):
            logger.info("Creating: %r", basedir)
            os.makedirs(basedir)
        self.upgrade_stats = shelve.open(s, flag="c")

        s = os.path.join(basedir, "packages_stats.db")

        if os.path.exists(s) or DEBUG > 1:
            self.package_stats = shelve.open(s, flag="c")

        self.patch_time_predictor = self.patch_time_predictor_math

    # predictor for patching time
    def patch_time_predictor_simple(self, p):
        if "ServerBogomips" in p and "PatchTime" in p:
            return float(p["PatchTime"]) / BOGOMIPS * float(p["ServerBogomips"])
        else:
            return None

    def update(self, p, t):
        # save delta info
        if self.package_stats is not None:
            n = p["NEW/Package"]
            d = copy(p)
            d["LocalDeltaTime"] = t
            try:
                self.package_stats[n] = d
            except Exception:
                logger.exception("ERROR:Cannot update package_stats")

        if self.upgrade_stats is None:
            return

        s = "ServerID"
        if s not in p:
            return
        s = s + ":" + p[s]
        if s not in self.upgrade_stats:
            r = 1
            if "ServerBogomips" in p:
                r = float(p["ServerBogomips"]) / BOGOMIPS
            try:
                self.upgrade_stats[s] = {"PatchSpeedRatio": r}
            except Exception:
                logger.exception("ERROR:Cannot update upgrade_stats")

        if "PatchTime" not in p:
            return
        ut = float(p["PatchTime"])

        r = self.upgrade_stats[s]["PatchSpeedRatio"]

        nr = 0.95 * r + 0.05 * (t / ut)
        a = self.upgrade_stats[s]
        a["PatchSpeedRatio"] = nr
        try:
            self.upgrade_stats[s] = a
        except Exception:
            logger.exception("ERROR:Cannot update upgrade_stats")
        if VERBOSE > 1:
            logger.debug(
                "  Upstream %r PatchSpeedRatio from %r to %r , %r", ut, r, nr, self.upgrade_stats[s]["PatchSpeedRatio"]
            )

    def patch_time_predictor_math(self, p):
        "Predicts time to patch."
        if "PatchTime" not in p:
            return None
        ut = float(p["PatchTime"])
        #
        s = "ServerID"
        if s not in p:
            return self.patch_time_predictor_simple(p)
        s = s + ":" + p[s]
        if s not in self.upgrade_stats:
            return self.patch_time_predictor_simple(p)

        r = self.upgrade_stats[s]["PatchSpeedRatio"]
        return r * ut


def delta_uri_from_config(config, **dictio):
    secs = config.sections()
    for s in secs:
        opt = config.options(s)
        if "delta_uri" not in opt:
            raise DebDeltaError("sources.conf section " + repr(s) + "does not contain delta_uri", exitcode=3)
        match = True
        for a in dictio:
            # damn it, ConfigParser changes everything to lowercase !
            if (a.lower() in opt) and (dictio[a] != config.get(s, a)):
                # print '!!',a, repr(dictio[a]) , ' != ',repr(config.get( s, a))
                match = False
                break
        if match:
            return config.get(s, "delta_uri")
    if VERBOSE:
        logger.warn(" " + _("(sources.conf does not provide a server for `%s')"), repr(dictio["PackageName"]))


def delta_upgrade_(args):
    # a list of all error exitcodes that derive from downloading and applying
    mainexitcodes = [0]

    original_cwd = os.getcwd()

    import _thread
    import threading
    import queue
    import urllib.request, urllib.error, urllib.parse
    import fcntl
    import atexit
    import signal

    proxies = urllib2.getproxies()
    if VERBOSE and proxies:
        # note that this message is indented, I dont know what's best in translations
        logger.warn(
            _(
                ' Proxy settings detected in the environment; using "urllib2" for downloading; but\n  this disables some features and is in general slower and buggier. See man page.'
            )
        )
    # for example, urllib2 transforms http response "401"  into "404" , and "302" into "200"

    config = configparser.SafeConfigParser()
    a = config.read(["/etc/debdelta/sources.conf", expanduser("~/.debdelta/sources.conf")])
    # FIXME this does not work as documented in Python
    # if VERBOSE > 1 : print 'Read config files: ',repr(a)

    import warnings

    warnings.simplefilter("ignore", FutureWarning)

    if DO_PROGRESS:
        sys.stderr.write(string.ljust(_("Initializing APT cache..."), terminalcolumns) + "\r")
    elif VERBOSE:
        logger.debug(_("Initializing APT cache..."))

    try:
        import apt_pkg
    except ImportError:
        raise DebDeltaError('python module "apt_pkg" is missing. Please install python-apt', True)

    try:
        import apt
    except ImportError:
        raise DebDeltaError(
            'python module "apt" is missing. Please install a newer version of python-apt (newer than 0.6.12).', True
        )

    apt_pkg.init()

    # from apt import SizeToStr
    # Return a string describing the size in a human-readable manner using
    # SI prefix and base-10 units, e.g. '1k' for 1000, '1M' for 1000000, etc.

    def SizeToKibiStr(a):
        "this uses kibibytes (altough the program prints them as kilobytes)"
        if a < 8096:
            return str(int(a)) + "B"
        elif a < 8096 * 1024:
            return str(int(a / 1024)) + "kB"
        else:
            return str(int(a / 1024 / 1024)) + "MB"

    if DO_PROGRESS:
        sys.stderr.write(string.ljust(_("Upgrading APT cache..."), terminalcolumns) + "\r")
    elif VERBOSE:
        logger.debug(_("Upgrading APT cache..."))

    cache = apt.Cache()
    try:
        cache.upgrade(True)
    except BaseException:
        if DO_PROGRESS:
            sys.stderr.write(string.ljust(_("Failed! Safe upgrading APT cache..."), terminalcolumns) + "\r")
        elif VERBOSE:
            logger.debug(_("Failed! Safe upgrading APT cache..."))
        cache.upgrade(False)

    if DO_PROGRESS:
        sys.stderr.write(string.ljust(_("Upgraded APT cache."), terminalcolumns) + "\r")
    elif VERBOSE:
        logger.debug(_("Upgraded APT cache."))

    diversions = scan_diversions()

    if DIR is None:
        if os.getuid() == 0:
            DEB_DIR = "/var/cache/apt/archives"
        else:
            DEB_DIR = "/tmp/archives"
    else:
        DEB_DIR = DIR
    if not os.path.exists(DEB_DIR):
        os.mkdir(DEB_DIR)
    if not os.path.exists(DEB_DIR + "/partial"):
        os.mkdir(DEB_DIR + "/partial")

    try:
        # APT does (according to strace)
        # open("/var/cache/apt/archives/lock", O_RDWR|O_CREAT|O_TRUNC, 0640) = 17
        # fcntl64(17, F_SETFD, FD_CLOEXEC)        = 0
        # fcntl64(17, F_SETLK, {type=F_WRLCK, whence=SEEK_SET, start=0, len=0}) = 0
        # so
        a = os.open(DEB_DIR + "/lock", os.O_RDWR | os.O_TRUNC | os.O_CREAT, 0o640)
        fcntl.fcntl(a, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        # synopsis lockf(   fd, operation, [length, [start, [whence]]])
        fcntl.lockf(a, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, 0)
    except IOError:
        s = sys.exc_info()[1]
        from errno import EAGAIN

        if s.errno == EAGAIN:
            a = " already locked!"
        else:
            a = str(s)
        if DEB_DIR == "/var/cache/apt/archives":
            a = a + " (is APT running?)"
        raise DebDeltaError("could not lock dir: " + DEB_DIR + " " + a, retriable=True)

    if VERBOSE or DEB_DIR != "/var/cache/apt/archives":
        logger.info(_("Recreated debs are saved in the directory %s"), DEB_DIR)

    # these are the packages that do not have a delta
    no_delta = []

    total_time = -(time.time())

    # predictor for patching time
    if DO_PREDICTOR:
        predictor = Predictor()

    # this is a dictonary (key is package name) of parameters of deltas
    # (to add some math in the future)
    params_of_delta = {}

    patching_queue = queue.Queue()
    thread_returns = {}
    # thread_do_patch

    def thread_do_patch(que, no_delta, returns, exitcodes, forensics):
        if VERBOSE > 1:
            logger.info("  Patching thread started. ")
        debs_size = 0
        debs_time = 0
        while True:
            a = que.get()
            if a is None:
                break
            (name, delta, newdeb, deb_uri) = a
            debs_time -= time.time()
            TD = tempo()
            if not ACT:
                logger.info("Would create: %r    ", newdeb)
            else:
                if VERBOSE >= 2:
                    logger.debug("  Now patching for: %r", name)
                try:
                    # start_time=time.time()
                    returns["patchname"] = os.path.basename(newdeb)
                    ret = do_patch_(delta, "/", newdeb, TD, returns, diversions=diversions, do_progress=False)
                    del returns["patchname"]
                    l = os.path.getsize(newdeb)
                    # a=time.time() - start_time
                    a = ret[1]
                    # dear translator, please align this line with the line saying 'Downloaded, ...'
                    msg = _("Created,    time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s")
                    msgdata = {"time": a, "speed": SizeToKibiStr(l / (a + 0.001)), "name": os.path.basename(newdeb)}
                    if DO_PROGRESS:
                        sys.stderr.write(string.ljust(msg % msgdata, terminalcolumns) + "\n")
                    else:
                        logger.info(msg % msgdata)
                except KeyboardInterrupt:
                    _thread.interrupt_main()
                    rmtree(TD)
                    return
                except DebDeltaError:
                    s = sys.exc_info()[1]
                    puke(" Error: applying of delta for " + name + " failed: ", s)
                    if "e" in DEB_POLICY:
                        no_delta.append((deb_uri, newdeb))
                    elif VERBOSE > 1:
                        logger.debug('  No deb-policy "e", no download of %r', deb_uri)
                    forensics.append(s.logs)
                    exitcodes.append(s.exitcode)
                except BaseException:
                    if puke is None:
                        return
                    puke(" *** Error while applying delta for " + name + ": ")
                    if "e" in DEB_POLICY:
                        no_delta.append((deb_uri, newdeb))
                    elif VERBOSE > 1:
                        logger.debug('  No deb-policy "e", no download of %r', deb_uri)
                    exitcodes.append(4)
                else:
                    if name in params_of_delta:
                        p = params_of_delta[name]
                        name, elaps = ret
                        if DO_PREDICTOR:
                            predictor.update(p, elaps)
                            if VERBOSE > 1:
                                t = predictor.patch_time_predictor(p)
                                if t:
                                    logger.debug("  (Predicted %.3f sec )", t)
                    debs_size += os.path.getsize(newdeb)
                    if os.path.exists(delta):
                        os.unlink(delta)
            rmtree(TD)
            debs_time += time.time()
        returns["debs_size"] = debs_size
        returns["debs_time"] = debs_time
        if VERBOSE > 1:
            logger.debug("  Patching thread ended , bye bye. ")

    #####################################

    def progress_string(statusdb):
        download = ""
        if "downloaduri" in statusdb:
            download = "D %2d%% (%4s/s) %s " % (
                statusdb.get("downloadprogress", -1),
                statusdb.get("downloadspeed", "-"),
                statusdb["downloaduri"],
            )
        patch = ""
        if "patchname" in statusdb:
            patch = "P %2d%% %s" % (statusdb.get("patchprogress", -1), statusdb["patchname"])
        if terminalcolumns is None:
            return download + " ; " + patch
        if not patch:
            return download[:terminalcolumns]
        if not download:
            return patch[:terminalcolumns]
        ld = len(download)
        lp = len(patch)
        b = ld + lp
        if b < terminalcolumns - 3:
            return download + " ; " + patch
        a = float(terminalcolumns - 5) / float(b)
        ld = int(ld * a)
        lp = int(lp * a)
        return download[:ld] + " ; " + patch[:lp] + ".."

    #########################################

    import socket
    import http.client
    from urllib.parse import urlparse, urlunparse

    # manage connections
    # keeps a cache of all connections, by URL
    http_conns = {}

    def conn_by_url(url):
        url = urlparse(url)[1]
        if url not in http_conns:
            if VERBOSE > 1:
                logger.debug("  Opening connection to: %r", url)
            http_conns[url] = http.client.HTTPConnection(url, timeout=TIMEOUT)
        return http_conns[url]

    def conn_close(url, fatal=False):
        url = urlparse(url)[1]
        conn = http_conns.get(url)
        if fatal:
            http_conns[url] = None
        else:
            del http_conns[url]
        if conn is not None:
            if VERBOSE > 1:
                logger.debug("  Closing connection to: %r", url)
            conn.close()

    ####

    def _connect(uri, headers):
        "connects for a GET ; returns (filetype, statuscode, servermessage, getheaders)"
        uri_p = urlparse(uri)
        if uri_p.scheme == "http" and not proxies:
            # use persistent http connections
            conn = conn_by_url(uri)
            if conn is None:
                return None, None, None, None
            try:
                conn.request("GET", urllib.parse.quote(uri_p[2]), headers=headers)
                r = conn.getresponse()
                return r, r.status, r.reason, r.msg
            except (http.client.HTTPException, socket.error):
                e = sys.exc_info()[1]
                if VERBOSE:
                    puke(" Connection error (retrying): ", uri_p[1])
                conn_close(uri)
                try:
                    conn = conn_by_url(uri)
                    conn.request("GET", urllib.parse.quote(uri_p[2]), headers=headers)
                    r = conn.getresponse()
                    return r, r.status, r.reason, r.msg
                except (http.client.HTTPException, socket.error):
                    e = sys.exc_info()[1]
                    puke("Connection error (fatal): ", uri_p[1])
                    mainexitcodes.append(1)
                    try:
                        conn_close(uri, fatal=True)
                    except BaseException:
                        pass
                    mainexitcodes.append(1)
                    return e, None, None, None
        else:  # use urllib2
            try:
                if uri_p.scheme == "http":
                    a = [copy(z) for z in uri_p]
                    a[2] = urllib.parse.quote(uri_p[2])
                    uri = urlunparse(a)
                req = urllib.request.Request(uri, headers=headers)
                r = urllib.request.urlopen(req)
                # print r.info(),dir(r),r.code
                return r, getattr(r, "code", None), getattr(r, "msg", "(no message)"), r.info()
            except urllib.error.HTTPError:
                e = sys.exc_info()[1]
                return e.code, None, None, None
            except (http.client.HTTPException, socket.error, urllib.error.URLError):
                e = sys.exc_info()[1]
                puke("Connection error (fatal)", uri)
                mainexitcodes.append(1)
                return e, None, None, None

    # various HTTP facilities

    def _parse_ContentRange(s):
        # bytes 0-1023/25328
        if not s or s[:6] != "bytes ":
            logger.warn("Malformed Content-Range %r", s)
            return
        a = s[6:].split("/")
        if len(a) != 2:
            logger.warn("Malformed Content-Range %r", s)
            return
        b = a[0].split("-")
        if len(b) != 2:
            logger.warn("Malformed Content-Range %r", s)
            return
        return int(b[0]), int(b[1]), int(a[1])

    # test_uri

    def test_uri(uri):
        conn = conn_by_url(uri)
        if conn is None:
            return None
        uri_p = urlparse(uri)
        assert uri_p[0] == "http"
        conn.request("HEAD", urllib.parse.quote(uri_p[2]), headers=HTTP_USER_AGENT)
        r = conn.getresponse()
        r.read()
        r.close()
        return r.status

    # download_10k_uri
    def download_10k_uri(uri, outname):
        "in case of connection error, returns the (error, None, None, None) ; otherwise returns (status,len,outname,complete)"
        # download
        uri_p = urlparse(uri)
        assert uri_p[0] == "http"
        re = copy(HTTP_USER_AGENT)
        re["Range"] = "bytes=0-10239"
        complete = False
        r, status, msg, responseheaders = _connect(uri, re)
        if not hasattr(r, "read") and responseheaders is None:
            return r, None, None, None
        if status == 301 and "location" in responseheaders:
            r.read()
            r.close()
            return download_10k_uri(responseheaders["location"], outname)
        elif status == 206:
            outnametemp = os.path.join(os.path.dirname(outname), "partial", os.path.basename(outname))
            try:
                l = _parse_ContentRange(responseheaders["Content-Range"])[2]
            except (KeyError, ValueError):
                l = None
        elif status == 200:
            outnametemp = outname
            complete = True
            try:
                l = int(responseheaders.get("Content-Length"))
            except BaseException:
                l = None
        else:  # FIXME how do we deal with a FTP mirror of deltas ?
            r.read()
            r.close()
            return status, None, None, None
        s = r.read()
        r.close()
        # (maybe I did not understand the status 206 ?)
        if not complete and l is not None and len(s) >= l:
            outnametemp = outname
            complete = True
        if os.path.exists(outnametemp) and os.path.getsize(outnametemp) >= len(s):
            # do not truncate preexisting file
            complete = os.path.getsize(outnametemp) >= l
            return status, outnametemp, l, complete
        out = open(outnametemp, "w")
        out.write(s)
        out.close()
        return status, outnametemp, l, complete

    # download_uri
    def download_uri(uri, outname, conn_time, len_downloaded, statusdb):
        outnametemp = os.path.join(os.path.dirname(outname), "partial", os.path.basename(outname))
        re = copy(HTTP_USER_AGENT)
        # content range
        l = None
        if os.path.exists(outnametemp):
            # shamelessly adapted from APT, methods/http.cc
            s = os.stat(outnametemp)
            l = s[ST_SIZE]
            # t=s[ST_MTIME]
            # unfortunately these do not yet work
            # thank god for http://docs.python.org/lib/module-time.html
            # actually APT does
            # t=time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(t))
            ##re["If-Range"] =  time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(t))
            ####re["If-Range"] =  time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(t))
            re["Range"] = "bytes=%li-" % ((int(l) - 1))
        # start downloading
        start_time = time.time()
        r, status, message, responseheaders = _connect(uri, re)
        if not hasattr(r, "read") and responseheaders is None:
            return
        if status in (301, 302) and "location" in responseheaders:
            r.read()
            r.close()
            if VERBOSE > 1:
                logger.debug(_("  Redirect to:") + " " + repr(responseheaders["location"]))
            return download_uri(responseheaders["location"], outname, conn_time, len_downloaded, statusdb)
        if not (status is None or status == 200 or (status == 206 and l is not None)):
            if VERBOSE:
                logger.warn("Connection problem, status:" + str(status) + " msg:" + str(message) + " uri:" + str(uri))
            r.read()
            r.close()
            return
        # print 'ooK Content-Range', r.getheader('Content-Range') #HACK
        if l and status == 200:
            logger.warn(" Hmmm... our HTTP range request failed, %r %r %r", re, status, message)
        if status == 200:
            out = open(outnametemp, "w")
            try:
                total_len = int(responseheaders["Content-Length"])
            except (KeyError, ValueError):
                total_len = None
        elif status == 206:
            # APT does scanf of    "bytes %lu-%*u/%lu",&StartPos,&Size
            # first-byte-pos "-" last-byte-pos "/" instance-length
            out = open(outnametemp, "a")
            try:
                a, b, total_len = _parse_ContentRange(responseheaders["Content-Range"])
            except (KeyError, ValueError):
                e = sys.exc_info()[1]
                logger.warn(
                    "! problem, http response [206], Content Range %s , error %s , uri %s\n"
                    % (responseheaders.get("Content-Range"), e, uri)
                )
                return
            out.seek(a)
            out.truncate()
        else:
            out = open(outnametemp, "w")
            try:
                total_len = int(responseheaders.get("Content-length"))
            except ValueError:
                total_len = None

        free = freespace(os.path.dirname(outname))
        if total_len is not None and free and (free + 2 ** 14) < total_len:
            logger.warn(_("Not enough disk space to download:") + " " + os.path.basename(uri))
            r.read()
            r.close()
            mainexitcodes.append(1)
            return
        j = 0

        s = r.read(1024)
        while s and (total_len is None or out.tell() < total_len):
            j += len(s)
            out.write(s)
            if total_len:
                statusdb["downloadprogress"] = 99.9 * out.tell() / total_len
            a = time.time() + conn_time - start_time
            if a > 0.5:
                statusdb["downloadspeed"] = SizeToKibiStr(float(j + len_downloaded) / a)
            s = r.read(1024)
        out.close()
        r.close()
        # end of download
        a = time.time() - start_time
        # if total_len == None:
        #  total_len = os.path.getsize(outnametemp)

        # dear translator, please align this line with the line saying 'Created,    ...'
        msg = _("Downloaded, time %(time)5.2fsec, speed %(speed)4s/sec, %(name)s")
        msgdata = {"time": a, "speed": SizeToKibiStr(j / (a + 0.001)), "name": os.path.basename(uri)}
        if DO_PROGRESS:
            sys.stderr.write(string.ljust(msg % msgdata, terminalcolumns) + "\n")
        else:
            logger.info(msg % msgdata)

        os.rename(outnametemp, outname)
        # FIXME this is incorrect by 1024 bytes
        return conn_time + a, (j + len_downloaded)

    # end of HTTP stuff

    # start patching thread
    forensics = []

    patching_thread = threading.Thread(
        target=thread_do_patch, args=(patching_queue, no_delta, thread_returns, mainexitcodes, forensics)
    )
    patching_thread.daemon = True
    patching_thread.start()

    # first merry-go-round

    deltas_down_size = 0
    deltas_down_time = 0

    # this is a list of tuples of .....
    available_deltas = []

    not_available_deltas = []

    if hasattr(apt.package.Package, "is_installed"):

        def is_installed(p):
            return p.is_installed

    elif hasattr(apt.package.Package, "isInstalled"):

        def is_installed(p):
            return p.isInstalled

    else:
        assert 0

    if hasattr(apt.package.Package, "marked_upgrade"):

        def marked_upgrade(p):
            return p.marked_upgrade

    elif hasattr(apt.package.Package, "markedUpgrade"):

        def marked_upgrade(p):
            return p.markedUpgrade

    else:
        assert 0

    progress_count = 0

    # first merry-go-round, use package cache to fill available_deltas, download 10kB of each delta
    for p in cache:
        # print progress
        if DO_PROGRESS:
            progress_count += 1
            if 0 == (progress_count & 2047):
                sys.stderr.write(
                    string.ljust("%2.1f%%" % (float(progress_count) * 100.0 / len(cache)), terminalcolumns) + "\r"
                )

        if is_installed(p) and marked_upgrade(p):
            if args and p.name not in args:
                continue
            # thanks a lot to Julian Andres Klode
            candidate = p.candidate
            origin = p.candidate.origins[0]
            arch = candidate.architecture
            deb_uri = candidate.uri
            installed_version = p.installed.version
            candidate_version = p.candidate.version
            newsize = p.candidate.size
            deb_path = deb_uri.split("/")
            try:
                thepoolindex = deb_path.index("pool")
            except ValueError:
                logger.warn(
                    '! Package "%s" (version %s) does not have "pool" in the uri %s \n'
                    % (p.name, candidate_version, deb_uri)
                )
                continue
            deb_path = "/".join(deb_path[thepoolindex:])

            # try all possible variants of the filename
            newdebs = [p.shortname + "_" + candidate_version + "_" + arch + ".deb", os.path.basename(deb_uri)]
            if ":" in candidate_version:
                a = candidate_version.split(":")
                newdebs.append(p.shortname + "_" + a[1] + "_" + arch + ".deb")
                newdebs.append(p.shortname + "_" + a[0] + "%3A" + a[1] + "_" + arch + ".deb")
                newdebs.append(p.shortname + "_" + a[0] + "%3a" + a[1] + "_" + arch + ".deb")

            for newdeb in newdebs:
                if os.path.exists(DEB_DIR + "/" + newdeb) or os.path.exists("/var/cache/apt/archives/" + newdeb):
                    if VERBOSE > 1:
                        logger.debug("  Already downloaded: %r %r", p.name, candidate_version)
                    newdeb = None
                    break
            if newdeb is None:
                continue
            newdeb = DEB_DIR + "/" + newdebs[-1]

            if VERBOSE > 1:
                logger.debug(
                    "  Looking for a delta for %s from %s to %s ", p.name, installed_version, candidate_version
                )
            delta_uri_base = delta_uri_from_config(
                config,
                Origin=origin.origin,
                Label=origin.label,
                Site=origin.site,
                Archive=origin.archive,
                PackageName=p.name,
            )
            if delta_uri_base is None:
                if "s" in DEB_POLICY:
                    no_delta.append((deb_uri, newdeb))
                continue

            a = urlparse(delta_uri_base)
            assert a[0] == "http"

            # delta name
            delta_name = delta_base_name(p.shortname, installed_version, candidate_version, arch)

            uri = delta_uri_base + "/" + os.path.dirname(deb_path) + "/" + delta_name

            # download first part of delta
            abs_delta_name = DEB_DIR + "/" + delta_name

            # maybe it is already here
            if os.path.exists(abs_delta_name):
                a = abs_delta_name
            else:
                a = DEB_DIR + "/partial/" + delta_name
                if not os.path.exists(a):
                    a = None
            if a:
                l = os.path.getsize(a)
                if VERBOSE > 1:
                    logger.debug("  Already here: %r", abs_delta_name)
                s = get_info_fast(a)
                if s:
                    params_of_delta[p.name] = info_2_db(s)
                available_deltas.append((l, p.name, uri, abs_delta_name, newdeb, deb_uri, a, True))
                continue
            # if not, download its first part

            if DO_PROGRESS:
                sys.stderr.write(
                    string.ljust(
                        "%2.1f%% " % (float(progress_count) * 100.0 / len(cache))
                        + _("Downloading head of %s...") % p.name,
                        terminalcolumns,
                    )
                    + "\r"
                )
            deltas_down_time -= time.time()
            status, tempname, l, complete = download_10k_uri(uri, abs_delta_name)
            deltas_down_time += time.time()

            # some strange error in remote server?
            # FIXME this does not support ftp delta repositories
            if status != 200 and status != 206 and status != 404:
                logger.warn("Delta is not downloadable (%s %s):%s", status, http.client.responses.get(status), uri)
                continue

            if status == 404:
                not_available_deltas.append(p.name)
                # check if delta is too big
                if (
                    uri[:7] == "http://" and not proxies and 200 == test_uri(uri + "-too-big")
                ):  # FIXME support ftp or proxies
                    logger.info(_("Delta is too big:") + " " + delta_name)
                    if "b" in DEB_POLICY:
                        no_delta.append((deb_uri, newdeb))
                    elif VERBOSE > 1:
                        logger.debug('  No deb-policy "b", no download of %r', deb_uri)
                    continue
                # check if delta is queued in the server but not yet done
                if (
                    uri[:7] == "http://" and not proxies and 200 == test_uri(uri + "-queued")
                ):  # FIXME support ftp or proxies
                    logger.info(_("Delta is not yet ready in the server:") + " " + delta_name)
                    if "q" in DEB_POLICY:
                        no_delta.append((deb_uri, newdeb))
                    elif VERBOSE > 1:
                        logger.debug('  No deb-policy "q", no download of %r', deb_uri)
                    continue
                # check if delta failed upstream
                if (
                    uri[:7] == "http://" and not proxies and 200 == test_uri(uri + "-fails")
                ):  # FIXME support ftp or proxies
                    logger.info(_("Delta missing, server failed to create it:") + " " + delta_name)
                    if "f" in DEB_POLICY:
                        no_delta.append((deb_uri, newdeb))
                    elif VERBOSE > 1:
                        logger.debug('  No deb-policy "f", no download of %r', deb_uri)
                    continue
                # FIXME the server is not generating these stamps !
                # if  uri[:7] == 'http://' and not proxies and newsize <=  2 * MIN_DEB_SIZE : # check only on small packages
                #  smallstatus = test_uri(uri+'-smalldeb')
                #  if smallstatus == 200: ETC ETC
                ###
                # packages smaller than MIN_DEB_SIZE are ignored by the server.
                if newsize <= MIN_DEB_SIZE:  # check only on small packages
                    logger.info(_("Delta was not created since new package is too small:") + " " + delta_name)
                    if "t" in DEB_POLICY:
                        no_delta.append((deb_uri, newdeb))
                    elif VERBOSE > 1:
                        logger.debug('  No deb-policy "t", no download of %r', deb_uri)
                    continue
                if DEBUG and VERBOSE:
                    logger.info(_("Delta is not present:") + " " + uri)
                else:
                    logger.info(_("Delta is not present:") + " " + delta_name)
                if "u" in DEB_POLICY:
                    no_delta.append((deb_uri, newdeb))
                elif VERBOSE > 1:
                    logger.debug('  No deb-policy "u", no download of %r', deb_uri)
                continue

            if VERBOSE > 1:
                logger.debug("Delta is present: %r %r", delta_name, tempname)
            elif DO_PROGRESS:
                sys.stderr.write(
                    string.ljust(
                        "%2.1f%%" % (float(progress_count) * 100.0 / len(cache)) + _("Downloaded head of %s.") % p.name,
                        terminalcolumns,
                    )
                    + "\r"
                )

            if os.path.isfile(tempname):
                deltas_down_size += os.path.getsize(tempname)

            # parse file and save info
            try:
                s = get_info_fast(tempname)
            except DebDeltaError:
                e = sys.exc_info()[1]
                logger.error("!!" + str(e) + "\n")
                logger.error("!! (renamed to " + tempname + "~~NOT~A~DELTA~~  )\n")
                os.rename(tempname, tempname + "~~NOT~A~DELTA~~")
                if proxies:
                    logger.error("!!maybe a proxy is returning an error page??\n")
                else:
                    logger.error("!!damaged delta??\n")
                continue
            if s:
                params_of_delta[p.name] = info_2_db(s)
                s = patch_check_tmp_space(params_of_delta[p.name], "/")
                if not s:
                    logger.warn("%r : sorry %r", p.name, s)
                    # neither download deb nor delta..
                    # the user may wish to free space and retry
                    continue
            # FIXME may check that parameters are conformant to what we expect

            if complete:
                patching_queue.put((p.name, abs_delta_name, newdeb, deb_uri))
            else:
                available_deltas.append((l, p.name, uri, abs_delta_name, newdeb, deb_uri, tempname, complete))
    # end of first merry-go-round

    available_deltas.sort()

    if DEBUG or VERBOSE:
        if DO_PROGRESS:
            sys.stderr.write(" " * terminalcolumns + "\r")
        logger.info(
            " "
            + _("Deltas: %(present)d present and %(absent)d not,")
            % {"present": len(available_deltas), "absent": len(not_available_deltas)}
        )
        logger.info(
            " "
            + _("downloaded so far: time %(time).2fsec, size %(size)s, speed %(speed)4s/sec.")
            % {
                "time": deltas_down_time,
                "size": SizeToKibiStr(deltas_down_size),
                "speed": SizeToKibiStr(deltas_down_size / float(deltas_down_time + 0.001)),
            }
        )
        if available_deltas:
            logger.info(" " + _("Need to get %s of deltas."), SizeToKibiStr(sum([a[0] for a in available_deltas])))

    # check available space
    a = freespace("/var/cache/apt/archives") / 1024
    b = sum([int(s.get("NEW/Installed-Size", "0")) for s in list(params_of_delta.values())])
    c = sum([int(s.get("NEW/Size", "0")) for s in list(params_of_delta.values())]) / 1024
    if DEB_FORMAT == "deb" and a < c:
        logger.warn("**" + _("Very low disk space, need %(need)d kB have %(have)d kB"), {"need": c, "have": a})
    if DEB_FORMAT == "unzipped" and a < b:
        logger.warn("**" + _("Very low disk space, need %(need)d kB have %(have)d kB"), {"need": b, "have": a})

    # start  progress thread

    def print_progress(common_db):
        while sys and "STOP" not in common_db:
            sys.stderr.write(progress_string(common_db) + "\r")
            time.sleep(0.2)

    if DO_PROGRESS and terminalcolumns > 4:
        progress_thread = threading.Thread(target=print_progress, args=(thread_returns,))
        progress_thread.daemon = True
        progress_thread.start()
    else:
        progress_thread = None

    # second merry-go-round, download rest of available deltas , queue them
    for delta_len, name, uri, abs_delta_name, newdeb, deb_uri, tempname, complete in available_deltas:
        # this seems to create problems....
        # if not os.path.exists(abs_delta_name) and os.path.exists(tempname) and os.path.getsize(tempname) == delta_len:
        #  print 'Just rename:',name #this actually should never happen, but , who knows...
        #  os.rename(tempname,abs_delta_name)
        #  tempname=abs_delta_name

        if name in params_of_delta:
            s = patch_check_tmp_space(params_of_delta[name], "/")
            if not s:
                logger.warn("%r : sorry, %r", name, s)
                # argh, we ran out of space in meantime
                continue

        if not os.path.exists(abs_delta_name):
            thread_returns["downloaduri"] = os.path.basename(uri)
            r = download_uri(uri, abs_delta_name, deltas_down_time, deltas_down_size, thread_returns)
            del thread_returns["downloaduri"]
            if r is None or isinstance(r, http.client.HTTPException):
                if VERBOSE:
                    logger.info(" " + _("You may wish to rerun, to get also:") + " " + uri)
                continue
            else:
                deltas_down_time = r[0]
                deltas_down_size = r[1]

            # queue to apply delta
        if os.path.exists(abs_delta_name):
            # append to queue
            patching_queue.put((name, abs_delta_name, newdeb, deb_uri))
        else:
            if "u" in DEB_POLICY:
                no_delta.append((deb_uri, newdeb))
            elif VERBOSE > 1:
                logger.debug('  No deb-policy "u", no download of %r', deb_uri)
    # end of second merry-go-round

    # terminate queue
    patching_queue.put(None)

    # do something useful in the meantime
    debs_down_size = 0
    debs_down_time = 0
    if patching_thread.isAlive() and no_delta and VERBOSE > 1:
        logger.info("  Downloading deltas done, downloading debs while waiting for patching thread.")
    while patching_thread.isAlive() or ("a" in DEB_POLICY and no_delta):
        if no_delta:
            uri, newdeb = no_delta.pop()
            thread_returns["downloaduri"] = os.path.basename(uri)
            r = download_uri(uri, newdeb, debs_down_time, debs_down_size, thread_returns)
            del thread_returns["downloaduri"]
            if r is None or isinstance(r, http.client.HTTPException):
                if VERBOSE:
                    logger.debug(" You may wish to rerun, to get also: %r", uri)
                continue
            if r:
                debs_down_time = r[0]
                debs_down_size = r[1]
        if not no_delta:
            time.sleep(0.1)

    for i in http_conns:
        if http_conns[i] is not None:
            http_conns[i].close()

    while patching_thread.isAlive():
        time.sleep(0.1)

    # terminate progress report
    thread_returns["STOP"] = True
    while progress_thread is not None and progress_thread.isAlive():
        time.sleep(0.1)

    if DO_PROGRESS:
        sys.stderr.write(" " * terminalcolumns + "\r")

    total_time += time.time()
    logger.info(_("Delta-upgrade statistics:"))
    msg = _("size %(size)s time %(time)dsec speed %(speed)s/sec")
    if VERBOSE:
        if deltas_down_time:
            a = float(deltas_down_size)
            t = deltas_down_time
            logger.info(
                " "
                + _("downloaded deltas, ")
                + msg % {"size": SizeToKibiStr(a), "time": int(t), "speed": SizeToKibiStr(a / t)}
            )
        if thread_returns["debs_time"]:
            a = float(thread_returns["debs_size"])
            t = thread_returns["debs_time"]
            logger.info(
                " "
                + _("patching to debs, ")
                + msg % {"size": SizeToKibiStr(a), "time": int(t), "speed": SizeToKibiStr(a / t)}
            )
        if debs_down_time:
            a = float(debs_down_size)
            t = debs_down_time
            logger.info(
                " "
                + _("downloaded debs, ")
                + msg % {"size": SizeToKibiStr(a), "time": int(t), "speed": SizeToKibiStr(a / t)}
            )
    if total_time:
        a = float(debs_down_size + thread_returns["debs_size"])
        t = total_time
        logger.info(
            " "
            + _("total resulting debs, size %(size)s time %(time)dsec virtual speed %(speed)s/sec")
            % {"size": SizeToKibiStr(a), "time": int(t), "speed": SizeToKibiStr(a / t)}
        )

    if forensics:
        forensic_send(forensics)
    return max(mainexitcodes)

