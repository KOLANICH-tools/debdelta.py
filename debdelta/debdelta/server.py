#!/usr/bin/python

"""Usage: debdelta_server [ -D | -M]  config_file   command

Options:
 -D  daemonize before executing the command
 -M  mail any stdout or stderr to 'email' (see config)

Possible commands:

 backup_Packages                backup all Packages.bz2  from all mirrors
                                in 'mirrorsdir' into  'backup_Packages_dir'

 scan_backups_queue_deltas      scan all Packages.bz2 in 'mirrorsdir' and backups,
                                and queue all deltas that should be created

 start_worker   [--EQE]             worker that creates the deltas
                            --EQE    exit when queue is empty

 backup,queue,worker             as above three

 start_gpg_agent                     starts the agent and loads the gpg key
                                    (FIXME)

 update_popcon                     update cache of popularity contest

 peek_queue                      print the first item in the queue of deltas

 publish                       update html stats, move stuff from transit to server
"""

# Copyright (c) 2013 A. Mennucci
# License: GNU GPL v2

import os, sys, atexit, tempfile
from os.path import join
from copy import copy
import time, string, shutil, pickle, lockfile, logging, logging.handlers
import deltas_history
import deltas_queue
import debdelta
from deltas_queue import SQL_queue, dbapi

try:
    import daemon
except ImportError:
    daemon = None

try:
    import debian.deb822

    debian_deb822 = debian.deb822
except ImportError:
    debian_deb822 = None

logging.basicConfig(format="%(asctime)s %(levelname)-7s %(funcName)s %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)  # this will be changed later on

if os.name == "posix" and sys.version_info[0] < 3:
    try:
        import subprocess32 as subprocess
    except ImportError:
        import subprocess

        logger.warning(' module "subprocess32" unavailable , do not use threads')
else:
    import subprocess

if sys.version_info.major == 2:
    string_types = (str, str)  # python2
else:
    string_types = (str, bytes)  # python3

if len(sys.argv) <= 2:
    sys.stderr.write(__doc__)
    sys.exit(0)

if sys.argv:
    # do this before going into daemon mode, since this changes the CWD
    sys_argv_0_abspath = os.path.abspath(sys.argv[0])
else:
    if __name__ == "__main__":
        raise Exception(" why is sys.argv empty?? ")

args = None
config_abspath = None

# final exit code of this module, if run as a script
return_code = 0
# temporary file to redirect input and output of this module to
temp_out = None

DO_DAEMON = False
DO_MAIL = False

if __name__ == "__main__":
    args = copy(sys.argv[1:])
    while args and args[0] and args[0][0] == "-":
        if args[0] == "--help":
            sys.stderr.write(__doc__)
            sys.exit(0)
        else:
            for j in args[0][1:]:
                if "D" == j:
                    if daemon is None:
                        sys.stderr.write('Sorry, needs "python-daemon" \n')
                        sys.exit(3)
                    DO_DAEMON = True
                elif "M" == j:
                    DO_MAIL = True
                elif "h" == j:
                    sys.stderr.write(__doc__)
                    sys.exit(0)
                else:
                    sys.stderr.write("Unrecognized option, use --help\n")
                    sys.exit(1)
        args = args[1:]

    if len(args) > 1:
        # do this before going into daemon mode, since this changes the CWD
        config_abspath = os.path.abspath(args[0])
        if not os.path.isfile(config_abspath):
            sys.stderr.write("Config_file option is not a file : %r\n" % config_abspath)
            sys.exit(1)
        args = args[1:]
    else:
        sys.stderr.write("Needs a config_file and a command. Use --help \n")
        sys.exit(2)

daemon_context = None
if DO_DAEMON:
    daemon_context = daemon.DaemonContext(umask=0o022)
    daemon_context.open()
    logger.info("Running as PID %d", os.getpid())


# redirect stdin and stderr

email = None


def send_temp_out_as_mail(out):
    out.flush()
    sys.stderr.flush()
    sys.stdout.flush()
    if os.path.getsize(out.name) > 0:
        if logger:
            logger.debug("there was output, sending email")
        if email:
            p = subprocess.Popen(["mail", "-s", repr(args), email], stdin=open(out.name))
            p.wait()
            if p.returncode:
                if logger:
                    logger.warn("email failed, file is %r ", out.name)
            else:
                os.unlink(out.name)
        # else, do not delete the temp file
    else:
        if logger:
            logger.debug("there was no output, not sending email")
        os.unlink(out.name)
    z = open(os.devnull, "a")
    os.dup2(z.fileno(), 1)
    os.dup2(z.fileno(), 2)
    out.close()  # <- warning from here on, output to stdout and stderr are lost


if DO_MAIL:
    if temp_out is None:
        temp_out = tempfile.NamedTemporaryFile(prefix="debdeltas_server_out", delete=False)
        os.dup2(temp_out.fileno(), 1)
        os.dup2(temp_out.fileno(), 2)
        atexit.register(send_temp_out_as_mail, temp_out)


###
# http://stackoverflow.com/questions/36932/how-can-i-represent-an-enum-in-python
# from enum import Enum
class Enum(object):
    def __init__(self, *k):
        pass


def enum(*enums):
    d = dict([(enums[k], k) for k in range(len(enums))])
    return type("Enum", (object,), d)


#####


# configuration
exec(compile(open(config_abspath, "rb").read(), config_abspath, 'exec'))

tmp_dir = tmp_dir.rstrip("/")

debdelta.DEBUG = DEBUG
debdelta.VERBOSE = VERBOSE
debdelta.DO_TEST = DO_TEST
# debdelta.ACT = ACT
debdelta.DO_CACHE = True

debdelta.DO_GPG = True
debdelta.USE_DELTA_ALGO = "xdelta3"
debdelta.GPG_SIGNING_KEY = gnupg_key
debdelta.GPG_HOME = gnupg_home

debdelta.TMPDIR = tmp_dir
debdelta.tempfile.tempdir = tmp_dir
tempfile.tempdir = tmp_dir
os.environ["TMPDIR"] = tmp_dir

if not os.path.exists(lock_dir):
    try:
        os.makedirs(lock_dir)
    except BaseException:
        logger.exception(" while creating %r", lock_dir)
        raise

for d in mirrorsdir, backup_Packages_dir, deltas_www_dir, forensic_www_dir, deltas_transit_dir:
    if not os.path.isdir(d):  # todo: or if cannot write there
        logger.critical("config variable is not a a directory :" + repr(d))
        sys.exit(1)

######

# http://stackoverflow.com/questions/14758299/python-logging-daemon-destroys-file-handle
logger = logging.getLogger(__name__)
logger_hdlr = logging.handlers.RotatingFileHandler(join(logs_dir, "debdeltas_server"), maxBytes=2 ** 24, backupCount=30)
logger_formatter = logging.Formatter("%(asctime)s %(process)d %(levelname)-7s %(funcName)s %(message)s")
logger_hdlr.setFormatter(logger_formatter)
logger.addHandler(logger_hdlr)
logger.setLevel(getattr(logging, logging_level))
debdelta.logger.addHandler(logger_hdlr)
debdelta.logger.setLevel(getattr(logging, logging_level))

if DO_MAIL and temp_out:
    logger.debug("sendind stdout stderr to %r", temp_out.name)


# http://stackoverflow.com/questions/9410760/redirect-stdout-to-logger-in-python
class LoggerWriter(object):
    def __init__(self, prefix="", logger=logger, level=logging.DEBUG):
        self.logger = logger
        self.handler = None
        self.dupfile = None
        for i in logger.handlers:  # look for a handler that has a stream
            if hasattr(i, "stream"):
                self.handler = i
                self.dupfile = os.fdopen(os.dup(self.handler.stream.fileno()), "a")
                break
        if self.dupfile is None:
            logger.error(" cannot find a stream in the logger, send to devnull")
            self.dupfile = open(os.devnull, "w")
        self.level = level
        self.prefix = prefix

    def write(self, message):
        for a in message.split():
            if a:
                self.logger.log(self.level, self.prefix + repr(a))

    def close(self):
        return self.dupfile.close()

    def flush(self):
        return self.dupfile.flush()

    def __str__(self):
        return str(self.dupfile)

    def __repr__(self):
        return repr(self.dupfile)

    def fileno(self):
        return self.dupfile.fileno()


######


def my_subprocess_Popen(cmd, **kwargs):
    if "stdin" not in kwargs:
        kwargs["stdin"] = open(os.devnull)
    if "stdout" not in kwargs:
        kwargs["stdout"] = LoggerWriter(prefix=("%r stdout=" % cmd[0]), level=logging.INFO)
    if "stderr" not in kwargs:
        kwargs["stderr"] = LoggerWriter(prefix=("%r stderr=" % cmd[0]), level=logging.ERROR)
    if "close_fds" not in kwargs:
        kwargs["close_fds"] = True
    return subprocess.Popen(cmd, **kwargs)


######


# Packages files as tuples
# Packages files are often represented as lists, with 7 elements,
# whose meaning is described in this enum.
# We call this representation  LiPa
# Note that the second argument is always 'dists' and the sixth
# is always 'Packages' (this makes debug logging more meaningful)
LiPa_enum = enum("distribution", "dists", "codename", "component", "architecture", "filename", "extension")


def LiPa_find_extension(dirname, li):
    """ given dirname and a LiPa 'li' (of 6 or 7 elements, if 7 the last is ignored),
      find an extension such that the package exists in that dirname;
      returns LiPa with correct extension, or None."""
    if len(li) == 7:
        li = li[:6]
    assert len(li) == 6
    if not os.path.isdir(join(dirname, *(li[:5]))):
        # some suites (e.g.  kfreebsd) do not contain some arches (e.g. amd64)
        logger.warning("No directory for %r %r", dirname, li)
        return None
    a = join(*li)
    for e in (".xz", ".bz2", ".gz", ""):
        if os.path.isfile(join(dirname, a + e)):
            return li + [e]
    logger.warning("No valid extension for LiPa %r in dirname %r", li, dirname)
    return None


def LiPa_to_filename(li, ext=None):
    " Join together a LiPa to provide a filename; optionally with a given extension"
    assert len(li) == 7
    return join(*(li[:-1])) + (ext if ext else li[-1])


def LiPa_to_filename_no_ext(li):
    " Join together a LiPa to provide a filename w/o extension"
    assert len(li) == 7
    return join(*(li[:-1]))


def mirrors_binary_Packages(mirrorsdir=mirrorsdir, archs=architectures):
    """ returns a nested family of dictionaries, indexed succesively
       distribution, codename, component, architecture
     (note that codename may be 'wheezy/updates' )
    the last one contains the LiPa"""
    distrib = {}
    # iterate to list mirrors
    for m in os.listdir(mirrorsdir):
        if os.path.isdir(join(mirrorsdir, m)) and m not in mirrors_exclude:
            distrib[m] = {}
    # iterate to find distributions in mirrors
    for m in distrib:
        magic = "/updates" if m[-8:] == "security" else ""
        # iterate on distribution codenames, such as wheezy, jessie
        for j in os.listdir(join(mirrorsdir, m, "dists")):
            mj = join(mirrorsdir, m, "dists", j)
            if os.path.isdir(mj) and not os.path.islink(mj):
                if (m, j) in codenames_exclude:
                    logger.debug("Skipping %r in %r", j, m)
                else:
                    distrib[m][j + magic] = {}
                # print 'dist',m,j,magic,mj
    # iterate to find binary package lists in distributions in mirrors
    for m in distrib:
        for d in distrib[m]:
            # iterate on components
            for k in components:
                for a in archs:
                    z = LiPa_find_extension(mirrorsdir, [m, "dists", d, k, "binary-" + a, "Packages"])
                    if z:
                        if k not in distrib[m][d]:
                            distrib[m][d][k] = {}
                        distrib[m][d][k][a] = z
                        logger.debug(" Found %r", z)
    return distrib


def iterate_Packages_in_dict_of_mirrors(distrib, mirrorsdir=mirrorsdir):
    for m in distrib:
        for d in distrib[m]:
            for k in components:
                if k in distrib[m][d]:
                    for a in distrib[m][d][k]:
                        yield distrib[m][d][k][a]
                else:
                    logger.debug(" No component %r in %r " % (k, (m, d)))


backup_Packages_lockname = join(lock_dir, "backup_Packages")


def backup_Packages():
    # similar to rfc-3339
    now = time.strftime("%Y-%m-%d_%H:%M:%S", time.gmtime())
    tmpdir = tempfile.mkdtemp(dir=backup_Packages_dir)
    try:
        logger.debug("start")
        with lockfile.FileLock(backup_Packages_lockname, timeout=lock_timeout):
            _backup_Packages(now, tmpdir)
        logger.debug("end")
    except Exception:
        logger.exception("(rm temporaries and reraise exception)")
        if os.path.isdir(tmpdir):
            logger.warn("on exception, deleting tmp dir %r ", tmpdir)
            shutil.rmtree(tmpdir)
        raise
    os.rename(tmpdir, join(backup_Packages_dir, now))


class Release_as_dict(object):
    def __init__(self, a, thehash):
        self.thehash = thehash  # hash used to deduplicate
        if debian_deb822 is not None and a and os.path.isfile(a):
            self.rele = {z["name"]: z[self.thehash] for z in debian_deb822.Release(open(a))[thehash]}
            self.filename = a
            if not self.rele:
                logger.warn("Could not extract hashes %r from %r ", thehash, a)
        else:
            if a:
                logger.warn("file not found:" + repr(a))
            self.rele = {}
            self.filename = None

    def __len__(self):  # used for truth value
        return len(self.rele)

    def get(self, a, b=None):
        return self.rele.get(a, b)


def _backup_Packages(now, where):
    distrib = mirrors_binary_Packages()

    thehash = "sha256"  # hash used to deduplicate
    # changed to sha256 after https://lists.debian.org/debian-devel-announce/2016/03/msg00006.html

    lb = list_backups()  # list previous backups

    if max_backup_age:
        for z in lb[2:]:  # keep at least two backups
            a = join(backup_Packages_dir, z)
            if os.path.getmtime(a) < (time.time() - max_backup_age * 24 * 3600):
                try:
                    logger.info("deleting old backup " + repr(a))
                    shutil.rmtree(a)
                except BaseException:  # swallow exception, if any
                    logger.exception(" while removing tree " + repr(a))

    oldwhere = join(backup_Packages_dir, lb[0]) if lb else None

    NewRelease = {}
    OldRelease = {}
    if debian_deb822 is None:
        logger.warn(" please install package 'python-debian' ")
    for m in distrib:
        for d in distrib[m]:
            # read and copy Release file
            if oldwhere:
                OldRelease[(m, d)] = Release_as_dict(join(oldwhere, m, "dists", d, "Release"), thehash)
            else:
                OldRelease[(m, d)] = Release_as_dict(None, None)
            b = join(mirrorsdir, m, "dists", d, "Release")
            NewRelease[(m, d)] = Release_as_dict(b, thehash)
            if NewRelease[(m, d)]:
                os.makedirs(join(where, m, "dists", d))
                shutil.copy2(b, join(where, m, "dists", d, "Release"))
            if os.path.isfile(b + ".gpg"):
                shutil.copy2(b + ".gpg", join(where, m, "dists", d, "Release.gpg"))
                # check signature. TODO currently if signature fails there is no consequence
                p = my_subprocess_Popen(["gpgv", "-q", b + ".gpg", b], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                e = p.stdout.read()
                p.wait()
                if p.returncode:
                    logger.error(" gpgv failed for " + repr(b) + " message:" + repr(e))
            else:
                logger.error("file not found:" + repr(b + ".gpg"))

    for p in iterate_Packages_in_dict_of_mirrors(distrib):
        os.makedirs(join(where, *(p[:-2])))
        m_d = (p[0], p[2])
        linked_p = None
        fp = LiPa_to_filename(p)
        m_p = join(mirrorsdir, fp)
        n_p = join(where, fp)
        o_p = None
        B = join(*(p[LiPa_enum.component : -1]))  # exclude extension
        new = NewRelease[m_d].get(B)
        if new:
            # save hash in companion file
            open(os.path.splitext(n_p)[0] + "." + thehash, "w").write(new)
        elif NewRelease[m_d]:
            logger.warn(" failed to get %r for %r from new Release %r" % (thehash, B, NewRelease[m_d].filename))
        if oldwhere and new:
            o_p = join(oldwhere, fp)
            if os.path.isfile(o_p):
                old = OldRelease[m_d].get(B)
                if not old:
                    if OldRelease[m_d]:
                        logger.warn(
                            " failed to get %r for %r from old Release %r" % (thehash, B, OldRelease[m_d].filename)
                        )
                elif old == new:
                    linked_p = True
                    logger.debug(" by Release os.link  %r %r ", o_p, n_p)
                    os.link(o_p, n_p)
                else:
                    linked_p = False
            if linked_p is None:
                r = subprocess.call(["cmp", "--quiet", o_p, m_p])
                if r == 0:
                    linked_p = True
                    logger.debug(" by cmp os.link %r %r ", o_p, n_p)
                    os.link(o_p, n_p)
        if not linked_p:
            shutil.copy2(m_p, n_p)
        elif o_p:
            o_c = debdelta.cache_sequence(o_p)
            n_c = debdelta.cache_sequence(n_p)
            if o_c.exists:
                os.link(o_c.cache_filename, n_c.cache_filename)


def list_backups(bPd=backup_Packages_dir):
    "list backups timestamps (that are also subdirectories of 'backup_Packages_dir') sorted, newest first"
    return tuple(
        reversed(
            sorted(
                [
                    a
                    for a in os.listdir(backup_Packages_dir)
                    if (a and os.path.isdir(join(backup_Packages_dir, a)) and a[0] == "2")
                ]
            )
        )
    )  # y3k bug ?


def scan_packages(packages, label, ibpa):
    " 'packages' is a list of tuples (b,p) where p is LiPa and b is timestamp of backup "
    for b, p in packages:
        m = join(mirrorsdir, p[0])
        fil = join(backup_Packages_dir, b, LiPa_to_filename(p))
        logger.debug(" scan  %r %r", b, p)
        for a in debdelta.iterate_Packages(fil, use_debian_822=False):
            a["Label"] = label
            # cheat, the Packages file is in backup_Packages_dir but
            # the pool is in mirrorsdir
            a["Basepath"] = m
            a["Packages_file"] = p  # <- deb822 crashes on this
            a["Timestamp"] = b
            # do note check if the file exists... it will be rechecked
            # if os.path.isfile(join(m,a['Filename'])):
            #    debdelta.info_by_pack_arch_add(a,ibpa)
            # inlined, maybe it is faster
            pack = a["Package"]
            arch = a["Architecture"]
            if (pack, arch) not in ibpa:
                ibpa[(pack, arch)] = []
            ibpa[(pack, arch)].append(a)


def stat_inode(s):
    import stat

    a = os.stat(s)
    return a[stat.ST_INO], a[stat.ST_DEV]


def iter_backups_for_deltas(bPd=backup_Packages_dir):
    VersionCompare = debdelta.init_apt_return_VersionCompare()
    lb = list_backups(bPd)
    if not lb:
        logger.critical(" no backups in " + bPd)
        return
    # iterate on most recent backups of all Packages,
    current_distrib = mirrors_binary_Packages(join(bPd, lb[0]))
    for p in iterate_Packages_in_dict_of_mirrors(current_distrib):
        latest = (lb[0], p)
        logger.info("now working on %r %r", lb[0], p)
        latest_filename = join(bPd, lb[0], LiPa_to_filename(p))
        visited_inodes = [stat_inode(latest_filename)]
        older = []
        # add some previous version of each Packages file
        bj = 1
        while len(older) < max_backups and bj < len(lb):
            # the fields in this list 'a' are as in 'packages_path_as_list_enum' , and such that,
            #  if os.path.joined, a valid fullpath is obtained
            af = join(bPd, lb[bj], LiPa_to_filename(p))
            if os.path.isfile(af):
                ai = stat_inode(af)
                if ai not in visited_inodes:
                    older.append((lb[bj], p))
                    visited_inodes.append(ai)
                    logger.debug(" adding to older version %s for %r", lb[bj], p)
                    bj = bj + skip_backups
                else:
                    if DEBUG >= 2:
                        logger.debug(" skipping duplicate %s for %r", lb[bj], p)
                    bj = bj + 1
            else:
                logger.warn(" missing %s for %r", lb[bj], p)
                bj = bj + 1

        if p[0][-8:] == "security":
            # for security, add also the corresponding stable packages
            q = list(copy(p))
            q[0] = p[0][:-9]
            if p[2][-8:] == "/updates":
                q[2] = p[2][:-8]
            for b in (lb[0],):  # currently we add only the most recent one
                a = LiPa_find_extension(join(bPd, b), q)
                if a:
                    logger.info("and on as well %r %r", b, a)
                    older.append((b, a))
                else:
                    logger.warn(" missing  %r %r", b, q)
        # todo, for stable-updates we should also add stable
        if older:
            count = 0
            logger.debug(" now create list of deltas for %r %r", latest, older)
            info_by_pack_arch = {}
            scan_packages((latest,), "CMDLINE", info_by_pack_arch)
            scan_packages(older, "OLD", info_by_pack_arch)
            logger.debug(" create list of deltas for %r", latest)
            for pa, ar in info_by_pack_arch:
                info_pack = info_by_pack_arch[(pa, ar)]
                # absurdely verbose, lists each single package
                if DEBUG >= 3:
                    logger.debug("   now create list of deltas for %r %r", pa, ar)
                assert info_pack
                for z in debdelta.iter_deltas_one_pack_arch(
                    pa,
                    ar,
                    info_pack,
                    deltas_www_dir + "/" + p[0] + "-deltas//",
                    forensic_www_dir + "//",
                    VersionCompare,
                    loglevel=logging.DEBUG,
                ):
                    count += 1
                    yield z
            logger.info(" yielded %d", count)
        else:
            logger.debug(" no older to create list of deltas for %r", latest)


def scan_backups_for_deltas(bPd=backup_Packages_dir):
    for z in iter_backups_for_deltas(bPd):
        logger.info("%r", z)


class Compute_Priority(object):
    warned = []

    def __init__(self):
        self.warned = []
        self.popcon_dict = {}
        if os.path.isfile(popcon_cache):
            self.popcon_dict = pickle.load(open(popcon_cache))
        else:
            logger.warn(" popcon_cache is unavailable ")

    def __call__(self, old, new):
        " compute priority . A lower number is an higher priority (with 0 being highest priority)"
        # todo fixme: add new package
        m = old["Packages_file"][LiPa_enum.distribution]
        if m not in priority_for_mirrors and m not in self.warned:
            self.warned.append(m)
            logger.warn('mirror %r not in configuration "priority_for_mirrors" ' % m)
        return int(
            priority_for_mirrors.get(m, 0.0) + priority_by_popcon * (1.0 - self.popcon_dict.get(old["Package"], 0.0))
        )


scan_backups_queue_deltas_lockname = join(lock_dir, "scan_backups_queue_deltas")


def scan_backups_queue_deltas(bPd=backup_Packages_dir):
    with lockfile.FileLock(scan_backups_queue_deltas_lockname, timeout=lock_timeout):
        logger.info("start")
        _scan_backups_queue_deltas(bPd)
        logger.info("end")


def _scan_backups_queue_deltas(bPd=backup_Packages_dir):

    compute_priority = Compute_Priority()

    thesqldb = SQL_queue(sqlite3_queue)

    lb = list_backups(bPd)

    # db = dbapi.OPEN(sqlite3_database)

    thesqldb.queue_add_begin()

    for old, new, delta, forensicfile in iter_backups_for_deltas(bPd):
        p = old["Packages_file"]
        priority = compute_priority(old, new)
        shortdelta = delta[len(deltas_www_dir) + 1 :]
        x = thesqldb.queue_peek_delta(shortdelta)
        if x:
            logger.debug("already queued %r as %r ", (priority, old, new, delta, forensicfile), x)
        elif os.path.isfile(delta) or os.path.exists(delta + "-too-big") or os.path.exists(delta + "-fails"):
            # fixme should check also if the new deb is too small
            logger.debug("exists, not queued: %r", (priority, old, new, delta, forensicfile))
        else:
            # this may actually requeue already queued records...
            # it is ok since they will have newer timestamps
            thesqldb.queue_add(priority, old["File"], new["File"], shortdelta, forensicfile)
            logger.debug("queued: %r", (priority, old, new, shortdelta, forensicfile))
            #
            deltadirname = os.path.dirname(delta)
            if not os.path.exists(deltadirname):
                os.makedirs(deltadirname)
            open(delta + "-queued", "w")
    thesqldb.queue_add_commit()


def set_environ_gpg_agent():
    if gnupg_agent_info:
        pass  # keep environment if available
    elif type(gnupg_agent_info) in (str, str):
        if os.path.isfile(gnupg_agent_info):
            gpg_agent_info = open(gnupg_agent_info).readline().strip().split("=")[1]
            os.environ["GPG_AGENT_INFO"] = gpg_agent_info
        else:
            logger.error(" file not found: " + gnupg_agent_info)
    elif gnupg_agent_info == False:
        if "GPG_AGENT_INFO" in os.environ:
            del os.environ["GPG_AGENT_INFO"]
    else:
        logger.warn("configuration variable 'gpg_agent_info' set to a strange value: " + repr(gnupg_agent_info))


def create_one_delta_simple():
    set_environ_gpg_agent()

    thesqldb = SQL_queue(sqlite3_queue)
    x = thesqldb.queue_pop()
    E = thesqldb.fields_enum
    if x is None:
        logger.info("queue is empty")
    elif os.path.isfile(x[E.delta]):
        logger.info("already exists, skipped", x[E.delta])
    else:
        ret = debdelta.do_delta_and_test(*(x[2:6]))  # <- skip id and priority
        if 0 < ret[0]:
            logger.warn("failed %r", x[E.delta])
            # FIXME, REQUE


worker_creates_deltas_lockname = join(lock_dir, "worker_creates_deltas")


def worker_creates_deltas(exit_when_queue_empty=False):
    with lockfile.FileLock(worker_creates_deltas_lockname, timeout=lock_timeout) as L:
        logger.debug("start , EQE=%r" % exit_when_queue_empty)
        open(L.path, "w").write(pickle.dumps({"exit_when_queue_empty": exit_when_queue_empty, "pid": os.getpid()}))
        _worker_creates_deltas(exit_when_queue_empty=exit_when_queue_empty)
        logger.debug("end")
        if os.path.exists(L.path):
            os.unlink(L.path)


def create_one_delta_from_queue(x, y, thesqldb):
    ret = None
    now = int(time.time())
    E = thesqldb.fields_enum
    if x[E.ctime] < (now - max_queue_age * 24 * 3600):
        logger.debug("queue item too old %r", x[E.delta])
    elif not os.path.isfile(x[E.old_name]):
        logger.warn("missing old deb %r for %r", x[E.old_name], x[E.delta])
    elif not os.path.isfile(x[E.new_name]):
        logger.warn("missing new deb %r for %r", x[E.new_name], x[E.delta])
    # check in server
    elif os.path.isfile(x[E.delta]):
        logger.info("already available delta %r", x[E.delta])
    elif os.path.isfile(x[E.delta] + "-too-big"):
        logger.info("tried, too big, delta %r", x[E.delta])
    elif os.path.isfile(x[E.delta] + "-fails"):
        logger.info("tried, it failed, delta %r", x[E.delta])
    # check in transit
    elif os.path.isfile(y[E.delta]):
        logger.info("already available delta %r", y[E.delta])
    elif os.path.isfile(y[E.delta] + "-too-big"):
        logger.info("tried, too big, delta %r", y[E.delta])
    elif os.path.isfile(y[E.delta] + "-fails"):
        logger.info("tried, it failed, delta %r", y[E.delta])
    # all fine, go create
    else:
        try:
            ret = debdelta.do_delta_and_test(*(y[2:6]))
        except (SystemExit, KeyboardInterrupt):
            # python-daemon will raise this on sigterm
            logger.warning("while do_delta_and_test , SystemExit or KeyboardInterrupt")
            try:
                if x:
                    thesqldb.queue_add(*(x[1:]))
            except BaseException:
                logger.exception("while requeueing %r", x)
            raise
        except Exception:
            logger.exception("while do_delta_and_test on %r", x)
            # do not reque
            if x and os.path.exists(x[E.delta] + "-queued"):
                os.unlink(x[E.delta] + "-queued")
    return ret


def _worker_creates_deltas(exit_when_queue_empty=False):
    set_environ_gpg_agent()
    created = []
    last_publishing = time.time()
    thesqldb = SQL_queue(sqlite3_queue)
    E = thesqldb.fields_enum
    publish = Publisher(publisher)
    if sqlite3_history:
        thesqlhistory = deltas_history.SQL_history(sqlite3_history)
    else:
        thesqlhistory = None
    #
    moved = move_from_transit_to_server()
    update_html()
    publish.start(moved)
    #
    while True:
        x = None
        try:
            x = thesqldb.queue_pop()
            if x is None and exit_when_queue_empty:
                logger.info("queue empty, exiting")
                break
        except dbapi.OperationalError:
            logger.exception(" sqlite3 OperationalError ")
        if True:
            if x is None:  # queue is empty, or error
                time.sleep(60)
            else:
                y = list(x)
                x = list(x)
                delta = x[E.delta]
                shortdelta = delta[len(deltas_www_dir) + 1 :] if delta[0] == "/" else delta
                x[E.delta] = join(deltas_www_dir, shortdelta)
                y[E.delta] = join(deltas_transit_dir, shortdelta)
                ret = None
                try:
                    ret = create_one_delta_from_queue(x, y, thesqldb)
                except (SystemExit, KeyboardInterrupt):
                    break
                if ret:
                    if 0 == ret[0]:
                        logger.info("created %r", shortdelta)
                        if os.path.exists(y[E.delta]):  # do not append if the delta was too big
                            created.append(x[E.delta])
                    else:
                        logger.warn("failed %r", shortdelta)
                        # FIXME REQUEUE if r == 1 , in case recreate timestamp
                append_to_sql_history(x, ret, E, thesqlhistory)
            if publish.poll() is not None and (
                (created and time.time() > publisher_interval + last_publishing)
                or len(created) > publisher_flush_deltas
            ):
                publish.wait()
                move_from_transit_to_server()
                update_html()
                publish.start(created)
                created = []
                last_publishing = time.time()
            else:
                time.sleep(0.0001)
    #
    publish.wait()
    move_from_transit_to_server()
    update_html()
    publish.start()
    publish.wait()


def move_from_transit_to_server():
    p = subprocess.Popen(
        ["find", "-type", "f", "-not", "-name", "*_tmp_"], cwd=deltas_transit_dir, stdout=subprocess.PIPE
    )
    moved = []
    ndequeud = 0
    for j in p.stdout:
        j = j[:-1]
        delta = join(deltas_www_dir, j)
        deltadirname = os.path.dirname(delta)
        if not os.path.exists(deltadirname):
            os.makedirs(deltadirname)
        logger.debug("moving from transit %r", j)
        shutil.move(join(deltas_transit_dir, j), delta)
        moved.append(delta)
        a, b = os.path.splitext(delta)
        a += ".debdelta-queued"
        if os.path.isfile(a):
            logger.debug("removing from server %r", a)
            os.unlink(a)
            ndequeud += 1
    logger.info("moved %d files from transit, %d queue timestamps removed", len(moved), ndequeud)
    p.wait()
    return moved


def append_to_sql_history(x, ret, x_fields_enum, thesqlhistory):
    if x and ret and thesqlhistory:
        E = x_fields_enum
        try:
            (error_code, delta_size, delta_elaps, patch_elaps, info_delta, error_string) = ret
            info_delta_db = debdelta.info_2_db(info_delta)
            thesqlhistory.add(
                None,  # it is difficult to recover the distribution here
                info_delta_db.get("OLD/Package"),
                info_delta_db.get("OLD/Architecture"),
                info_delta_db.get("OLD/Version"),
                info_delta_db.get("NEW/Version"),
                os.path.getsize(x[E.old_name]) if x[E.old_name] else None,
                os.path.getsize(x[E.new_name]) if x[E.new_name] else None,
                x[E.delta][len(deltas_www_dir) + 1 :] if x[E.delta] else None,
                delta_size,
                delta_elaps,
                patch_elaps,
                x[E.forensic][len(forensic_www_dir) + 1 :] if x[E.forensic] and os.path.exists(x[E.delta]) else None,
                error_string,
                None,
                1,
                os.getloadavg()[0],
            )
        except (SystemExit, KeyboardInterrupt):
            raise
        except BaseException:
            logger.exception("error while adding to history")


def update_html():
    try:
        if sqlite3_history and sqlite3_history_html:
            logger.debug("updating %r", sqlite3_history_html)
            deltas_history.html_one_day(sqlite3_history, sqlite3_history_html)
    except BaseException:
        logger.exception("error while creating %r", sqlite3_history_html)
    try:
        if sqlite3_queue_html:
            logger.debug("updating %r", sqlite3_queue_html)
            deltas_queue.html(sqlite3_queue, sqlite3_queue_html)
    except BaseException:
        logger.exception("error while creating %r", sqlite3_queue_html)
    try:
        if sqlite3_web_log:
            shutil.copy(join(logs_dir, "debdeltas_server"), sqlite3_web_log)
    except BaseException:
        logger.exception("error while creating %r", sqlite3_web_log)


class Publisher(object):
    def __init__(self, publisher):
        self.publisher = publisher
        self.proc = None
        self.returncode = False  # False means not process , None means process running
        self.created = None
        self.args = None
        self.now = 0

    def start(self, created=[]):
        if not self.publisher:
            return
        if self.proc:
            logger.warn(" publisher is already running, cannot run twice")
            return
        if os.path.isfile(publisher):
            logger.info("publish")
            self.now = time.time()
            args = [self.publisher, config_abspath]
            self.args = args
            self.created = created
            p = my_subprocess_Popen(args + created)
            self.proc = p
            self.returncode = None
            return p
        else:
            logger.warn(" does not exists: " + publisher)

    def poll(self):
        if not self.proc:
            return self.returncode
        self.returncode = self.proc.poll()
        self._log_publishing()
        return self.returncode

    def wait(self):
        if not self.proc:
            # no use warning here ... logger.warn(' publisher is not running')
            return self.returncode
        self.returncode = self.proc.wait()
        self._log_publishing()
        return self.returncode

    def _log_publishing(self):
        if self.proc and self.returncode is not None:
            if self.returncode:
                logger.error("failed: exitstatus %r args %r deltas %r", self.returncode, self.args, self.created)
            else:
                if self.created:
                    logger.info(" sent %d deltas in %d seconds", len(self.created), time.time() - self.now)
                else:
                    logger.info(" full sync in %d seconds", time.time() - self.now)
            self.proc = None


def update_popcon():
    " prepare a cache in popcon_cache, a pickle of a dict where keys are names of packages, and values\
    are popularity, normalized so that maximum popularity is 1.0 "
    import pickle as pickle

    popcon_dict = {}
    maximum = None
    for a in my_subprocess_Popen(popcon_update_command, shell=True, stdout=subprocess.PIPE).stdout:
        if not a or a[0] == "#":
            continue
        b = [c for c in a.split() if c]
        if len(b) < 2 or b[1] == "Total":
            continue
        p, v = b[1], b[2]
        if maximum is None:
            maximum = float(v)
        v = float(v) / maximum
        # skip too small values
        if v < (0.5 / float(priority_by_popcon)):
            continue
        # a lower number is an higher priority later on
        popcon_dict[p] = v
    if popcon_dict:
        # if there was a network error, avoid overwriting
        logger.info("parsed popcon file, %d relevant entries" % len(popcon_dict))
        pickle.dump(popcon_dict, open(popcon_cache + "~~", "w"))
        os.rename(popcon_cache + "~~", popcon_cache)
    else:
        logger.error("failed to download or parse file")


def daemonize_maybe_mail(cmdname, cmd, *args, **kw):
    " now unused"
    if daemon is None:
        logger.error('Sorry, needs "python-daemon" ')
        sys.exit(3)
    if not os.path.isdir(lock_dir):
        os.makedirs(lock_dir)
    # http://www.python.org/dev/peps/pep-3143/
    try:
        sys.stdout.flush()
        sys.stderr.flush()
        out = tempfile.NamedTemporaryFile(delete=False)
        outerr = os.fdopen(os.dup(out.fileno()), "w")
        with daemon.DaemonContext(
            stdout=out,
            stderr=outerr,
            umask=0o022,
            files_preserve=[out, outerr, logger_hdlr.stream],
            pidfile=lockfile.FileLock(join(lock_dir, cmdname)),
        ):
            logger.info("start " + cmdname)
            try:
                cmd(*args, **kw)
            except SystemExit:
                logger.warn("SystemExit from " + cmdname + " , output in " + out.name)
                raise
            except Exception:
                logger.exception(cmdname + "--daemonized")
                logger.warn("output was left in " + out.name)
                raise
            logger.info("end " + cmdname)

        sys.stdout.close()
        sys.stderr.close()
        sys.stdout = os.open(os.devnull, os.O_RDWR)
        sys.stderr = os.open(os.devnull, os.O_RDWR)
        outerr.close()
        out.close()  # <- warning from here on, output to stdout and stderr are lost
        if os.path.getsize(out.name) > 0:
            logger.debug("there was output, sending email")
            p = my_subprocess_Popen(["mail", "-s", cmdname, email], stdin=subprocess.PIPE)
            o = open(out.name)
            for a in o:
                p.stdin.write(a)
            p.stdin.close()
            p.wait()
            if p.returncode:
                logger.warn("email failed")
        os.unlink(out.name)

    except SystemExit:
        raise
    except Exception:
        logger.exception(cmdname)


def start_gpg_agent():
    # ignore environment ?
    # gpg_agent_info=os.getenv('GPG_AGENT_INFO')
    del os.environ["GPG_AGENT_INFO"]
    gpg_agent_info = None
    if os.path.isfile(gnupg_agent_info_file):
        gpg_agent_info = open(gnupg_agent_info_file).readline().strip().split("=")[1]
    if gpg_agent_info:
        if not os.path.exists(gpg_agent_info.split(":")[0]):
            logger.warn(" agent info is obsolete %r", gpg_agent_info)
            gpg_agent_info = None
    if gpg_agent_info:
        os.environ["GPG_AGENT_INFO"] = gpg_agent_info
        r = subprocess.call(["gpg-agent"])
        if r:
            logger.warn(" agent is not happy ")
            gpg_agent_info = None
            del os.environ["GPG_AGENT_INFO"]
    if gpg_agent_info:
        logger.info("using existing agent %r", gpg_agent_info)
    else:
        r = subprocess.call(
            ["gpg-agent", "--homedir", gnupg_home, "--daemon", "--write-env-file", gnupg_agent_info_file]
        )
        if r:
            logger.error("starting agent failed: %r", r)
            return 4
        gpg_agent_info = open(gnupg_agent_info_file).readline().strip().split("=")[1]
        logger.info("started agent %r", gpg_agent_info)

    os.environ["GPG_AGENT_INFO"] = gpg_agent_info
    n = tempfile.NamedTemporaryFile(delete=False)
    n.write("pippo\n")
    n.close()

    r = subprocess.Popen(
        [
            "gpg",
            "--quiet",
            "--batch",
            "--homedir",
            gnupg_home,
            "-o",
            "/dev/null",
            "--default-key",
            gnupg_key,
            "--sign",
            n.name,
        ],
        stdin=sys.stdin,
        stderr=sys.stderr,
        stdout=sys.stdout,
    )
    if r:
        sys.stderr.write("test signing fails " + repr(r) + "\n")
    os.unlink(n.name)


####


def daemon_test(a="foobar"):
    logger.info(a)
    os.system("date")
    time.sleep(60)


#########################################################
def main():
    if not args:
        if __name__ == "__main__":
            sys.stderr.write("Please provide a command. Use -h\n")
            sys.exit(2)

    elif args[0] == "backup_Packages":
        backup_Packages()

    elif args[0] == "scan_backups_for_deltas":
        scan_backups_for_deltas()

    elif args[0] == "scan_backups_queue_deltas":
        scan_backups_queue_deltas()

        # kept for backward compatibility
    elif args[0] == "backup_then_scan_and_queue_deltas" and not DO_DAEMON:
        os.execv(sys_argv_0_abspath, ["-D", config_abspath, "backup,queue,worker"])

    elif args[0] == "start_worker_d":
        f = len(args) > 1 and args[1] == "--EQE"
        if not DO_DAEMON:
            os.execv(sys_argv_0_abspath, ["-D", config_abspath] + args)
        else:
            worker_creates_deltas(exit_when_queue_empty=f)
        # end of stuff for backward compatibility

    elif args[0] in ("backup,queue,worker", "backup_then_scan_and_queue_deltas"):
        backup_Packages()
        scan_backups_queue_deltas()
        L = lockfile.FileLock(worker_creates_deltas_lockname)
        D = {}
        if L.is_locked():
            try:
                D = pickle.load(open(L.path))
            except BaseException:
                logger.exception(" while reading lock info %r", L.path)
            if D.get("exit_when_queue_empty"):
                # after this time, either it has exited, or it has noted that other deltas have been queued
                time.sleep(120)
            else:
                logger.debug(" backup,queue,worker : a persistent worker is present, exiting")
        if not L.is_locked():
            worker_creates_deltas(exit_when_queue_empty=True)

    elif args[0] == "start_worker":
        f = len(args) > 1 and args[1] == "--EQE"
        worker_creates_deltas(exit_when_queue_empty=f)

    elif args[0] == "update_popcon":
        update_popcon()

    elif args[0] == "peek_queue":
        thesqldb = SQL_queue(sqlite3_queue)
        logger.info(thesqldb.queue_peek())

    elif args[0] == "create_one_delta":
        create_one_delta_simple()

    elif args[0] == "daemonize_test":
        daemon_test("barfoo")

    elif args[0] == "start_gpg_agent":
        return_code = start_gpg_agent()

    elif args[0] == "publish":
        publish = Publisher(publisher)
        update_html()
        move_from_transit_to_server()
        publish.start()
        publish.wait()

    elif "--help" in args or "-h" in args:
        sys.stderr.write(__doc__)
        sys.exit(0)
    else:
        sys.stderr.write("Command not recognized. Use -h \n")
        sys.exit(2)
    raise SystemExit(return_code)

if __name__ == "__main__":
    main()

