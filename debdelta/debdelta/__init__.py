#!/usr/bin/python

# Copyright (C) 2006-09 Andrea Mennucci.
# License: GNU Library General Public License, version 2 or later

import sys, os, tempfile, string, getopt, tarfile, shutil, time, traceback
import subprocess, time, tarfile, stat, hashlib, random, gzip

from string import join
import logging.handlers
import logging
from stat import ST_SIZE, ST_MTIME, ST_MODE, S_IMODE, S_IRUSR, S_IWUSR, S_IXUSR
from types import FunctionType, LambdaType
from copy import copy
from os.path import abspath, expanduser

EMAIL = "mennucc1@debian.org"

#### messages and translations
# Early errors (such as errors in args parsing) are printed on stderr.
# Subsequent errors,warnings,messages are printed on stdout,using the 'logging' facility
# but the progress bars are on stderr

# Messages printed at verbosity 0 or 1 are translated, higher verbosities are not
# Errors are sometimes translated, sometimes not...
#  obscure error messages that would be printed only in very rare cases are not translated
#    e.g.: a malformed http header, a gnupg unexptected error, damaged input files...
#  more common error messages are translated,
#    e.g.: out of disk space while using debdelta-upgrade , file does not exist...

try:
    import gettext

    gettext.bindtextdomain("debdelta", "/usr/share/locale")
    gettext.textdomain("debdelta")
    _ = gettext.gettext
except Exception:
    a = sys.exc_info[1]
    sys.stderr.write('Could not initialize "gettext", translations will be unavailable\n' + str(a))

    def _(x):
        return x


doc = {}
doc["delta"] = _(
    """\
Usage: debdelta [ option...  ] fromfile tofile delta
  Computes the difference of two deb files, from fromfile to tofile, and writes it to delta

Options:
--signing-key KEY
            gnupg key used to sign the delta
--no-md5    do not include MD5 info in delta
--needsold  create a delta that can only be used if the old deb is available
 -M Mb      maximum memory  to use (for 'bsdiff' or 'xdelta')
--delta-algo ALGO
            use a specific backend for computing binary diffs
""")


doc["deltas"] = _("""\
Usage: debdeltas [ option...  ]  [deb files and dirs, or 'Packages' files]
  Computes all missing deltas for deb files.
  It orders by version number and produce deltas to the newest version

Options:
--signing-key KEY
            key used to sign the deltas (using GnuPG)
--dir DIR   force saving of deltas in this DIR
            (otherwise they go in the dir of the newer deb_file)
--old ARGS  'Packages' files containing list of old versions of debs
--alt ARGS  for any cmdline argument, search for debs also in this place
 -n N       how many deltas to produce for each deb (default unlimited)
--no-md5    do not include MD5 info in delta
--needsold  create a delta that can only be used if the old .deb is available
--delta-algo ALGO
            use a specific backend for computing binary diffs;
            possible values are: xdelta xdelta-bzip xdelta3 bsdiff
 -M Mb      maximum memory to use (for 'bsdiff' or 'xdelta')
--clean-deltas     delete deltas if newer deb is not in archive
--cache     cache parsed version of Packages.bz2 as Packages.debdelta_cache
""")

# implement : --search    search in the directory of the above debs for older versions

doc["patch"] = _("""\
Usage: debpatch [ option...  ] delta  fromfile  tofile
  Applies delta to fromfile and produces a reconstructed  version of tofile.

(When using 'debpatch' and the old .deb is not available,
  use the unpack directory, usually '/', for the fromfile.)

Usage: debpatch --info delta
  Write info on delta.

Options:
--no-md5   do not verify MD5 (if found in info in delta)
 -A        accept unsigned deltas
--format FORMAT
           format of created deb
""")

doc["delta-upgrade"] = _("""\
Usage: debdelta-upgrade [package names]
  Downloads all deltas and apply them to create the debs
  that are needed by 'apt-get upgrade'.

Options:
--dir DIR   directory where to save results
--deb-policy POLICY
            policy to decide which debs to download,
 -A         accept unsigned deltas
--format FORMAT
            format of created debs
--timeout SECONDS
            adjust timeout for connections, default is
            15 seconds
""")

doc["patch-url"] = _("""\
Usage: debpatch-url [package names]
  Show URL wherefrom to downloads all deltas that may be used to upgrade the given package names
""")

doc_common = _("""\
 -v         verbose (can be added multiple times)
--no-act    do not do that (whatever it is!)
 -d         add extra debugging checks
 -k         keep temporary files (use for debugging)
--gpg-home HOME
            specify a different home for GPG

See man page for more options and details.
""")

minigzip = "/usr/lib/debdelta/minigzip"
minibzip2 = "/usr/lib/debdelta/minibzip2"


####################################################################


try:
    import ConfigParser
except ImportError:
    import configparser


try:
    import debian.deb822

    debian_deb822 = debian.deb822
except ImportError:
    debian_deb822 = None

try:
    import cPickle as pickle
except ImportError:
    import pickle


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger(__name__)

if sys.version_info.major == 2:
    string_types = (str, unicode)  # python2
else:
    string_types = (str, bytes)  # python3


def get_termsize():
    import termios
    import fcntl
    import struct

    s = struct.pack("HHHH", 0, 0, 0, 0)
    fd_stdout = sys.stdout.fileno()
    x = fcntl.ioctl(fd_stdout, termios.TIOCGWINSZ, s)
    return struct.unpack("HHHH", x)[:2]


try:
    (terminalrows, terminalcolumns) = get_termsize()
except BaseException:
    (terminalrows, terminalcolumns) = (None, None)  # (24, 80)

# main program, read options

# target of: maximum memory that bsdiff will use
MAXMEMORY = 1024 * 1024 * 50

# this is +-10% , depending on the package size
MAX_DELTA_PERCENT = 70

# min size of .deb that debdelta will consider
# very small packages cannot be effectively delta-ed
MIN_DEB_SIZE = 10 * 1024


N_DELTAS = None

USE_DELTA_ALGO = "bsdiff"

TIMEOUT = 15
DEBUG = 0
VERBOSE = 0
KEEP = False
INFO = False
NEEDSOLD = False
DIR = None
ALT = []
OLD = []
ACT = True
DO_MD5 = True
DEB_POLICY = ["b", "s", "e", "t", "f", "q"]
DO_PROGRESS = terminalcolumns is not None and __name__ == "__main__"

# where/how debpatch/debdelta-upgrade will send forensic data, when patching fails
# possible values:
#  False                 : do not send them
#  True                  : compute forensic but not send them, just list them
#  mail                  : automatically send by email to default address
#  user@domain           : automatically send by email to address
#  mailto:user@domain    : as above
#  mutt:user@domain      : as above, but use 'mutt', so the user can customize it
#  http://domain/cgi     : send them automatically thru a CGI script
# Warning: the above is mostly TODO
FORENSIC = "http"

# directory tree where forensic info are stored by 'debdeltas'
FORENSICDIR = None

DEB_FORMAT = "deb"
DEB_FORMAT_LIST = ("deb", "unzipped", "preunpacked")  # not yet implemented on patching side :  (,'piped')

# for debdeltas: test patches internally
DO_TEST = False

DO_GPG = True  # this is changed a few lines below
GPG_SIGNING_KEY = None
if os.getuid() == 0:
    GPG_HOME = "/etc/debdelta/gnupg"
else:
    GPG_HOME = None
GPG_MASTER_PUB_KEYRING = "/usr/share/keyrings/debian-debdelta-archive-keyring.gpg"

GPG_CMD = "gpg"
if os.path.exists("/usr/bin/gpg2"):
    GPG_CMD = "/usr/bin/gpg2"

CLEAN_DELTAS = False
CLEAN_DELTAS_MTIME = 2  # two days grace period
CLEAN_ALT = False

DO_PREDICTOR = False

DO_CACHE = False  # cache parsed version of Packages.bz2 as Packages.debdelta_cache

# see README.features
DISABLEABLE_FEATURES = ["xz", "lzma", "xdelta3-fifo"]
DISABLED_FEATURES = []

HTTP_USER_AGENT = {"User-Agent": "Debian debdelta-upgrade"}


DPKG_MULTIARCH = 0 == os.system("dpkg --assert-multi-arch 2> /dev/null")

action = None
for i in DISABLED_FEATURES:
    if i not in DISABLEABLE_FEATURES:
        sys.stderr.write(_("Error: feature `%s' cannot be disabled.") % i + "\n")
        raise SystemExit(3)

try:
    BOGOMIPS = float(
        subprocess.Popen("grep bogomips /proc/cpuinfo", shell=True, stdout=subprocess.PIPE).stdout.read().split(":")[-1]
    )
except BaseException:
    if VERBOSE:
        sys.stderr.write(" Warning, /proc not mounted, using bogus BOGOMIPS\n")
    BOGOMIPS = 3000.0

SP = subprocess.Popen(["hostname", "-f"], shell=False, stdout=subprocess.PIPE)
HOSTID = hashlib.md5(SP.stdout.read()).hexdigest()
SP.wait()
del SP

TMPDIR = (os.getenv("TMPDIR") or "/tmp").rstrip("/")

if KEEP:

    def unlink(a):
        if VERBOSE > 2:
            logger.debug("   -k: would unlink " + repr(a))

    def rmdir(a):
        if VERBOSE > 2:
            logger.debug("   -k: would rmdir " + repr(a))

    def rmtree(a):
        if VERBOSE > 2:
            logger.debug("   -k: would rm -r " + repr(a))


else:

    def __wrap__(a, cmd):
        c = cmd.__name__ + "(" + a + ")"
        if a[: len(TMPDIR) + 9] != TMPDIR + "/debdelta":
            raise DebDeltaError("Internal error! refuse to  " + c)
        try:
            cmd(a)
        except OSError:
            logger.exception(" Warning! when trying to " + repr(c) + " got OSError ")
            raise

    def unlink(a):
        return __wrap__(a, os.unlink)

    def rmdir(a):
        return __wrap__(a, os.rmdir)

    def rmtree(a):
        return __wrap__(a, shutil.rmtree)


# various routines


def my_popen_read(cmd):
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=open(os.devnull), close_fds=True).stdout


def freespace(w):
    assert os.path.exists(w)
    try:
        a = os.statvfs(w)
        freespace = long(a[0]) * long(a[4])
    except Exception:
        logger.exception("Statvfs error on %r", w)
        freespace = None
    return freespace


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
    a = p.readline()
    while a:
        a = de_n(a)
        if a[:4] in ("Pack", "Vers", "Arch", "Stat", "Inst", "File"):
            if info is not None:
                info.append(prefix + a)
            if params is not None:
                i = a.index(":")
                assert a[i : i + 2] == ": "
                params[prefix + a[:i]] = a[i + 2 :]
        a = p.readline()


def append_info(delta, info):
    "insert into the delta (that is an AR archive) the info file, as a first element, possibly removing a previous occurrence"
    # new style : special info file
    TD = abspath(tempfile.mkdtemp(prefix="debdelta", dir=TMPDIR))
    infofile = open(TD + "/info", "w")
    for i in info:
        infofile.write(i + "\n")
    infofile.close()
    if DO_GPG:
        r = _compute_hashes_(TD + "/info")
    else:
        r = None
    system(["ar", "rSi", "0", delta, "info"], TD)
    rmtree(TD)
    return r


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


def list_ar(f):
    assert os.path.exists(f)
    ar_list = []
    p = my_popen_read("ar t " + f)
    while True:
        a = p.readline()
        if not a:
            break
        a = de_n(a)
        ar_list.append(a)
    p.close()
    return ar_list


def list_tar(f):
    assert os.path.exists(f)
    ar_list = []
    p = my_popen_read("tar t " + f)
    while True:
        a = p.readline()
        if not a:
            break
        a = de_n(a)
        ar_list.append(a)
    p.close()
    return ar_list


def untar_control_in_deb(ar_ls):
    " ar_ls is usually list_ar(n) ; it returns  (c , b, z) \
    where c 'name of control' , b 'option for tar' , z 'unzip command' "
    c = None
    for a in ar_ls:
        if a[:12] == "control.tar.":
            c = a
    assert c
    # command for tar
    bdb = {".gz": "-z", ".bz2": "-j", ".lzma": "--lzma", ".xz": "-J"}
    zdb = {".gz": ["gzip", "-cd"], ".bz2": ["bzip2", "-cd"], ".lzma": ["unlzma", "-c"], ".xz": ["unxz", "-c"]}
    return c, bdb.get(c[11:]), zdb.get(c[11:])


class cache_sequence(object):
    cache_filename = None
    cache_file = None
    cache = None
    exists = None
    broken = None
    suffix = ".debdelta_cache"

    def __init__(self, filename, cache_filename=None):
        """manages a cache file that store a sequence of python object;
        'filename' is a reference file that is related to the data being cached,
        and is used to create the name of the cache file, unless 'cache_filename'
        is provided
        """
        self.cache_filename = os.path.splitext(filename)[0] + self.suffix if cache_filename is None else cache_filename
        self.cache_file = None
        self.cache = None
        self.broken = None
        self.exists = os.path.isfile(self.cache_filename) and os.path.getmtime(filename) < os.path.getmtime(
            self.cache_filename
        )

    def __iter__(self):
        assert self.exists and not self.cache
        self.cache = gzip.GzipFile(self.cache_filename)
        return self

    def next(self):
        assert self.cache
        try:
            return pickle.load(self.cache)
        except EOFError:
            self.cache = None
            raise StopIteration
        except Exception:
            logger.exception("Cache file is broken, deleting %r" % self.cache_filename)
            if ACT:
                os.unlink(self.cache_filename)
            self.cache = None
            self.broken = True
            # do not kill program
            raise StopIteration

    def __prepare_for_write__(self):
        if not self.cache:
            if DEBUG:
                logger.debug("Creating cache file : %r", self.cache_filename)
            self.cache_file = open(self.cache_filename + "~tmp~", "wb")
            self.cache = gzip.GzipFile(
                filename="", fileobj=self.cache_file, mode="wb"
            )  # 'mtime=0' needs python2.7 or higher

    def close(self):
        try:
            if self.cache:
                self.cache.close()
                self.cache = None
            if self.cache_file:
                self.cache_file.close()
                self.cache_file = None
                os.rename(self.cache_filename + "~tmp~", self.cache_filename)
        except Exception:
            logger.exception("Cannot close the cache file %r" % self.cache_filename)
            self.broken = True

    __del__ = close

    def write(self, s):
        " write one object"
        assert not self.exists
        if self.broken:
            return
        self.__prepare_for_write__()
        try:
            self.cache.write(pickle.dumps(s))
        except Exception:
            logger.exception("Cannot write to cache file, deleting %r", self.cache_filename)
            self.close()
            if ACT:
                os.unlink(self.cache_filename)
            self.broken = True


class cache_same_dict(cache_sequence):
    "cache occurrences of a dict that uses always the same keys; omit the keys to optimize"

    def __init__(self, filename, keys):
        super(cache_same_dict, self).__init__(filename)
        self.keys = keys

    def write(self, s):
        n = [s[k] for k in self.keys]
        super(cache_same_dict, self).write(n)

    def next(self):
        n = super(cache_same_dict, self).next()
        return dict(map(lambda x, y: (x, y), self.keys, n))  # dict comprehension may be used instead


#####################################################################


ALLOWED = "<>()[]{}.,;:!_-+/ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

ECHO_TEST = r"""c='\0151\0141'
E='echo -ne'
if test c`$E 'i'"$c" `o = ciiao  ; then
 :
else
 E='echo -n'
 if test c`$E 'i'"$c" `o = ciiao  ; then
  :
 else
  #echo WARNING : BUILTIN echo DOES NOT WORK OK
  E='/bin/echo -ne'
  test c`$E 'i'"$c" `o = ciiao
 fi
fi
"""


def prepare_for_echo__(s):
    assert type(s) in string_types
    r = ""
    shortquoted = False
    for a in s:
        if a in ALLOWED:
            r += a
            shortquoted = False
        elif a in "0123456789":
            if shortquoted:
                a = "\\" + ("000" + oct(ord(a)))[-4:]
            shortquoted = False
            r += a
        else:
            a = "\\" + oct(ord(a))
            r += a
            shortquoted = len(a) < 5
    return r


def apply_prepare_for_echo(shell, repres):
    a = ECHO_TEST + " $E '" + repres + "' \n exit "
    p = subprocess.Popen([shell], stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
    (i, o) = (p.stdout, p.stdin)
    o.write(a)
    o.close()
    a = i.read()
    i.close()
    return a


# ack! I wanted to use 'dash' as preferred shell, but bug 379227 stopped me
SHELL = "/bin/bash"
# check my code
s = "\x00" + "1ciao88\n77\r566" + "\x00" + "99\n"
r = prepare_for_echo__(s)
a = apply_prepare_for_echo(SHELL, r)
if a != s:
    sys.stderr.write("string=" + repr(s))
    sys.stderr.write("repres=" + repr(r))
    sys.stderr.write("shell=" + SHELL)
    sys.stderr.write("output=" + repr(a))
    sys.stderr.write("Errror in prepare_for_echo.")
    raise SystemExit(4)
del r, s, a

###


def prepare_for_echo(s):
    r = prepare_for_echo__(s)
    if DEBUG > 2:
        a = apply_prepare_for_echo(SHELL, r)
        if a != s:
            z = "Error in prepare_for_echo()\n"
            z += "string=" + repr(s) + "\n"
            z += "repres=" + repr(r) + "\n"
            z += "shell=" + SHELL + "\n"
            z += "output=" + repr(a) + "\n"
            raise DebDeltaError(z, exitcode=4)
    return r


#####################################################################


def version_mangle(v):
    if ":" in v:
        return join(v.split(":"), "%3a")
    else:
        return v


def version_demangle(v):
    if "%" in v:
        return join(v.split("%3a"), ":")
    else:
        return v


def delta_base_name(pkg, old_ver, new_ver, arch, ext=".debdelta"):
    assert ":" not in pkg
    return pkg + "_" + version_mangle(old_ver) + "_" + version_mangle(new_ver) + "_" + arch + ext


def tempo():
    TD = abspath(tempfile.mkdtemp(prefix="debdelta", dir=TMPDIR))
    for i in "OLD", "NEW", "PATCH":
        os.mkdir(TD + "/" + i)
    if VERBOSE > 2 or KEEP:
        logger.debug("Temporary in " + TD)
    return TD


##########


class DebDeltaError(Exception):  # should derive from (Exception):http://docs.python.org/dev/whatsnew/pep-352.html
    # Subclasses that define an __init__ must call Exception.__init__
    # or define self.args.  Otherwise, str() will fail.
    def __init__(self, s, retriable=False, exitcode=None, logs=None):
        assert type(s) in string_types
        self.retriable = retriable
        if retriable:
            self.args = (s + " (retriable) ",)
        else:
            self.args = (s + " (non retriable) ",)
        if exitcode is None:
            if retriable:
                exitcode = 1
            else:
                exitcode = 2
        self.exitcode = exitcode
        self.logs = logs


def die(s):
    # if s : sys.stderr.write(s+'\n')
    assert type(s) in string_types
    raise DebDeltaError(s)


class PopenPipe(object):
    def __init__(self, a, **dictargs):
        # special code for pipes http://docs.python.org/library/subprocess.html#replacing-shell-pipeline
        old_stdin = dictargs.pop("stdin", None)
        old_stdout = dictargs.pop("stdout", None)
        self.pros = []
        while "|" in a:
            l = a.index("|")
            a1 = a[:l]
            a = a[l + 1 :]
            p = subprocess.Popen(args=a1, stdin=old_stdin, stdout=subprocess.PIPE, **dictargs)
            self.pros.append(p)
            old_stdin = p.stdout
        final_pro = subprocess.Popen(args=a, stdin=old_stdin, stdout=old_stdout, **dictargs)
        for p in self.pros:
            p.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
        self.pros.append(final_pro)
        #
        self.returncode = None
        self.stdout = self.pros[-1].stdout
        self.stdin = self.pros[0].stdin
        self.read = getattr(self.pros[-1].stdout, "read", None)
        self.write = getattr(self.pros[0].stdin, "write", None)

    def __set_returncode(self):
        if any([(p.returncode < 0) for p in self.pros]):
            self.returncode = min([p.returncode for p in self.pros])
        else:
            self.returncode = max([p.returncode for p in self.pros])
        return self.returncode

    def poll(self):
        for p in self.pros:
            p.poll()
        return self.__set_returncode()

    def wait(self):
        for p in self.pros:
            p.wait()
        return self.__set_returncode()

    def terminate(self):
        self.pros[0].poll()
        if self.pros[0].returncode is None:
            self.pros[0].terminate()

    def close(self):
        self.terminate()
        self.wait()


def system(a, TD, saveargs=None, ignore_output=False, return_output=False):
    "a must be a tuple, TD the temporary directory ; if return_output , it will return (stdout,stderr,exitcode) regardless"
    assert type(a) in (list, tuple)
    # mvo: compat with python2.5 where tuple does not have index
    a = list(a)
    if VERBOSE and TD[: (len(TMPDIR) + 9)] != TMPDIR + "/debdelta":
        logger.debug(' Warning "system()" in ' + TD + " for " + repr(a))
    (temp_fd, temp_name) = tempfile.mkstemp(prefix="debdelta_out_system")
    (temp_err_fd, temp_err_name) = tempfile.mkstemp(prefix="debdelta_err_system")

    MPP = PopenPipe(a, stdin=open(os.devnull), stdout=temp_fd, stderr=temp_err_fd, cwd=TD, close_fds=True)
    ret = MPP.wait()
    os.close(temp_fd)
    os.close(temp_err_fd)
    if VERBOSE > 3:
        logger.debug("   system(%r)=%d", a, ret)
    if ignore_output == False and (os.stat(temp_name)[ST_SIZE] > 0 or os.stat(temp_err_name)[ST_SIZE] > 0):
        logger.debug(' command "%s" returned %d and  produced output as follows' % (a, ret))
        for i in open(temp_name):
            logger.debug("stdout:  " + repr(i))
        for i in open(temp_err_name):
            logger.debug("stderr:  " + repr(i))
    if return_output:
        return temp_name, temp_err_name, ret
    os.unlink(temp_err_name)
    os.unlink(temp_name)
    if ret == 0:
        return
    elif ret != 1 or a[0] != "xdelta":
        s = "Error , non zero return status " + str(ret) + ' for command "' + repr(a) + '"'
        try:
            if DEBUG and saveargs:
                T = abspath(tempfile.mkdtemp(prefix="debdelta", dir=TMPDIR))
                open(T + "/command", "w").write(repr(a))
                for l in saveargs:
                    if l[0] != "/":
                        l = TD + "/" + l
                    if os.path.exists(l):
                        shutil.copy2(l, T)
                        s = s + "\n saved argument " + l + " in " + T
                    else:
                        s = s + "\n did not find argument " + l
        except OSError:
            o = sys.exc_info()[1]
            s = s + '\n    (there was an additional OSError "' + str(o) + '" when trying to save arguments)'
        die(s)


def check_deb(f):
    if not os.path.exists(f):
        die(_("Error: the file `%s' does not exist.") % f)
    if not os.path.isfile(f):
        die(_("Error: `%s' is not a regular file.") % f)
    p = open(f)
    if p.read(21) != "!<arch>\ndebian-binary":
        die(_("Error: `%s' does not seem to be a Debian package.") % f)
    p.close()


def check_is_delta(f):
    if not os.path.exists(f):
        die(_("Error: the file `%s' does not exist.") % f)
    if not os.path.isfile(f):
        die(_("Error: `%s' is not a regular file.") % f)
    p = open(f)
    if p.read(8) != "!<arch>\n":
        die(_("Error: `%s' does not seem to be a Debian delta.") % f)
    p.close()


def puke(s, e=None):
    " write informations on stderr, if DEBUG also traceback"
    (typ, value, trace) = sys.exc_info()
    if e is None or len(str(e)) < 2:
        logger.error(str(s) + " : " + str(e) + " " + str(typ) + " " + str(value))
    else:
        logger.error(str(s) + " : " + str(e))
    if DEBUG and trace and traceback.print_tb(trace):
        logger.error(traceback.print_tb(trace))


# GPG


def gpg_base_commandline():
    if GPG_HOME:
        GPG_BASE_CMD_LINE = [GPG_CMD, "--homedir", GPG_HOME]
    else:
        GPG_BASE_CMD_LINE = [GPG_CMD, "--keyring", GPG_MASTER_PUB_KEYRING]

    if VERBOSE < 1:
        GPG_BASE_CMD_LINE += ["--quiet"]

    return GPG_BASE_CMD_LINE


def gpg_sign_command():
    return gpg_base_commandline() + ["--batch", "--armor", "--clearsign", "--default-key", GPG_SIGNING_KEY, "--sign"]


def compute_md5_up_to_len(o, length):
    "hash initial part of a file using MD5. 'o' may be a string (in which case the file is opened) or a file type; returns MD5 and bytes effectively read"
    assert type(length) in (int, long) and length >= 0
    if type(o) in string_types:
        o = open(o)
    m = hashlib.md5()
    a = True
    l = length
    while l > 0 and a:
        a = o.read(min(1024, l))
        l -= len(a)
        m.update(a)
    return m.hexdigest(), length - l


def compute_md5_len(o):
    "hash the file using MD5. 'o' may be a string (in which case the file is opened) or a file type; returns MD5 and length"
    if type(o) in string_types:
        o = open(o)
    m = hashlib.md5()
    a = o.read(1024)
    l = 0
    while a:
        l += len(a)
        m.update(a)
        a = o.read(1024)
    return m.hexdigest(), l


def compute_md5(o):
    "hash the file using MD5. 'o' may be a string (in which case the file is opened) or a file type; returns MD5 (as a string of hexes)"
    return compute_md5_len(o)[0]


def _compute_hashes_(na):
    "hash the file"
    o = open(na)
    m = hashlib.md5()
    s = hashlib.sha1()
    a = o.read(1024)
    while a:
        m.update(a)
        s.update(a)
        a = o.read(1024)
    r = (m.hexdigest(), s.hexdigest(), os.stat(na)[ST_SIZE])
    return r


def _compute_hashes_db_(li, DIR):
    db = {}
    for na in li:
        db[na] = _compute_hashes_(DIR + "/" + na)
    return db


def verify_signature(signature, DIR):
    a = "-----BEGIN PGP SIGNED MESSAGE-----\n"
    if open(signature).read(len(a)) != a:
        return ("BAD_FORMAT", signature)

    role = os.path.basename(signature)
    assert role[:4] == "_gpg"
    role = role[4:]

    (temp_fd, temp_name) = tempfile.mkstemp(prefix="debdelta_gpg_verified")
    # (read_end, write_end) = os.pipe()
    p = subprocess.Popen(
        gpg_base_commandline() + ["--batch", "--status-fd", "2", "--output", "-", signature],
        stdout=subprocess.PIPE,
        stderr=temp_fd,
        stdin=open(os.devnull),
        close_fds=True,
    )
    r = _verify_signature_no_gpg(p.stdout, DIR, role)
    p.wait()

    os.close(temp_fd)

    if VERBOSE > 2 or p.returncode:
        for j in open(temp_name):
            logger.debug("   GPG> " + j)

    os.unlink(temp_name)

    if p.returncode:
        return ("GPG_VERIFY_FAILED", signature)

    return r


def _verify_signature_no_gpg(signature, DIR, role):
    # list stuff, skipping signatures
    dir_list = [a for a in os.listdir(DIR) if a[:4] != "_gpg"]
    # compute signatures
    hashes = _compute_hashes_db_(dir_list, DIR)
    # scan hashes file (GPG already verified)
    if type(signature) in string_types:
        f = open(signature)
    elif hasattr(signature, "readline"):
        f = signature
    else:
        raise AssertionError
    a = f.readline()
    if a != "Version: 4\n":
        return ("UNSUPPORTED_VERSION", a)
    a = f.readline()
    while a:
        if a[:5] == "Role:":
            if a[5:].strip() != role:
                return ("ROLE_MISMATCH", a)
            a = f.readline()
        elif a[:6] == "Files:":
            # parse files
            a = f.readline()
            while a and a[0] in ("\t", " "):
                a = a.rstrip("\n")
                a = a.lstrip()
                a = a.split(" ")
                if VERBOSE > 3:
                    logger.debug("    checking hashes " + repr(a))
                (md5, sha1, le, na) = a
                if na not in dir_list:
                    return ("ABSENT", na)
                (cmd5, csha1, cle) = hashes[na]
                if int(le) != cle:
                    return ("SIZE", na)
                # check hashes
                if md5 != cmd5:
                    return ("MD5", na)
                if sha1 != csha1:
                    return ("SHA1", na)
                dir_list.remove(na)
                a = f.readline()
        elif VERBOSE > 2:
            logger.debug("   signature header ignored: " + a)
            a = f.readline()
        else:
            a = f.readline()
    # end parsing
    if dir_list:
        return ("UNCHECKED", dir_list)
    return True


def _write_signature(db, filename, role):
    "starting from a database of hashes, see _compute_hashes_, it writes a signature file"
    f = open(filename, mode="w")
    # this is the format of dpkg-sig, but is redundant, since the "date" and "signer"
    # are already available thru the gpg signature
    # f.write("Version: 4\nSigner: \nDate: %s\nRole: %s\nFiles: \n" % (time.ctime(),role))
    # and actually dpkg-sig will validate also a simpler file, so, lets save a few bytes
    f.write("Version: 4\nRole: %s\nFiles:\n" % (role,))
    for a in db:
        (m, s, l) = db[a]
        f.write("\t" + m + " " + s + " " + str(l) + " " + a + "\n")
    f.close()


def sign_delta(delta, db, role="maker"):
    TD = abspath(tempfile.mkdtemp(prefix="debdelta", dir=TMPDIR))
    try:
        _write_signature(db, TD + "/_temp", role)
        p = subprocess.Popen(
            gpg_sign_command() + ["--output", TD + "/_gpg" + role, TD + "/_temp"],
            stdin=open(os.devnull),
            close_fds=True,
        )
        p.wait()
        if p.returncode == 0:
            r = system(("ar", "qS", delta, TD + "/_gpg" + role), TD)
    except BaseException:
        rmtree(TD)
        raise
    rmtree(TD)
    if p.returncode:
        raise DebDeltaError("GnuPG fails to sign")
    if r:
        raise DebDeltaError("ar fails to add the signature")


# apply patch

# info auxiliary routines


def _info_patch_unzip_(TD):
    "unzip info and patch.sh"
    if os.path.exists(TD + "PATCH/info.gz"):
        system(("gunzip", "PATCH/info.gz"), TD)
    if os.path.exists(TD + "PATCH/patch.sh.gz"):
        system(("gunzip", "PATCH/patch.sh.gz"), TD)
    elif os.path.exists(TD + "PATCH/patch.sh.bz2"):
        system(("bunzip2", "PATCH/patch.sh.bz2"), TD)
    elif os.path.exists(TD + "PATCH/patch.sh.lzma"):
        if not os.path.exists("/usr/bin/unlzma"):
            raise DebDeltaError('This patch needs lzma. Please install the Debian package "lzma".', retriable=True)
        system(("unlzma", "PATCH/patch.sh.lzma"), TD)
    elif os.path.exists(TD + "PATCH/patch.sh.xz"):
        if not os.path.exists("/usr/bin/unxz"):
            raise DebDeltaError('This patch needs xz. Please install the Debian package "xz-utils".', retriable=True)
        system(("unxz", "PATCH/patch.sh.xz"), TD)


def get_info_slow(delta, T=None):
    if T:
        TD = T
    else:
        TD = tempo()
    if TD[-1] != "/":
        TD = TD + "/"
    delta = abspath(expanduser(delta))
    system(
        (
            "ar",
            "x",
            delta,
            "info",
            "info.gz",
            "patch.sh",
            "patch.sh.gz",
            "patch.sh.bz2",
            "patch.sh.lzma",
            "patch.sh.xz",
        ),
        TD + "/PATCH",
        ignore_output=True,
    )
    _info_patch_unzip_(TD)
    info = _scan_delta_info_(TD)
    if T is None:
        rmtree(TD)
    return info


def get_info_fast(delta):
    f = open(delta)
    s = f.readline()
    if "!<arch>\n" != s:
        raise DebDeltaError("This is not a delta file: " + delta)
    s = f.read(60)
    if len(s) != 60:
        logger.warning("(Warning, cannot get info from  truncated: " + delta + " )")
        return None
    if s[:4] != "info":
        # old style debdelta, with info in patch.sh
        if VERBOSE > 1:
            logger.warning("  (Warning, cannot get info from old style: " + delta + " )")
        return None
    # parse ar segment
    ## see /usr/include/ar.h
    if s[-2:] != "`\n":
        logger.warning("(Warning, cannot get info from  " + delta + " , format not known)")
        return None
    l = int(s[-12:-2])
    s = f.read(l)
    if len(s) != l:
        logger.warning("(Warning, cannot get info from truncated: " + delta + " )")
        return None
    info = s.split("\n")
    f.close()
    return info


def get_info(delta, TD=None):
    info = get_info_fast(delta)
    if info is None:
        info = get_info_slow(delta, TD)
    return info


def _scan_delta_info_(TD):
    info = []
    if os.path.isfile(TD + "PATCH/info"):
        # new style debdelta, with info file
        p = open(TD + "PATCH/info")
        info = p.read().split("\n")
        p.close()
        if info[-1] == "":
            info.pop()
    else:
        # old style debdelta, with info in patch.sh
        p = open(TD + "PATCH/patch.sh")
        s = p.readline()
        s = p.readline()
        while s:
            if s[0] == "#":
                s = de_n(s)
                info.append(s[1:])
            s = p.readline()
        p.close()
    return info


def info_2_db(info):
    params = {}
    for s in info:
        if ":" in s:
            i = s.index(":")
            params[s[:i]] = s[i + 2 :]
        elif s:
            params[s] = True
    return params


# other auxiliary routines


def patch_check_tmp_space(params, olddeb):
    if not isinstance(params, dict):
        params = info_2_db(params)
    if "NEW/Installed-Size" not in params or "OLD/Installed-Size" not in params:
        logger.warning("(Warning... Installed size unknown...)")
        return True
    free = freespace(TMPDIR)
    if free is None:
        return True
    free = free / 1024
    if os.path.isdir(olddeb):
        instsize = int(params["NEW/Installed-Size"])
        # the last action of the script is to gzip the data.tar, so
        if "NEW/Size" in params:
            instsize += int(params["NEW/Size"]) / 1024
        else:
            instsize = instsize * 1.8
    else:
        instsize = int(params["NEW/Installed-Size"]) + int(params["OLD/Installed-Size"])
    instsize += 2 ** 13
    if free < instsize:
        return _("not enough disk space (%(free)dkB) in directory %(dir)s for applying delta (needs %(size)dkB)") % {
            "free": int(free),
            "dir": TMPDIR,
            "size": instsize,
        }
    else:
        return True


def scan_diversions():
    f = open("/var/lib/dpkg/diversions")
    d = {}

    a = 1
    while True:
        a = f.readline()
        if not a:
            break
        a = de_n(a)
        b = de_n(f.readline())
        p = de_n(f.readline())
        d[a] = (b, p)
    f.close()
    return d


# debforensic extract


# in base-passwd 3.5.11
# /usr/share/base-passwd/passwd.master
base_passwd = """root::0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/bin/sh
bin:*:2:2:bin:/bin:/bin/sh
sys:*:3:3:sys:/dev:/bin/sh
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/bin/sh
man:*:6:12:man:/var/cache/man:/bin/sh
lp:*:7:7:lp:/var/spool/lpd:/bin/sh
mail:*:8:8:mail:/var/mail:/bin/sh
news:*:9:9:news:/var/spool/news:/bin/sh
uucp:*:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:*:13:13:proxy:/bin:/bin/sh
www-data:*:33:33:www-data:/var/www:/bin/sh
backup:*:34:34:backup:/var/backups:/bin/sh
list:*:38:38:Mailing List Manager:/var/list:/bin/sh
irc:*:39:39:ircd:/var/run/ircd:/bin/sh
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:*:65534:65534:nobody:/nonexistent:/bin/sh"""
base_passwd_db = {}
base_passwd_anti_db = {}
for a in base_passwd.split("\n"):
    a = a.split(":")
    base_passwd_db[a[0]] = int(a[2])
    base_passwd_anti_db[int(a[2])] = a[0]

base_group = """root:*:0:
daemon:*:1:
bin:*:2:
sys:*:3:
adm:*:4:
tty:*:5:
disk:*:6:
lp:*:7:
mail:*:8:
news:*:9:
uucp:*:10:
man:*:12:
proxy:*:13:
kmem:*:15:
dialout:*:20:
fax:*:21:
voice:*:22:
cdrom:*:24:
floppy:*:25:
tape:*:26:
sudo:*:27:
audio:*:29:
dip:*:30:
www-data:*:33:
backup:*:34:
operator:*:37:
list:*:38:
irc:*:39:
src:*:40:
gnats:*:41:
shadow:*:42:
utmp:*:43:
video:*:44:
sasl:*:45:
plugdev:*:46:
staff:*:50:
games:*:60:
users:*:100:
nogroup:*:65534:"""

base_group_db = {}
base_group_anti_db = {}
for a in base_group.split("\n"):
    a = a.split(":")
    base_group_db[a[0]] = int(a[2])
    base_group_anti_db[int(a[2])] = a[0]

# all code following return name,mode,tartype,uid,gid,uname,gname

# adapted from tarfile.py, a Python module


def stat_to_tar(name):
    "returns name,mode,tartype,uid,gid,uname,gname,data"
    statres = os.lstat(name)
    stmd = statres.st_mode
    data = None
    if stat.S_ISREG(stmd):
        tartype = tarfile.REGTYPE
        # here ideally we should SHA1 the file ;
        # but this is done elsewhere for performance,
        # and to have multi_hash in the future
    elif stat.S_ISDIR(stmd):
        tartype = tarfile.DIRTYPE
    elif stat.S_ISFIFO(stmd):
        tartype = tarfile.FIFOTYPE
    elif stat.S_ISLNK(stmd):
        tartype = tarfile.SYMTYPE
        data = os.readlink(name)
    elif stat.S_ISCHR(stmd):
        tartype = tarfile.CHRTYPE
    elif stat.S_ISBLK(stmd):
        tartype = tarfile.BLKTYPE
    elif stat.S_ISSOCK(stmd):
        tartype = "SOCKET"  # SOCKETs are not supported in tar files
    else:
        raise TypeError

    if tartype in (tarfile.CHRTYPE, tarfile.BLKTYPE):
        data = str(os.major(statres.st_rdev)) + " " + str(os.minor(statres.st_rdev))

    uid, gid = statres.st_uid, statres.st_gid

    if uid in base_passwd_anti_db:
        uname = base_passwd_anti_db[uid]
    else:
        import pwd

        try:
            uname = pwd.getpwuid(uid)[0]
        except KeyError:
            uname = None

    if gid in base_group_anti_db:
        gname = base_group_anti_db[gid]
    else:
        import grp

        try:
            gname = grp.getgrgid(gid)[0]
        except KeyError:
            gname = None

    # 07777 is used in tarfile.TarInfo.tobuf
    return name.lstrip("/"), stmd & 0o7777, tartype, uid, gid, uname, gname, data


def tarinfo_to_ls(tartype, tarmode):
    "returns a string -rwxrwxrwx such as what ls -l prints "
    if ord(tartype) == 0:
        a = "_"
    else:
        if tartype >= "0" and tartype <= "6":
            a = "-hlcbdp"[ord(tartype) - ord("0")]
        else:
            a = "?"
    return a + tarfile.filemode(tarmode)[1:]


def sha1_hash_file(f):
    s = hashlib.sha1()
    if type(f) in string_types:
        f = open(f)
    a = f.read(1024)
    while a:
        s.update(a)
        a = f.read(1024)
    f.close()
    return s.digest()


def hash_to_hex(s):
    a = ""
    for i in s:
        a = a + ("%02x" % ord(i))
    return a


def forensics_rfc(
    o, db, bytar, controlfiles, files, conffiles, diverted=[], diversions={}, localepurged=[], prelink_u_failed=[]
):
    " this is invoked by do_patch_() as well as do_delta_() ; in the former case, by_tar=False"
    assert isinstance(diversions, dict)
    if isinstance(db, dict):
        for a in sorted(db.keys()):
            if a[:3] == "OLD":
                o.write(a[4:] + ": " + db[a] + "\n")
    else:
        for a in sorted(db):
            if a[:3] == "OLD":
                o.write(a[4:] + "\n")
    if diverted:
        o.write("Diversions:\n")
        for a in sorted(diverted):
            b, p = diversions[a]
            o.write(" From: " + a + "\n")
            o.write(" To: " + b + "\n")
            o.write(" By: " + p + "\n")
    if conffiles:
        o.write("Conffiles:\n")
        for a in sorted(conffiles):
            o.write(" " + a + "\n")
    for L, N in ((controlfiles, "Control"), (files, "Files")):
        o.write(N + ":\n")
        for l in sorted(L):
            if bytar:
                name, mode, tartype, uid, gid, uname, gname, data = l
                tmpcopy = None
                divert = None
            else:
                name, divert, tmpcopy = l
                if os.path.exists(divert):
                    fullname, mode, tartype, uid, gid, uname, gname, data = stat_to_tar(divert)
                else:
                    fullname, mode, tartype, uid, gid, uname, gname, data = "", 0, "?", 0, 0, "?", "?", "?"
                if tartype == tarfile.REGTYPE:
                    if tmpcopy and os.path.exists(tmpcopy):
                        data = hash_to_hex(sha1_hash_file(tmpcopy))
                    elif os.path.exists(divert):
                        data = hash_to_hex(sha1_hash_file(divert))
            if name in (".", "/", "./", "/.") and tartype == tarfile.DIRTYPE:  # skip root
                continue
            if uname is None:
                uname = str(uid)
            if gname is None:
                gname = str(gid)
            name = de_bar(name)
            o.write(" " + tarinfo_to_ls(tartype, mode) + " " + uname + " " + gname)
            if N == "Files" and tartype == tarfile.REGTYPE and name in conffiles:
                o.write(" [conffile]")
            if N == "Files" and tartype == tarfile.REGTYPE and name in localepurged:
                o.write(" [localpurged]")
            if N == "Files" and tartype == tarfile.REGTYPE and name in prelink_u_failed:
                o.write(" [prelink-u failed]")
            if divert and not os.path.exists(divert):
                o.write(" [missing file %r]" % divert)
            if tmpcopy:
                o.write(" [prelink-u]")
            o.write("\n " + name + "\n")
            if data is not None:
                o.write(" " + data + "\n")
            else:
                o.write(" \n")


def tar_those(f):
    " tar multiple files in one tar (all in the same base directory!). Note that f may be a list of lists or strings or mixed."
    temptar = tempfile.mktemp(suffix=".tgz")
    tar = tarfile.open(name=temptar, mode="w:gz")
    for z in f:
        if type(z) in (list, tuple):
            for j in z:
                tar.add(j, arcname=os.path.basename(j))
        elif type(z) in string_types:
            tar.add(z, arcname=os.path.basename(z))
        else:
            DebDeltaError(" internal error m92ksy")
    tar.close()
    return temptar


def forensic_send(f, forensic=FORENSIC):
    " note that f must be a list of lists (or None)"
    assert isinstance(f, list)
    if not forensic:
        if f:
            logger.error(_('(Faulty delta. Please consider retrying with the option "--forensic=http" ).') + "\n")
        return
    if not f:
        return
    if all([(z is None) for z in f]):
        logger.warning("Sorry, no forensic logs were generated")
        return
    if forensic[:4] in ("mutt", "mail") or forensic[:7] == "icedove" or forensic[:10] == "thunderbird":
        email = EMAIL
        if ":" in forensic:
            a = forensic.find(":")
            email == forensic[a:]
            forensic = forensic[:a]
        logger.warning(_("There were faulty deltas.") + " " + _("Now invoking the mail sender to send the logs."))
        if forensic in ("mutt", "mail"):
            raw_input(_("(hit any key)"))
            args = []
            for z in f:
                if z:
                    for j in z:
                        args += ["-a", j]
            subprocess.call(["mutt", email, "-s", "delta_failures"] + args)
        else:
            temptar = tempfile.mktemp(suffix=".tgz")
            tar = tarfile.open(name=temptar, mode="w:gz")
            for z in f:
                if z:
                    for j in z:
                        tar.add(j, arcname=os.path.basename(j))
            tar.close()
            args = "to=%s,subject=delta_failures,attachment='file:///%s'" % (email, temptar)
            subprocess.call([forensic, "-compose", args])
        return
    elif forensic[:4] == "http":
        logger.warning(_("There were faulty deltas.") + " " + _("Sending logs to server."))
        temptar = tempfile.mktemp(suffix=".tgz")
        tar = tarfile.open(name=temptar, mode="w:gz")
        for z in f:
            if z:
                for j in z:
                    tar.add(j, arcname=os.path.basename(j))
        tar.close()
        # http://atlee.ca/software/poster
        import urllib
        import urllib2
        import httplib
        import poster

        poster.streaminghttp.register_openers()
        datagen, headers = poster.encode.multipart_encode(
            {"auth_userid": "debdelta", "auth_password": "slartibartfast", "thefile": open(temptar, "rb")}
        )
        # Create the Request object
        request = urllib2.Request("http://debdelta.debian.net:7890/receive", datagen, headers)
        # Actually do the request, and get the response
        logger.info(" " + _("Server answers:"), repr(urllib2.urlopen(request).read()))
        return
    else:
        logger.warning(_("Faulty delta. Please send by email to %s the following files:\n") % EMAIL)
        for z in f:
            if z:
                logger.warning(" " + string.join(z, " ") + "\n")
        return
    logger.warning(_('(Faulty delta. Please consider retrying with the option "--forensic=http" ).') + "\n")


def elf_info(f):
    "returns (is_elf, ei_class, ei_data, ei_osabi, e_type)"
    import struct

    elfheader = open(f).read(32)
    if len(elfheader) == 32:
        # parse as specified in /usr/include/elf.h from libelf-dev
        EI_CLASS = {1: "ELFCLASS32", 2: "ELFCLASS64"}
        EI_DATA = {1: "ELFDATA2LSB", 2: "ELFDATA2MSB"}  # 2's complement, little endian  # 2's complement, big endian
        EI_OSABI = {
            0: "ELFOSABI_SYSV",  # UNIX System V ABI
            1: "ELFOSABI_HPUX",
            2: "ELFOSABI_NETBSD",
            3: "ELFOSABI_LINUX",
            # fixme insert other values
            9: "ELFOSABI_FREEBSD",
            12: "ELFOSABI_OPENBSD",
            97: "ELFOSABI_ARM",
        }
        # fixme what is ET_LOOS , ET_HIOS  , ET_LOPROC, ET_HIPROC ??
        ET_TYPE = {
            1: "ET_REL",  # Relocatable file
            2: "ET_EXEC",  # Executable file
            3: "ET_DYN",  # Shared object file
            4: "ET_CORE",
        }  # Core file

        ei_magic, ei_class, ei_data, ei_version, ei_osabi, ei_abiversion = struct.unpack_from("4sBBBBB", elfheader)
        e_type, e_machine, e_version = struct.unpack_from("HHI", elfheader, 16)
        # FIXME I think I am getting ei_osabi wrong.. it is always 0
        is_elf = "\x7fELF" == ei_magic
        # and ei_class in (1,2) and \
        #    ei_version == 1 and \
        #    ei_data in (1,2) and e_type>0 and e_machine>0 and e_version>0
        return is_elf, EI_CLASS.get(ei_class), EI_DATA.get(ei_data), EI_OSABI.get(ei_osabi), ET_TYPE.get(e_type)
    # , e_machine, e_version
    else:
        return False, 0, 0, 0, 0


def parse_prelink_conf():
    " fixme , currently unused and incomplete "
    prelinked_dirs = []
    prelinked_blacklist = []
    prelinked_blacklist_glob = []
    for a in open("/etc/prelink.conf"):
        if a[0] == "#":
            continue
        a = a.strip()
        b = a.split()
        if len(b) != 2:
            logger.warning('  (sorry this line of /etc/prelink.conf cannot be parsed currently: "' + a + '")')
            continue
        if "-b" == b[0]:
            if "/" in b[1]:
                prelinked_blacklist.append(b[1])
            else:
                prelinked_blacklist_glob.append(b[1])
        elif "-l" == b[0]:
            prelinked_dirs.append(b[1])


# do_patch


def do_patch(delta, olddeb, newdeb, info=None, diversions=None, do_gpg=DO_GPG):
    runtime = {}
    T = None
    try:
        T = tempo()
        r = do_patch_(delta, olddeb, newdeb, T, runtime, info=info, diversions=diversions, do_gpg=do_gpg)
    except BaseException:
        if T:
            rmtree(T)
        if newdeb and os.path.exists(newdeb):
            os.unlink(newdeb)
        raise
    rmtree(T)
    return r


def do_patch_(delta, olddeb, newdeb, TD, runtime, info=None, diversions=None, do_gpg=DO_GPG, do_progress=DO_PROGRESS):

    import thread
    import threading

    if TD[-1] != "/":
        TD = TD + "/"

    HAVE_PRELINK = os.path.exists("/usr/sbin/prelink")
    # some people purge locales w/o using 'localepurge' , see e.g. http://bugs.debian.org/619086
    # HAVE_LOCALEPURGE=os.path.exists('/etc/locale.nopurge') or os.path.exists('/usr/sbin/localepurge')

    delta = abspath(delta)
    newdebshortname = "-"
    if newdeb:
        newdebshortname = newdeb
        newdeb = abspath(newdeb)
    if not os.path.isdir(olddeb):
        olddeb = abspath(olddeb)
    elif diversions is None:
        diversions = scan_diversions()

    start_sec = time.time()
    runtime["patchprogress"] = 0

    check_is_delta(delta)

    if not os.path.isdir(olddeb):
        check_deb(olddeb)

    temp_name, temp_err_name, ret = system(("ar", "xvo", delta), TD + "/PATCH", return_output=True, ignore_output=True)
    if ret:
        raise DebDeltaError("Cannot extract from " + delta)
    ar_list_delta = [a[4:] for a in open(temp_name).read().split("\n") if a]
    os.unlink(temp_name)
    os.unlink(temp_err_name)

    runtime["patchprogress"] = 1

    is_signed = False
    for a in ar_list_delta:
        if a[:4] == "_gpg":
            r = verify_signature(TD + "/PATCH/" + a, TD + "/PATCH")
            if True != r:
                die(delta + ": the signature file " + a + " fails as follows: " + repr(r))
            is_signed = True
            if VERBOSE > 1:
                logger.debug('  The signature by "' + a[4:] + '" is correctly verified for ' + delta)
    if not is_signed:
        if do_gpg:
            die(_("Delta is not signed:") + " " + delta)
        elif do_gpg is not None:
            logger.warning(_("WARNING, delta is not signed:") + " " + delta)

    runtime["patchprogress"] = 2

    _info_patch_unzip_(TD)

    if not os.path.isfile(TD + "PATCH/patch.sh"):
        die("Error. File `%s' is not a delta file." % delta)

    os.symlink(minigzip, TD + "minigzip")
    os.symlink(minibzip2, TD + "minibzip2")

    # lets scan parameters, to see what it does and what it requires
    if info is None:
        info = _scan_delta_info_(TD)
    params = info_2_db(info)

    runtime["patchprogress"] = 3

    # this is not needed in preparing the patch, but may help in forensic
    conf_files = []
    z = "/var/lib/dpkg/info/" + params["OLD/Package"] + ".conffiles"
    if FORENSIC and os.path.isfile(z):
        # note that filenames do not have leading /
        conf_files = [de_bar(p) for p in open(z).read().split("\n") if p]
    del z

    ###
    s = patch_check_tmp_space(params, olddeb)
    if not s:
        raise DebDeltaError("Sorry, " + s, True)

    if not os.path.isdir(olddeb):
        os.symlink(olddeb, TD + "/OLD.file")
        ar_list_old = list_ar(TD + "OLD.file")
        # unpack the old control structure, if available
        os.mkdir(TD + "/OLD/CONTROL")
        # unpack control.tar.gz
        f, b, z = untar_control_in_deb(ar_list_old)
        system(("ar", "p", TD + "OLD.file", f, "|", "tar", b, "-xp", "-f", "-", "-C", TD + "OLD/CONTROL"), TD)
    # then we check for the conformance
    if not os.path.isdir(olddeb) and "OLD/Size" in params:
        olddebsize = os.stat(olddeb)[ST_SIZE]
        if olddebsize != int(params["OLD/Size"]):
            raise DebDeltaError("Old deb size is " + str(olddebsize) + " instead of " + params["OLD/Size"])

    runtime["patchprogress"] = 4

    if DEBUG > 1:
        # this is currently disabled, since  'dpkg -s' is vey slow (~ 1.6 sec)
        dpkg_params = {}
        b = params["OLD/Package"]
        if os.path.isdir(olddeb):
            p = my_popen_read("env -i dpkg -s " + b)
        else:
            p = open(TD + "OLD/CONTROL/control")
        scan_control(p, params=dpkg_params, prefix="OLD")
        p.close()
        if os.path.isdir(olddeb):
            if "OLD/Status" not in dpkg_params:
                die("Error: package %s is not known to dpkg." % b)
            if dpkg_params["OLD/Status"] != "install ok installed":
                die("Error: package %s is not installed, status is %s." % (b, dpkg_params["OLD/Status"]))
        for a in params:
            if a[:3] == "OLD" and a != "OLD/Installed-Size" and a != "OLD/Size":
                if a not in dpkg_params:
                    die("Error parsing old control file , parameter %s not found" % a)
                elif params[a] != dpkg_params[a]:
                    die(
                        "Error : in delta , "
                        + a
                        + " = "
                        + params[a]
                        + "\nin old/installed deb, "
                        + a
                        + " = "
                        + dpkg_params[a]
                    )
        del b, p  # cannot delete 'a', python raise a SyntaxError

    runtime["patchprogress"] = 5

    # some auxiliary routines, separated to make code more readable

    def dpkg_L_faster(pa, ar, diversions):
        "Scan dpkg -L . 'diversions' must be prepared by scan_diversions() . Returns list of pairs of files ,and list of diverted files. "
        s = []
        diverted = []
        n = "/var/lib/dpkg/info/" + pa + ":" + ar + ".list"
        if not DPKG_MULTIARCH or not os.path.exists(n):
            n = "/var/lib/dpkg/info/" + pa + ".list"
        f = open(n)
        while True:
            a = f.readline()
            if not a:
                break
            a = de_n(a)
            if a in diversions:
                b, p = diversions[a]
                if p != pa:
                    s.append((a, b))
                    diverted.append(a)
                else:
                    s.append((a, a))
            else:
                s.append((a, a))
        f.close()
        return s, diverted

    def dpkg_L(pa, ar):
        "Scan dpkg -L . Currently unused, see previous function."
        # sys.stderr.write('INTERNAL WARNING: USING OBSOLETE dpkg_L\n')
        s = []
        diverted = []
        if DPKG_MULTIARCH:
            p = my_popen_read("env -i dpkg-query -L " + pa + ":" + ar)
        else:
            p = my_popen_read("env -i dpkg-query -L " + pa)
        a = p.readline()
        while a:
            a = de_n(a)
            # support diversions
            if a[:26] == "package diverts others to:":
                continue
            if s and a[:11] == "diverted by" or a[:20] == "locally diverted to:":
                orig, divert = s.pop()
                i = a.index(":")
                divert = a[i + 2 :]
                s.append((orig, divert))
                diverted.append(orig)
            else:
                s.append((a, a))
            a = p.readline()
        p.close()
        return s, diverted

    def _symlink_data_tree(pa, ar, TD, diversions, runtime):
        localepurged = []
        prelink_u_failed = []
        file_triples = []
        prelink_time = 0
        prelink_datasize = 0
        if diversions:
            s, diverted = dpkg_L_faster(pa, ar, diversions)
        else:
            s, diverted = dpkg_L(pa, ar)
        progressline = 0
        progresslen = float(len(s))
        for orig, divert in s:
            progressline += 1
            progress = 6.0 + 6.0 * float(progressline) / progresslen
            runtime["patchprogress"] = progress
            if do_progress:
                sys.stderr.write("P %2d%% %s\r" % (progress, newdebshortname))
            if os.path.isfile(divert) and not os.path.islink(divert):
                tmpcopy = TD + "OLD/DATA" + orig
                d = os.path.dirname(tmpcopy)
                if not os.path.exists(d):
                    os.makedirs(d)
                # the following code idea was provided by roman@khimov.ru
                unprelink = False
                if HAVE_PRELINK:
                    prelink_time -= time.time()
                    is_elf, ei_class, ei_data, ei_osabi, e_type = elf_info(divert)
                    # according to prelink-0.0.20090925/src/main.c
                    unprelink = is_elf and e_type in ("ET_DYN", "ET_EXEC")
                    prelink_time += time.time()
                if unprelink:
                    prelink_time -= time.time()
                    prelink_datasize += os.path.getsize(divert)
                    if VERBOSE > 3:
                        logger.debug("    copying/unprelinking " + divert + " to " + tmpcopy)
                    # unfortunately 'prelink -o' sometimes alters files, see http://bugs.debian.org/627932
                    shutil.copy2(divert, tmpcopy)
                    proc = subprocess.Popen(
                        ["/usr/sbin/prelink", "-u", tmpcopy],
                        stdin=open(os.devnull),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        close_fds=True,
                    )
                    out = proc.stdout.read().strip()
                    proc.wait()
                    if proc.returncode:
                        if not os.path.exists(tmpcopy):
                            if VERBOSE > 4:
                                logger.debug("     (prelink failed, symlinking " + divert + " to " + tmpcopy + ")")
                            os.symlink(divert, tmpcopy)
                            prelink_u_failed.append(de_bar(orig))
                            unprelink = False
                        elif VERBOSE > 4:
                            logger.debug("     (prelink failed, but file was copied)")
                        thestat = os.statvfs(tmpcopy)
                        if out[-39:] == "does not have .gnu.prelink_undo section":
                            if DEBUG:
                                logger.debug("  " + repr(out) + "\n")
                        elif (thestat.f_bsize * thestat.f_bavail / 1024) < 50000:
                            logger.warning("!!Prelink -u failed, it needs at least 50000KB of free disk space\n")
                            prelink_u_failed.append(de_bar(orig))
                            unprelink = False
                        else:
                            logger.warning("!!Prelink -u failed on %r : %r\n", tmpcopy, out)
                            prelink_u_failed.append(de_bar(orig))
                            unprelink = False
                    prelink_time += time.time()
                else:
                    if VERBOSE > 3:
                        logger.debug("    symlinking " + divert + " to " + a)
                    os.symlink(divert, tmpcopy)
                if unprelink and FORENSIC:
                    # unfortunately the script will delete the 'tmpcopy', so we hardlink it
                    z = tempfile.mktemp(prefix=TD)
                    os.link(tmpcopy, z)
                    file_triples.append((orig, divert, z))
                else:
                    file_triples.append((orig, divert, None))
            elif not os.path.exists(divert) and os.path.islink(divert):
                file_triples.append((orig, divert, None))
                if VERBOSE > 1:
                    logger.debug("  Broken symlink? %r", divert)
            elif not os.path.exists(divert):
                file_triples.append((orig, divert, None))
                if VERBOSE:
                    logger.debug(" Disappeared file? %r", divert)
                for z in ("locale", "man", "gnome/help", "omf", "doc/kde/HTML"):
                    w = "/usr/share/" + z
                    if orig[: len(w)] == w:
                        localepurged.append(de_bar(orig))
            else:
                file_triples.append((orig, divert, None))
                if VERBOSE > 3:
                    logger.debug("    not symlinking %r to %r", divert, orig)
        return file_triples, localepurged, prelink_u_failed, diverted, prelink_time, prelink_datasize

    def chmod_add(n, m):
        "same as 'chmod ...+...  n '"
        om = S_IMODE(os.stat(n)[ST_MODE])
        nm = om | m
        if nm != om:
            if VERBOSE > 2:
                logger.debug("   Performing chmod %s %s %s", n, oct(om), oct(nm))
            os.chmod(n, nm)

    def _fix_data_tree_(TD):
        for (dirpath, dirnames, filenames) in os.walk(TD + "OLD/DATA"):
            chmod_add(dirpath, S_IRUSR | S_IWUSR | S_IXUSR)
            for i in filenames:
                i = os.path.join(dirpath, i)
                if os.path.isfile(i):
                    chmod_add(i, S_IRUSR | S_IWUSR)
            for i in dirnames:
                i = os.path.join(dirpath, i)
                chmod_add(i, S_IRUSR | S_IWUSR | S_IXUSR)

    # initialize, just in case
    control_file_triples = []
    file_triples = []
    localepurged = []
    prelink_u_failed = []
    diverted = []
    prelink_time = 0
    prelink_datasize = 0

    # see into parameters: the patch may need extra info and data

    runtime["patchprogress"] = 6

    prelink_time = None

    for a in params:
        if "needs-old" == a:
            if os.path.isdir(olddeb):
                die("This patch needs the old version Debian package")
        elif "old-data-tree" == a:
            os.mkdir(TD + "/OLD/DATA")
            if os.path.isdir(olddeb):
                (
                    file_triples,
                    localepurged,
                    prelink_u_failed,
                    diverted,
                    prelink_time,
                    prelink_datasize,
                ) = _symlink_data_tree(params["OLD/Package"], params["OLD/Architecture"], TD, diversions, runtime)
            else:
                ar_list_old = list_ar(TD + "OLD.file")
                if "data.tar.bz2" in ar_list_old:
                    system(
                        (
                            "ar",
                            "p",
                            TD + "OLD.file",
                            "data.tar.bz2",
                            "|",
                            "tar",
                            "-xp",
                            "--bzip2",
                            "-f",
                            "-",
                            "-C",
                            TD + "OLD/DATA",
                        ),
                        TD,
                    )
                elif "data.tar.gz" in ar_list_old:
                    system(
                        (
                            "ar",
                            "p",
                            TD + "OLD.file",
                            "data.tar.gz",
                            "|",
                            "tar",
                            "-xp",
                            "-z",
                            "-f",
                            "-",
                            "-C",
                            TD + "OLD/DATA",
                        ),
                        TD,
                    )
                elif "data.tar.lzma" in ar_list_old:
                    if not os.path.exists("/usr/bin/lzma"):
                        raise DebDeltaError(
                            'This patch needs lzma. Please install the Debian package "lzma".', retriable=True
                        )
                    system(
                        (
                            "ar",
                            "p",
                            TD + "OLD.file",
                            "data.tar.lzma",
                            "|",
                            "unlzma",
                            "-c",
                            "|",
                            "tar",
                            "-xpf",
                            "-",
                            "-C",
                            TD + "OLD/DATA",
                        ),
                        TD,
                    )
                elif "data.tar.xz" in ar_list_old:
                    if not os.path.exists("/usr/bin/xz"):
                        raise DebDeltaError(
                            'This patch needs xz. Please install the Debian package "xz-utils".', retriable=True
                        )
                    system(
                        (
                            "ar",
                            "p",
                            TD + "OLD.file",
                            "data.tar.xz",
                            "|",
                            "unxz",
                            "-c",
                            "|",
                            "tar",
                            "-xpf",
                            "-",
                            "-C",
                            TD + "OLD/DATA",
                        ),
                        TD,
                    )
                else:
                    assert 0
                _fix_data_tree_(TD)
        elif "old-control-tree" == a:
            if os.path.isdir(olddeb):
                if not os.path.isdir(TD + "OLD/CONTROL"):
                    os.mkdir(TD + "OLD/CONTROL")
                p = params["OLD/Package"]
                a = params["OLD/Architecture"]
                for b in dpkg_keeps_controls:
                    z = "/var/lib/dpkg/info/" + p + ":" + a + "." + b
                    if not DPKG_MULTIARCH or not os.path.exists(z):
                        z = "/var/lib/dpkg/info/" + p + "." + b
                    if os.path.exists(z):
                        os.symlink(z, TD + "OLD/CONTROL/" + b)
                        control_file_triples.append((b, z, None))
                del z, p  # cannot delete 'a', python raise a SyntaxError
            # else... we always unpack the control of a .deb
        elif "needs-xdelta3" == a:
            if not os.path.exists("/usr/bin/xdelta3"):
                raise DebDeltaError(
                    'This patch needs xdelta3. Please install the Debian package "xdelta3".', retriable=True
                )
        elif "needs-xdelta3-fifo" == a:
            # not doing a specific check, I am using debian/control Conflicts
            if not os.path.exists("/usr/bin/xdelta3"):
                raise DebDeltaError(
                    'This patch needs xdelta3, at least version 3.0y. Please install the Debian package "xdelta3".',
                    retriable=True,
                )
        elif "needs-xdelta" == a:
            if not os.path.exists("/usr/bin/xdelta"):
                raise DebDeltaError(
                    'This patch needs xdelta. Please install the Debian package "xdelta".', retriable=True
                )
        elif "needs-bsdiff" == a:
            if not os.path.exists("/usr/bin/bsdiff"):
                raise DebDeltaError(
                    'This patch needs bsdiff. Please install the Debian package "bsdiff".', retriable=True
                )
        elif "needs-lzma" == a:
            if not os.path.exists("/usr/bin/lzma"):
                raise DebDeltaError('This patch needs lzma. Please install the Debian package "lzma".', retriable=True)
        elif "needs-xz" == a:
            if not os.path.exists("/usr/bin/xz"):
                raise DebDeltaError(
                    'This patch needs xz. Please install the Debian package "xz-utils".', retriable=True
                )
        elif "needs-minibzip2" == a:
            pass  # its your lucky day
        elif a[:6] == "needs-":
            raise DebDeltaError('patch says "' + a + "' and this is unsupported. Get a newer debdelta.", retriable=True)
        elif params[a]:
            logger.warning("WARNING patch says %r and this is unsupported. Get a newer debdelta.", a)

    if localepurged and not DEBUG:
        # actually we cannot be 100% sure that the delta really needs those files, but it is quite plausible
        raise DebDeltaError("Error, " + str(len(localepurged)) + " locale files are absent.")

    runtime["patchprogress"] = 12

    script_time = -(time.time())

    this_deb_format = DEB_FORMAT
    if this_deb_format != "deb" and "NEW/data.tar" not in params:
        # this patch does not support streaming
        logger.warn("Warning, created as standard deb: " + newdeb)
        this_deb_format = "deb"

    if this_deb_format == "preunpacked":  # need a fifo
        os.mkfifo(TD + "data.pipe")

    temp_err_name_fd, temp_err_name = tempfile.mkstemp(prefix="debdeltaE")
    temp_name_fd, temp_name = tempfile.mkstemp(prefix="debdeltaO")
    cmd = [SHELL, "-e", "PATCH/patch.sh"]
    if DEBUG > 2:
        cmd = [SHELL, "-evx", "PATCH/patch.sh"]
    if this_deb_format == "unzipped":
        cmd += ["unzipped"]
    elif this_deb_format == "preunpacked":
        cmd += ["piped"]

    env = {"PATH": os.getenv("PATH")}
    F = subprocess.Popen(
        cmd,
        cwd=TD,
        bufsize=4096,
        close_fds=True,
        stdin=open(os.devnull),
        env=env,
        stderr=temp_err_name_fd,
        stdout=temp_name_fd,
    )

    # data used by the preunpacked method
    data_md5 = None  # md5 of uncompressed data.tar
    tar_status = []  # should be [True] if 'preunpacked' went fine
    md5_status = []  # idem
    # this list contains tuples of (unpacked_temporary_filename, real_filename, owner, group, tartype, mode, mtime, linkname)
    preunpacked_filelist = []

    def do_cleanup():
        for a in preunpacked_filelist:
            pass
        # CHEAT we are not (yet) writing anything to disk
        # if a[0]: os.unlink(a[0])

    if this_deb_format == "preunpacked":  # do progress reporting and unpacking in filesystem

        def do_extension():
            return "_" + str(random.randint(1, 9999)).rjust(4, "0") + "_debdelta_preunpacked"

        def do_pipe_md5(i, o, rm, ms, ts):
            try:
                a = i.read(1024)
                while a and (ts == [] or ts == [True]):
                    rm.update(a)
                    o.write(a)
                    a = i.read(1024)
                    # TODO implement progress reporting here as well
                o.close()
                ms.append(True)
            except BaseException:
                import sys

                ms.append(sys.exc_info())
                if DEBUG:
                    logger.debug("  do_pipe_md5 crashed: " + repr(ms))

        def do_tar(i, fl, s):
            try:
                dt = tarfile.open(mode="r|", fileobj=i)
                for tarmember in dt:
                    if tarmember.isreg():
                        n = "/" + tarmember.name + do_extension()
                        while os.path.exists(n):  # wont overwrite existing stuff, never ever
                            n = "/" + tarmember.name + do_extension()
                    else:
                        n = ""
                    a = (
                        n,
                        tarmember.name,
                        tarmember.uname,
                        tarmember.gname,
                        tarmember.type,
                        tarmember.mode,
                        tarmember.mtime,
                        tarmember.linkname,
                    )
                    fl.append(a)
                    if n:
                        pass
                        # CHEAT we are not writing anything today!
                        # datatar.extract(tarmember,path=n)
                # successfully untarred!
                s.append(True)
            except BaseException:  # catch problems such as "out of disk space" or corrupted data
                import sys

                s.append(sys.exc_info())
                if DEBUG:
                    logger.debug("  do_tar crashed: " + repr(s))
                # flush input  (note that do_pipe_md5 will soon stop writing) no it seems useless #i.read()

        try:
            datapipe = open(TD + "data.pipe")
            rolling_md5 = hashlib.md5()
            (piper, pipew) = os.pipe()
            md5_thread = threading.Thread(
                target=do_pipe_md5,
                args=(open(TD + "data.pipe"), os.fdopen(pipew, "w"), rolling_md5, md5_status, tar_status),
            )
            tar_thread = threading.Thread(target=do_tar, args=(os.fdopen(piper), preunpacked_filelist, tar_status))
            # yeah maybe using two threads is more complex than strictly needed
            md5_thread.daemon = True
            md5_thread.start()
            tar_thread.daemon = True
            tar_thread.start()
            # join back the md5
            md5_thread.join()
            data_md5 = rolling_md5.hexdigest()
            if md5_status == [True] and params["NEW/data.tar"][:32] == data_md5:
                tar_thread.join()
                if tar_status == [True]:
                    F.wait()
                    # write data_list
                    a = open(TD + "data_list", "w")
                    a.write("Files:\n")
                    for (
                        unpacked_temporary_filename,
                        real_filename,
                        owner,
                        group,
                        tartype,
                        mode,
                        mtime,
                        linkname,
                    ) in preunpacked_filelist:
                        # to convert 'tar' type into 'ls' type
                        if tartype >= "0" and tartype <= "6":
                            tartype = "-hlcbdp"[ord(tartype) - ord("0")]
                        else:
                            tartype = "?"
                            logger.debug(
                                "WARNING unsupported tar type " + repr(tartype) + " for: " + repr(real_filename)
                            )
                        # if tartype < '0' or tartype > '6' :
                        #  tartype='?'
                        #  print 'WARNING unsupported tar type '+repr(tartype)+' for: '+repr(real_filename)
                        mode = oct(mode).rjust(4, "0")
                        a.write(
                            " %s %s %s %s %s\n %s\n %s\n %s\n"
                            % (tartype, mode, owner, group, mtime, unpacked_temporary_filename, real_filename, linkname)
                        )
                    a.close()
                    # append it into deb
                    system(["ar", "q", "NEW.file", "data_list"], TD)
        except BaseException:
            do_cleanup()
            raise
    else:  # progress reporting for deb_format != 'preunpacked'
        runtime["patchprogress"] = 12
        if "NEW/Size" in params and do_progress:
            NEW_size = int(params["NEW/Size"])
            while None == F.poll():
                if os.path.exists(TD + "NEW.file"):
                    a = os.path.getsize(TD + "NEW.file")
                    progress = int(12.0 + 84.0 * a / NEW_size)
                else:
                    progress = 12
                runtime["patchprogress"] = progress
                time.sleep(0.1)
                if do_progress:
                    sys.stderr.write("P %2d%% %s\r" % (progress, newdebshortname))
        F.wait()
    if do_progress and terminalcolumns:  # clean up
        sys.stderr.write(" " * terminalcolumns + "\r")
    ret = F.returncode
    os.close(temp_err_name_fd)
    os.close(temp_name_fd)

    script_time += time.time()  # for --format='preunpacked' this time also include data MD5
    runtime["patchprogress"] = 97

    # helper for debugging
    def tempos(f):
        if os.path.getsize(temp_name):
            f.append(temp_name)
        if os.path.getsize(temp_err_name):
            f.append(temp_err_name)

    if not FORENSIC:

        def fore():
            return None

    elif not os.path.isdir(olddeb):

        def fore():
            f = [delta, olddeb]
            tempos(f)
            return f

    else:

        def fore():
            temp_fore_name = ""
            f = []
            tempos(f)
            try:
                (temp_fd, temp_fore_name) = tempfile.mkstemp(prefix="debforensic_" + params["NEW/Package"] + "_")
                temp_file = os.fdopen(temp_fd, "w")
                temp_file.write("Delta: " + delta + "\n")
                temp_file.write("DeltaSHA1: " + hash_to_hex(sha1_hash_file(delta)) + "\n")
                temp_file.write("LocalePurgedFilesN: " + str(len(localepurged)) + "\n")
                temp_file.write("PrelinkUFailedN: " + str(len(prelink_u_failed)) + "\n")
                if ret:
                    temp_file.write("PatchExitCode: " + str(ret) + "\n")
                forensics_rfc(
                    temp_file,
                    params,
                    False,
                    control_file_triples,
                    file_triples,
                    conf_files,
                    diverted,
                    diversions,
                    localepurged,
                    prelink_u_failed,
                )
                # copy short content here and remove from list
                for i in copy(f):
                    if os.path.getsize(i) < 2000:
                        f.remove(i)
                        temp_file.write("PatchLogFile_" + str(i) + "_content:\n")
                        for ll in open(i):
                            temp_file.write(" " + repr(ll) + "\n")
                    else:
                        temp_file.write("PatchLogFileIs: " + str(i) + "\n")
                temp_file.close()
            except OSError:  # Exception,s:
                die("!!While creating forensic " + temp_fore_name + " error:" + str(s) + "\n")
            f.append(temp_fore_name)
            return f

    if ret:
        if localepurged:
            raise DebDeltaError('"debdelta" is incompatible with "localepurge".')
        else:
            f = fore()
            raise DebDeltaError("error in patch.sh.", logs=f)

    # then we check for the conformance
    if this_deb_format == "deb":
        if "NEW/Size" in params:
            newdebsize = os.stat(TD + "NEW.file")[ST_SIZE]
            if newdebsize != int(params["NEW/Size"]):
                f = fore()
                raise DebDeltaError("new deb size is " + str(newdebsize) + " instead of " + params["NEW/Size"], logs=f)

        if DO_MD5:
            if "NEW/MD5sum" in params:
                if VERBOSE > 1:
                    logger.debug("  verifying MD5  for %r", os.path.basename(newdeb or delta))
                m = compute_md5(open(TD + "NEW.file"))
                if params["NEW/MD5sum"] != m:
                    f = fore()
                    raise DebDeltaError(" MD5 mismatch, " + repr(params["NEW/MD5sum"]) + " != " + repr(m), logs=f)
            else:
                logger.warn(" Warning! no MD5 was verified for %r", os.path.basename(newdeb or delta))
    elif this_deb_format == "unzipped":
        if DO_MD5:
            c, b, z = untar_control_in_deb(list_ar(TD + "NEW.file"))
            p = PopenPipe(["ar", "p", (TD + "NEW.file"), c, "|"] + z, stdout=subprocess.PIPE)
            m = compute_md5(p.stdout)
            p.wait()
            if params["NEW/control.tar"][:32] != m:
                f = fore()
                raise DebDeltaError("MD5 mismatch for control.tar", logs=f)
            p = subprocess.Popen(["ar", "p", (TD + "NEW.file"), "data.tar"], stdout=subprocess.PIPE)
            m = compute_md5(p.stdout)
            p.wait()
            if params["NEW/data.tar"][:32] != m:
                f = fore()
                raise DebDeltaError("MD5 mismatch for data.tar", logs=f)
    elif this_deb_format == "preunpacked":
        if tar_status != [True]:
            f = fore()
            do_cleanup()
            raise DebDeltaError(
                "something bad happened in tar: " + repr(tar_status[0][1]), logs=f
            )  # todo format me better
        if md5_status != [True]:
            f = fore()
            do_cleanup()
            raise DebDeltaError(
                "something bad happened in md5: " + repr(md5_status[0][1]), logs=f
            )  # todo format me better
        # if DO_MD5: #actually we always do MD5
        m = compute_md5(
            subprocess.Popen(
                'ar p "%s" control.tar.gz | zcat' % (TD + "NEW.file"), stdout=subprocess.PIPE, shell=True
            ).stdout
        )
        if params["NEW/control.tar"][:32] != m:
            f = fore()
            do_cleanup()
            raise DebDeltaError("MD5 mismatch for control.tar", logs=f)
        if params["NEW/data.tar"][:32] != data_md5:
            f = fore()
            do_cleanup()
            raise DebDeltaError("MD5 mismatch for data.tar", logs=f)
    else:
        assert "unimplemented" == ""

    os.unlink(temp_name)
    os.unlink(temp_err_name)

    runtime["patchprogress"] = 99

    if newdeb:
        shutil.move(TD + "NEW.file", newdeb)

    end_sec = time.time()
    elaps = end_sec - start_sec

    if VERBOSE:
        if newdeb:
            debsize = os.stat(newdeb)[ST_SIZE]
        else:
            debsize = os.stat(olddeb)[ST_SIZE]
        # this printout uses kibibytes, and not SizeToStr, to ease statistics
        out = " " + _("Patching done, time %(time).2fsec, speed %(speed)dk/sec") % {
            "time": elaps,
            "speed": (debsize / 1024 / (elaps + 0.001)),
        }
        out += " " + _("(script %(time).2fsec %(speed)dk/sec)") % {
            "time": script_time,
            "speed": (debsize / 1024 / (script_time + 0.001)),
        }
        if prelink_time is not None and prelink_time > 0:
            prelink_datasize = prelink_datasize / 1024
            out += _("(prelink %(time).2fsec, %(size)dk, %(speed)dk/s)") % {
                "time": prelink_time,
                "size": prelink_datasize,
                "speed": prelink_datasize / (prelink_time + 0.001),
            }
            out += _("(unaccounted %.2fsec)") % (elaps - prelink_time - script_time)
        else:
            out += _("(unaccounted %.2fsec)") % (elaps - script_time)
        logger.info(out)
        # this is useless, if 'debpatch' it is in the command line, if 'debdelta-upgrade'
        # it is printed elsewhere
        # if newdeb != None:
        #  print 'result: '+os.path.basename(newdeb),
    return (newdeb, elaps)


# compute delta


def do_delta(olddeb, newdeb, delta):
    T = None
    try:
        T = tempo()
        if os.path.exists(delta + "_tmp_"):
            os.unlink(delta + "_tmp_")
        r = do_delta_(olddeb, newdeb, delta + "_tmp_", TD=T)
        (deltatmp, percent, elaps, info, gpg_hashes) = r
        info_hashes = append_info(deltatmp, info)
        if DO_GPG:
            gpg_hashes["info"] = info_hashes
            sign_delta(deltatmp, gpg_hashes)
        if os.path.exists(delta):
            os.rename(delta, delta + "~")
        os.rename(deltatmp, delta)
    except BaseException:
        if delta and os.path.exists(delta):
            os.unlink(delta)
        if delta and os.path.exists(delta + "_tmp_"):
            os.unlink(delta + "_tmp_")
        if T:
            rmtree(T)
        raise
    else:
        if T:
            rmtree(T)
    return r


def do_delta_(olddeb, newdeb, delta, TD, forensic_file=None, info=[]):
    """This function creates a delta. The delta is 'ar' archive (see 'man ar').
    The delta contains data, a script, and optional gpg signatures.
    The script recreates the new deb. Note that the deb is (again) an 'ar' archive,
    and has multiple members.
    Simple deb members are managed directly.
    The complex members are 'data.tar.xxx' and 'control.tar.gz' ;
    these are studied in the delta_tar() function, that in turn uses
    the Script() class.
    (Note that there is just one object instanced from Script(), in variable 'script').
    To recreate one of the complex members, there are two main steps in the script:
     (1) rebuild the member, uncompressed
     (2) recompress the member
    The part (2) is managed by script.zip_piped().
    The part (1) is more complex:
     (1a) there is a first subshell where data from the old version of the deb
       are piped to stdout (moreover some gzipped files may be transparently
      unzipped, delta-ed and re-gzipped, see delta_gzipped_files)
     (1b) the former (1a) is "piped" into the delta backend, to transform the old data into new.
     If the delta-backend is 'bsdiff' then the above process (1a,b) is repeated
     in chunks (indeed bsdiff cannot manage large files w/o exausting all your memory!)
    All the (chunks of) steps (1a,b) are in a subshell, and its result stdout is piped in (2).
    """
    if TD[-1] != "/":
        TD = TD + "/"

    import fnmatch

    start_sec = time.time()

    # I do not like global variables but I do not know of another solution
    global bsdiff_time, bsdiff_datasize
    bsdiff_time = 0
    bsdiff_datasize = 0

    olddeb = abspath(olddeb)
    check_deb(olddeb)
    os.symlink(olddeb, TD + "/OLD.file")
    olddebsize = os.stat(olddeb)[ST_SIZE]

    newdeb = abspath(newdeb)
    check_deb(newdeb)
    os.symlink(newdeb, TD + "/NEW.file")
    newdebsize = os.stat(newdeb)[ST_SIZE]

    # process all contents of old vs new .deb
    ar_list_old = list_ar(TD + "OLD.file")
    ar_list_new = list_ar(TD + "NEW.file")

    free = freespace(TD)
    if free and free < newdebsize:
        raise DebDeltaError("Error: not enough disk space in " + TD, True)

    delta = abspath(delta)

    # generater for numbered files
    def a_numb_file_gen():
        deltacount = 0
        while True:
            yield str(deltacount)
            deltacount += 1

    a_numb_file = a_numb_file_gen()
    a_numb_patch = a_numb_file_gen()

    ####################### class Script ########################
    class Script:
        """This class helps create the script 'patch.sh' that is the core of the delta.
        The script recreates the new deb. See documentation of do_delta_() for details.
        """

        def __init__(self, delta_uses_infifo):
            # start writing script
            self.fd = open(TD + "PATCH/patch.sh", "w")
            self.fd.write("#!/bin/bash -e\n")
            self.member = None
            self.current_chunk_name = None
            self.delta_uses_infifo = delta_uses_infifo
            if delta_uses_infifo:  # create the fifo as input for xdelta3
                self.the_fifo = a_numb_file.next()
                self.fd.write("mkfifo %s\n" % self.the_fifo)
            else:
                self.the_fifo = None
            # this is used when recompressing data.tar.zx
            self.xz_parameters = None
            # this is used when recompressing data.tar.gz
            self.gz_command = None

        def write(self, s):
            "verbatim write in the script"
            self.fd.write(s)

        def close(self):
            if self.the_fifo:
                self.fd.write("rm %s\n" % self.the_fifo)
            self.fd.close()

        def zip(self, n, cn, newhead=None):
            """inverts the unzip() function ; optionally, forces .gz header (to fight changes in libz)
            This is obsolete, not efficient, left as a compatibility layer."""
            self.fd.write('cat "' + n + '" | ')
            self.zip_piped(cn, newhead)
            self.fd.write(" > '" + n + cn + "' && rm '" + n + "'\n")

        def zip_piped(self, cn, newhead=None):
            "inverts the unzip() function, with piped behaviour"
            if cn == ".gz":
                cmd = string.join(self.gz_command, " ")
                if newhead:
                    s = prepare_for_echo(newhead)
                    self.fd.write("($E '" + s + "' && " + cmd + " | tail -c +" + str(len(newhead) + 1) + ")")
                else:
                    self.fd.write(cmd)
            elif cn == ".bz2":
                info_append("needs-minibzip2")
                self.fd.write("./minibzip2 -9")
            elif cn == ".lzma":
                info_append("needs-lzma")
                self.fd.write("lzma -9")
            elif cn == ".xz":
                info_append("needs-xz")
                if self.xz_parameters is None:
                    self.fd.write("xz -c")
                else:
                    self.fd.write("xz -c " + self.xz_parameters)
            else:
                assert 0

        def start_member(self, ar_line, newname, extrachar):
            "start a new 'ar' member"
            self.member = newname
            self.ar_line = ar_line
            self.extrachar = extrachar
            assert self.current_chunk_name is None
            self.fd.write("{\n")

        def end_member(self):
            assert self.member
            self.member = None
            self.fd.write("}\n")

        def start_rebuilding(self):
            "starts the first part of the delta/recompressing pipe (for a 'ar' member)"
            self.fd.write("(")

        def end_rebuilding(self):
            "ends the first part of the delta/recompressing pipe"
            self.fd.write(")|")  # pipe the delta/recompressing pipe

        def recompressing(self, new_filename, new_filename_ext, new_file_zip_head):
            self.fd.write("(")
            append_NEW_file(self.ar_line)
            script.zip_piped(new_filename_ext, new_file_zip_head)
            self.fd.write(" >> NEW.file\n")  # end delta tar
            if self.extrachar:
                append_NEW_file(self.extrachar)
            self.fd.write(")\n")

        def recompressing_by_arg(self, new_filename, new_filename_ext, new_file_zip_head, new_file_size):
            "flexible recompressing for data.tar , depending on first argument passed to the script"
            self.fd.write('( if test "$1" = "" \n then\n')
            self.recompressing(new_filename, new_filename_ext, new_file_zip_head)
            self.fd.write('elif test "$1" = "unzipped" \n then\n')
            # http://en.wikipedia.org/wiki/Ar_(Unix)
            assert new_filename == "NEW/data.tar"
            ar_line_unzipped = "data.tar".ljust(16) + self.ar_line[16:48] + str(new_file_size).ljust(10) + "`\n"
            append_NEW_file(ar_line_unzipped)  # there is no extra char, tar is 512b blocks
            self.fd.write('cat >> NEW.file \n elif test "$1" = "piped" \n then cat >> data.pipe \n fi )\n')

        def start_chunk(self, current_chunk_name):
            "start the pipe to create the chunk. The chunk is always piped"
            self.fd.write("(")
            self.current_chunk_name = current_chunk_name

        def end_chunk(self, current_chunk_name):
            """this ends the 'data part' of a chunk, and writes the old data somewhere;
            a successive script code (generated by delta_files() )
            will then delta it to transform old data into new data."""
            assert self.current_chunk_name == current_chunk_name
            if self.the_fifo:
                self.fd.write(") > " + self.the_fifo + "&\n")  # write to fifo, background
            else:
                self.fd.write(") > " + current_chunk_name + "\n")  # write chunk
            self.current_chunk_name = None

        def md5_check_file(self, n, md5=None):
            "add a md5 check in the script (this is done only if a lot -d are passed on cmdline)"
            if md5 is None:
                assert os.path.isfile(TD + n)
                md5 = compute_md5(TD + n)
            logger.debug("    adding extra MD5 for %r", n)
            self.fd.write(
                'if ! echo "%s  %s" | md5sum -c --quiet ; then echo "%s is currupt!"; exit 1; fi\n' % (md5, n, n)
            )

    ####################### end of class Script ########################

    # unpack control.tar.gz, scan control, write  parameters
    #
    def info_append(s):
        "smart appending that avoids duplicate entries"
        if s not in info:
            info.append(s)

    for o, l in ("OLD", ar_list_old), ("NEW", ar_list_new):
        os.mkdir(TD + o + "/CONTROL")
        # unpack control.tar.gz
        f = None
        for a in l:
            if a[:12] == "control.tar.":
                f = a
        b = {".gz": "-z", ".xz": "-J", ".bz2": "-j"}.get(f[11:])
        system(("ar", "p", TD + o + ".file", f, "|", "tar", b, "-xf", "-", "-C", TD + o + "/CONTROL"), TD)
        # scan control
        p = open(TD + "/" + o + "/CONTROL/control")
        s = []
        scan_control(p, params=None, prefix=o, info=s)
        p.close()
        if VERBOSE:
            logger.debug(" " + o + ": " + join([o[4:] for o in s], " "))
        info = info + s
        del s, p
    info.append("OLD/Size: " + str(olddebsize))
    info.append("NEW/Size: " + str(newdebsize))
    params = info_2_db(info)

    # scan debdelta.conf to find any special requirement
    debdelta_conf = ConfigParser.SafeConfigParser()
    debdelta_conf.read(["/etc/debdelta/debdelta.conf", expanduser("~/.debdelta/debdelta.conf")])

    debdelta_conf_skip = []
    for s in debdelta_conf.sections():
        if fnmatch.fnmatch(params["OLD/Package"], s):
            opt = debdelta_conf.options(s)
            if "skip" in opt:
                debdelta_conf_skip += debdelta_conf.get(s, "skip").split(";")
            break

    if VERBOSE > 1:
        logger.debug("  debdelta.conf says we will skip: %r", debdelta_conf_skip)

    gpg_hashes = {}

    if DO_MD5:
        # compute a MD5 of NEW deb
        newdeb_md5sum = compute_md5(TD + "NEW.file")
        info.append("NEW/MD5sum: " + newdeb_md5sum)
    else:
        newdeb_md5sum = None

    if NEEDSOLD:
        # this delta needs the old deb
        info.append("needs-old")
    else:
        info.append("old-data-tree")
        info.append("old-control-tree")

    # do we use a fifo as input for xdelta3
    delta_uses_infifo = ("xdelta3-fifo" not in DISABLED_FEATURES) and (USE_DELTA_ALGO == "xdelta3")

    # Note that there is just one object instanced from class Script()
    script = Script(delta_uses_infifo)

    a = USE_DELTA_ALGO
    if a == "xdelta-bzip":
        a = "xdelta"
    if not os.path.exists("/usr/bin/" + a):
        raise DebDeltaError('please install the package "' + a + '".', retriable=True)
    if delta_uses_infifo:
        info.append("needs-xdelta3-fifo")
    else:
        info.append("needs-" + a)
    del a

    # check for disk space
    if "NEW/Installed-Size" in params and "OLD/Installed-Size" in params:
        free = freespace(TD)
        instsize = int(params["NEW/Installed-Size"]) + int(params["OLD/Installed-Size"])
        if free and free < (instsize * 1024 + +(2 ** 23) + MAXMEMORY / 6):
            raise DebDeltaError(
                " Not enough disk space (%dkB) for creating delta (needs %dkB)." % (int(free / 1024), instsize), True
            )

    # check for conffiles
    a = TD + "/OLD/CONTROL/conffiles"
    if os.path.exists(a):
        p = open(a)
        # files do not have leading /
        old_conffiles = [de_bar(a) for a in p.read().split("\n") if a]
        p.close()
    else:
        old_conffiles = []

    # a=TD+'/OLD/CONTROL/list'
    # if os.path.exists(a):
    # p=open(a)
    # for a in p:
    # a=de_bar(de_n(a))
    # for j in debdelta_conf_skip:
    # if fnmatch(a,j):
    # old_conffiles.append(a) #OK, this abuses the name of the var a bit
    # print ' REPR skip ',repr(a)
    # else:
    # print '  The old debian package ',olddeb,' does not contain a file list?!?'

    def shell_not_allowed(name):
        "Strings that I do not trust to inject into the shell script; maybe I am a tad too paranoid..."
        # FIXME should use it , by properly quoting for the shell script
        return '"' in name or "'" in name or "\\" in name or "`" in name

    # uses MD5 to detect identical files (even when renamed)
    def scan_md5(n):
        md5 = {}
        f = open(n)
        a = de_n(f.readline())
        while a:
            m, n = a[:32], de_bar(a[34:])
            md5[n] = m
            a = de_n(f.readline())
        f.close()
        return md5

    new_md5 = None
    if os.path.exists(TD + "/NEW/CONTROL/md5sums"):
        new_md5 = scan_md5(TD + "/NEW/CONTROL/md5sums")

    old_md5 = None
    if os.path.exists(TD + "/OLD/CONTROL/md5sums"):
        old_md5 = scan_md5(TD + "/OLD/CONTROL/md5sums")

    # some routines  to prepare delta of two files

    def patch_append(f):
        # possibly GPG
        if DO_GPG:
            gpg_hashes[f] = _compute_hashes_(TD + "PATCH/" + f)
        if VERBOSE > 2:
            a = os.stat(TD + "PATCH/" + f)[ST_SIZE]
            logger.debug("   appending %r of size %d to delta, %3.2f%% of new .deb", f, a, (a * 100.0 / newdebsize))
        system(["ar", "qSc", delta, f], TD + "/PATCH")
        unlink(TD + "PATCH/" + f)

    def verbatim(f):
        pp = a_numb_patch.next()
        p = "PATCH/" + pp
        if VERBOSE > 1:
            logger.debug("  including %r verbatim in patch", name)
        os.rename(TD + f, TD + p)
        patch_append(pp)
        return p

    def unzip(f):
        c = ""
        if f[-3:] == ".gz":
            system(("gunzip", f), TD)
            f = f[:-3]
            c = ".gz"
        elif f[-4:] == ".bz2":
            system(("bunzip2", f), TD)
            f = f[:-4]
            c = ".bz2"
        elif f[-5:] == ".lzma":
            info_append("needs-lzma")
            system(("unlzma", f), TD)
            f = f[:-5]
            c = ".lzma"
        elif f[-3:] == ".xz":
            info_append("needs-xz")
            system(("unxz", f), TD)
            f = f[:-3]
            c = ".xz"
        else:
            raise NotImplementedError(" dont know how to decompress " + repr(f))
        return (f, c)

    def delta_files__(o, n, p, algo, outpiped, infifo):
        "delta of file 'o' to 'n' using/producing patch 'p' ; xdelta3 can also pipe"
        this_delta_outpiped = False
        # bdiff
        # http://www.webalice.it/g_pochini/bdiff/
        if algo == "bdiff":
            system(("~/debdelta/bdiff-1.0.5/bdiff", "-q", "-nooldmd5", "-nonewmd5", "-d", o, n, p), TD)
            script.write("~/debdelta/bdiff-1.0.5/bdiff -p " + o + " " + p + " " + n + "\n")
        # zdelta
        # http://cis.poly.edu/zdelta/
        elif algo == "zdelta":
            system(("~/debdelta/zdelta-2.1/zdc", o, n, p), TD)
            script.write("~/debdelta/zdelta-2.1/zdu " + o + " " + p + " " + n + "\n")
        # bdelta
        # http://deltup.sf.net
        elif algo == "bdelta":
            system(("~/debdelta/bdelta-0.1.0/bdelta", o, n, p), TD)
            script.write("~/debdelta/bdelta-0.1.0/bpatch " + o + " " + n + " " + p + "\n")
        # diffball
        # http://developer.berlios.de/projects/diffball/
        elif algo == "diffball":
            system(("~/debdelta/diffball-0.7.2/differ", o, n, p), TD)
            script.write("~/debdelta/diffball-0.7.2/patcher " + o + " " + p + " " + n + "\n")
        # rdiff
        elif algo == "rdiff":
            system(("rdiff", "signature", o, "sign_file.tmp"), TD)
            system(("rdiff", "delta", "sign_file.tmp", n, p), TD)
            script.write("rdiff patch " + o + " " + p + " " + n + "\n")
        # xdelta3
        elif algo == "xdelta3":
            system(("xdelta3", "-9", "-R", "-D", "-n", "-S", "djw", "-s", o, n, p), TD)
            if infifo:
                o = infifo  # use fifo as input
            if outpiped:
                this_delta_outpiped = True
                script.write("xdelta3 -d -R -D -c -s " + o + " " + p + "\n")
            else:
                script.write("xdelta3 -d -R -D -s " + o + " " + p + " " + n + "\n")
        # according to the man page,
        # bsdiff uses memory equal to 17 times the size of oldfile
        # but , in my experiments, this number is more like 12.
        # But bsdiff is sooooo slow!
        elif algo == "bsdiff":  # not ALLOW_XDELTA or ( osize < (MAXMEMORY / 12)):
            system(("bsdiff", o, n, p), TD)
            script.write("bspatch " + o + " " + n + " " + p + "\n")
        # seems that 'xdelta' is buggy on 64bit and different-endian machines
        # xdelta does not deal with different endianness!
        elif algo == "xdelta-bzip":
            system(
                ("xdelta", "delta", "--pristine", "--noverify", "-0", "-m" + str(int(MAXMEMORY / 1024)) + "k", o, n, p),
                TD,
            )
            system("bzip2 -9 " + p, TD, (p,))
            script.write("bunzip2 " + p + ".bz2 ; xdelta patch " + p + " " + o + " " + n + "\n")
            p += ".bz2"
        elif algo == "xdelta":
            system(
                ("xdelta", "delta", "--pristine", "--noverify", "-9", "-m" + str(int(MAXMEMORY / 1024)) + "k", o, n, p),
                TD,
            )
            script.write("xdelta patch " + p + " " + o + " " + n + "\n")
        elif algo == "jojodiff":
            system(("~/debdelta/jdiff06/src/jdiff", "-b", o, n, p), TD)
            script.write("~/debdelta/jdiff06/src/jpatch " + o + " " + p + " " + n + "\n")
        else:
            raise AssertionError(" unsupported delta algo ")
        return p, this_delta_outpiped

    def delta_files(o, n, outpiped=None, infifo=None):
        " compute delta of two files , and prepare the script consequently"
        nsize = os.path.getsize(TD + n)
        osize = os.path.getsize(TD + o)
        if VERBOSE > 1:
            logger.debug("  compute delta for %s (%dkB) and %s (%dkB)", o, osize / 1024, n, nsize / 1024)
        #
        p = "PATCH/" + a_numb_patch.next()
        tim = -(time.time())
        #
        if DEBUG > 3:
            script.md5_check_file(o)
        #
        if USE_DELTA_ALGO == "bsdiff" and osize > (1.1 * (MAXMEMORY / 12)) and VERBOSE:
            logger.debug(" Warning, memory usage by bsdiff on the order of %dMb", (12 * osize / 2 ** 20))
        #
        p, this_delta_outpiped = delta_files__(o, n, p, USE_DELTA_ALGO, outpiped, infifo)
        # script.write(s)
        #
        if DEBUG > 2 and not this_delta_outpiped:
            script.md5_check_file(n)
        #
        tim += time.time()
        #
        global bsdiff_time, bsdiff_datasize
        bsdiff_time += tim
        bsdiff_datasize += nsize
        #
        if infifo:
            script.write("rm " + p + "\n")
        else:
            script.write("rm " + o + " " + p + "\n")
        # how did we fare ?
        deltasize = os.path.getsize(TD + p)
        if VERBOSE > 1:
            logger.debug(
                "  delta is %3.2f%% of %s, speed: %dkB /sec",
                (deltasize * 100.0 / nsize),
                n,
                (nsize / 1024.0 / (tim + 0.001)),
            )
        # save it
        patch_append(p[6:])
        # clean up
        unlink(TD + o)
        return this_delta_outpiped

    def cmp_gz(o, n):
        "compare gzip files, ignoring header; returns first different byte (+-10), or True if equal"
        of = open(o)
        nf = open(n)
        oa = of.read(10)
        na = nf.read(10)
        if na[:3] != "\037\213\010":
            logger.warn(" Warning: was not created with gzip: %r", n)
            nf.close()
            of.close()
            return 0
        if oa[:3] != "\037\213\010":
            logger.warn(" Warning: was not created with gzip: %r", o)
            nf.close()
            of.close()
            return 0
        oflag = ord(oa[3])
        if oflag & 0xF7:
            logger.warn(" Warning: unsupported  .gz flags: %r %r", oct(oflag), o)
        if oflag & 8:  # skip orig name
            oa = of.read(1)
            while ord(oa) != 0:
                oa = of.read(1)
        l = 10
        nflag = ord(na[3])
        if nflag & 0xF7:
            logger.warn(" Warning: unsupported  .gz flags: %r %r", oct(nflag), n)
        if nflag & 8:  # skip orig name
            na = nf.read(1)
            s = na
            while ord(na) != 0:
                na = nf.read(1)
                s += na
            l += len(s)
            # print repr(s)
        while oa and na:
            oa = of.read(2)
            na = nf.read(2)
            if oa != na:
                return l
            l += 2
        if oa or na:
            return l
        return True

    def parse_gzip_header(n):
        " n may be a file name, a function returning a stream, or a stream"
        if type(n) in string_types:
            f = open(TD + n)
            a = f.read(10)
            f.close()
        elif type(n) in (FunctionType, LambdaType):
            f = n()
            a = f.read(10)
            if isinstance(f, PopenPipe):
                f.close()
        else:
            a = n.read(10)
        if a[:3] != "\037\213\010":
            logger.debug(" Warning: was not created with gzip: %r", n)
            return
        flag = ord(a[3])  # mostly ignored  :->
        orig_name = "-n"
        if flag & 8:
            orig_name = "-N"
        if flag & 0xF7:
            logger.debug(" Warning: unsupported  .gz flags: %r %r", oct(flag), n)
        # a[4:8] #mtime ! ignored ! FIXME will be changed...
        # from deflate.c in gzip source code
        format = ord(a[8])
        FAST = 4
        SLOW = 2  # unfortunately intermediate steps are lost....
        pack_level = 6
        if format == 0:
            pass
        elif format == FAST:
            pack_level = 1
        elif format == SLOW:
            pack_level = 9
        else:
            logger.debug(" Warning: unsupported compression .gz format: %r %r", oct(format), n)
            return
        if a[9] != "\003":
            if VERBOSE:
                logger.debug(" Warning: unknown OS in .gz format: %r %r", oct(ord(a[9])), n)
        pack_list = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        del pack_list[pack_level - 1]
        pack_list.append(pack_level)
        pack_list.reverse()
        # print 'format ', repr(format), type(format), format==FAST, pack_list
        return pack_list, orig_name

    def delta_gzipped_files(o, n):
        "delta o and n, replace o with n"
        assert o[-3:] == ".gz" and n[-3:] == ".gz"
        before = cmp_gz(TD + o, TD + n)
        if before:
            if VERBOSE > 3:
                logger.debug("    equal but for header: %r", n)
            return
        # compare the cost of leaving as is , VS the minimum cost of delta
        newsize = os.path.getsize(TD + n)
        if (newsize - before + 10) < 200:
            if VERBOSE > 3:
                logger.debug("    not worthwhile gunzipping: %r", n)
            return
        z = parse_gzip_header(n)
        if z is None:
            return
        pack_list, orig_name = z
        pack_level = pack_list[0]
        # OK, it seems we can play our trick
        p = "_tmp_"
        # unzip new file
        pro = subprocess.Popen(("zcat", TD + n), stdout=open(TD + p + ".new", "w"), cwd=TD)
        pro.wait()
        if pro.returncode:
            raise DebDeltaError("argghh, zcat failed on us")
        # test our ability of recompressing
        best_r = 0
        best_flag = None
        for i in pack_list:
            # force -n  ... no problem with timestamps
            gzip_flags = "-" + str(i)
            pro = subprocess.Popen(
                ("gzip", "-c", "-n", gzip_flags, TD + p + ".new"), stdout=open(TD + p + ".faked.gz", "w")
            )
            pro.wait()
            if pro.returncode:
                DebDeltaError("Argh, gzip failed on us")
            r = cmp_gz(TD + n, TD + p + ".faked.gz")
            if r > best_r:
                best_r = r
                best_flag = gzip_flags
            if r:
                break
            if i == pack_level and VERBOSE > 3:
                logger.debug("    warning: wrong guess to re-gzip to equal file: %r %r %r", gzip_flags, r, n)
        if not r:
            if VERBOSE > 1:
                logger.debug(
                    '  warning: cannot re-gzip to equal file, best was %d / %d , "%s" : %s ',
                    best_r,
                    newsize,
                    best_flag,
                    n,
                )
            os.unlink(TD + p + ".new")
            os.unlink(TD + p + ".faked.gz")
            return
        # actual delta of decompressed files
        pro = subprocess.Popen(("zcat", TD + o), stdout=open(TD + p + ".old", "w"), cwd=TD)
        pro.wait()
        if pro.returncode:
            raise DebDeltaError("argh, zcat failed on us")
        script.write("zcat '" + o + "' > " + p + ".old ; rm '" + o + "' \n")
        if VERBOSE > 2:
            logger.debug("   " + n[9:] + ("  (= to %d%%): " % (100 * before / newsize)))
        delta_files(p + ".old", p + ".new")
        script.write("gzip -c -n " + gzip_flags + " < " + p + ".new  > '" + o + "' ; rm " + p + ".new\n")
        # replace the old file with the best that we can do re-gzipping the new file
        # this is important in the rest of the delta-ing process
        os.rename(TD + p + ".faked.gz", TD + o)
        if DEBUG > 1:
            script.md5_check_file(o, compute_md5(TD + o))

    def guess_gz_command(o, check=True):
        """tries to guess the parameters used to compress, returns a command vector
          if it fails, returns False
         o may be a file name, a function returning a stream, or a stream
        """
        h = parse_gzip_header(o)
        if h is None:
            return False
        if type(o) in (FunctionType, LambdaType):
            o = o()
        elif type(o) in string_types:
            o = open(o)
        z = tempfile.NamedTemporaryFile(suffix=".gz", delete=False)
        shutil.copyfileobj(o, z)
        z.flush()
        if isinstance(o, PopenPipe):
            o.close()
        pack_list, orig_name = h
        pack_list.reverse()
        cmd_list = [(["gzip", "-nc"], l) for l in pack_list]
        cmd_list.append(([minigzip], 9))  # old method up to dpkg-deb in 2014-01-15
        wcmd = False  # fixme, there is no way to distinguish output of minigzip or gzip from header
        if check:
            redo = True
            while redo and cmd_list:
                cmd, par = cmd_list.pop()
                wcmd = copy(cmd)
                wcmd.append("-" + str(par))
                if VERBOSE > 2:
                    logger.debug("   Testing command %r", wcmd)
                w = PopenPipe(
                    ["zcat", z.name, "|"] + wcmd + ["|", "cmp", "-", z.name],
                    stdout=open(os.devnull, "w"),
                    stderr=open(os.devnull, "w"),
                    close_fds=True,
                )
                redo = False
                w.wait()
                if w.returncode:
                    redo = True
                    if VERBOSE or DEBUG:
                        logger.debug("  Tried gzip options but failed: %r", wcmd)
                elif VERBOSE > 2:
                    logger.debug("   Success with command %r", wcmd)
                if redo and not cmd_list:
                    logger.debug("  NO MORE OPTIONS !")
                    os.unlink(z.name)
                    return False
        os.unlink(z.name)
        return wcmd

    def guess_xz_parameters(o, check=True):
        """tries to guess the parameters used to compress, returns a  a string of options
          if it fails, returns False
           o may be a file name, a function returning a stream, or a stream
        """
        par = ""
        crc = ""
        thread = ""
        if type(o) in (FunctionType, LambdaType):
            o = o()
        elif type(o) in string_types:
            o = open(o)
        z = tempfile.NamedTemporaryFile(suffix=".xz", delete=False)
        # unfortunately 'xz --list' does not work on pipes!
        shutil.copyfileobj(o, z)
        z.flush()
        if isinstance(o, PopenPipe):
            o.close()
        b = subprocess.Popen(["xz", "-vv", "--robot", "--list", z.name], stdout=subprocess.PIPE)
        for a in b.stdout:
            a = a.rstrip("\n")
            a = string.split(a, "\t")
            if a[0] == "block":
                if crc and crc != a[9]:
                    logger.warn(
                        "  warning : this xz -- compressed file was compressed with variable blocks crc ?! '%s' != '%s'",
                        crc,
                        a[9],
                    )
                crc = a[9]
                if par and par != a[15]:
                    logger.warn(
                        "  warning : this xz -- compressed file was compressed with variable blocks options ?! '%s' != '%s'",
                        par,
                        a[15],
                    )
                par = a[15]
                if not thread and a[12] == "cu":
                    thread = "-T2"
        # print ' guessed par crc ',par,crc
        if crc:
            crc = crc.lower()
            if crc == "sha-256":
                crc = "sha256"
            if crc not in ("crc32", "crc64", "sha256"):
                logger.warn(" Unknown XZ crc %r", crc)
                crc = ""
        PARS = ["-6e", "-9", "-9e"]
        if par:
            PARS.append(par)
            if par == "--lzma2=dict=1MiB":
                # dbgsym deb files are compressed with -1e
                PARS.append("-1")
                PARS.append("-1e")
        if check:
            redo = True
            while redo and PARS:
                par = PARS.pop()
                w = ["xz", "-c"]
                if par:
                    w.append(par)
                if crc:
                    w += ["-C", crc]
                if thread:
                    w.append(thread)
                w.append("-")
                if VERBOSE > 2:
                    logger.debug("   Testing XZ options %r", w)
                redo = False
                c = PopenPipe(
                    ["unxz", "-c", z.name, "|"] + w + ["|", "cmp", "-", z.name],
                    stdout=open(os.devnull, "w"),
                    stderr=open(os.devnull, "w"),
                    close_fds=True,
                )
                c.wait()
                if c.returncode:
                    redo = True
                    if VERBOSE or DEBUG:
                        logger.debug(" Tried XZ options but failed: %r %r %r", par, crc, thread)
                if redo and not PARS:
                    # print '  HO FINITO LE OPZIONI !'
                    os.unlink(z.name)
                    return False
        if crc:
            crc = " -C " + crc
        if thread:
            thread = " " + thread
        os.unlink(z.name)
        return par + crc + thread

    # helper sh functions for script, for delta_tar()

    import difflib
    import re

    re_numbers = re.compile(r"^[0-9][0-9]*$")

    def file_similarity_premangle(fp):
        fps = fp.split("/")
        bns = fps[-1].split(".")
        j = len(bns) - 1  # search first "non numeric" extension, and put it last
        while j >= 0 and re_numbers.match(bns[j]):
            j -= 1
        if j >= 0:
            a = bns.pop(j)
            r = fps[:-1] + bns + [a]
        else:
            r = fps[:-1] + bns
        return r

    def files_similarity_score__noext__(oo, nn):
        ln = len(nn)
        lo = len(oo)
        l = 0
        while oo and nn:
            while oo and nn and oo[-1] == nn[-1]:
                oo = oo[:-1]
                nn = nn[:-1]
            if not oo or not nn:
                break
            while oo and nn and oo[0] == nn[0]:
                oo = oo[1:]
                nn = nn[1:]
            if not oo or not nn:
                break
            if len(nn) > 1 and oo[0] == nn[1]:
                l += 1
                nn = nn[1:]
            if len(oo) > 1 and oo[1] == nn[0]:
                l += 1
                oo = oo[1:]
            if not oo or not nn:
                break
            if oo[-1] != nn[-1]:
                oo = oo[:-1]
                nn = nn[:-1]
                l += 2
            if not oo or not nn:
                break
            if oo[0] != nn[0]:
                oo = oo[1:]
                nn = nn[1:]
                l += 2
        return (l + len(oo) + len(nn)) * 2.0 / float(ln + lo)

    def files_similarity_score__(oo, nn):
        oo = copy(oo)
        nn = copy(nn)
        if oo.pop() != nn.pop():
            return 0.2 + files_similarity_score__noext__(oo, nn)
        else:
            return files_similarity_score__noext__(oo, nn)

    def files_similarity_score__difflib__(oo, nn):
        "compute similarity by difflib. Too slow."
        if oo == nn:
            return 0
        d = difflib.context_diff(oo, nn, "", "", "", "", 0, "")
        d = [a for a in tuple(d) if a and a[:3] != "---" and a[:3] != "***"]
        if oo[-1] != nn[-1]:  # penalty for wrong extension
            return 0.2 + float(len(d)) * 2.0 / float(len(oo) + len(nn))
        else:
            return float(len(d)) * 2.0 / float(len(oo) + len(nn))

    def files_similarity_score(oo, nn):
        if oo == nn:
            return 0
        if type(oo) in string_types:
            oo = file_similarity_premangle(oo)
        if type(nn) in string_types:
            nn = file_similarity_premangle(nn)
        return files_similarity_score__(oo, nn)

    def fake_tar_header_2nd():
        " returns the second part of a tar header , for regular files and dirs"
        # The following code was contributed by Detlef Lannert.
        # into /usr/lib/python2.3/tarfile.py
        MAGIC = "ustar"  # magic tar string
        VERSION = "00"  # version number
        NUL = "\0"  # the null character
        parts = []
        for value, fieldsize in (
            ("", 100),
            # unfortunately this is not what DPKG does
            # (MAGIC, 6),
            # (VERSION, 2),
            #  this is  what DPKG does
            ("ustar  \x00", 8),
            ("root", 32),
            ("root", 32),
            ("%07o" % 0, 8),
            ("%07o" % 0, 8),
            ("", 155),
        ):
            l = len(value)
            parts.append(value + (fieldsize - l) * NUL)
        buf = "".join(parts)
        return buf

    fake_tar_2nd = fake_tar_header_2nd()
    fake_tar_2nd_echo = prepare_for_echo(fake_tar_2nd)
    script.write("FTH='" + fake_tar_2nd_echo + "'\n")
    script.write("E='echo -ne'\n")

    global time_corr
    time_corr = 0

    ####################  vvv     delta_tar    vvv ###########################
    def delta_tar(
        old_filename,
        new_filename,
        CWD,
        old_forensic,
        skip=[],
        old_md5={},
        new_md5={},
        chunked_p=(not delta_uses_infifo),
        debdelta_conf_skip=(),
    ):
        " compute delta of two tar files, and prepare the script consequently"
        assert type(old_filename) in string_types or isinstance(old_filename, FunctionType)

        script.write('ECR () { $E "$1" ; $E "${FTH}" ; cat OLD/' + CWD + '/"$1" ; rm OLD/' + CWD + '/"$1" ;}\n')
        script.write('EC () { $E "$1" ; $E "${FTH}" ; cat OLD/' + CWD + '/"$1" ;}\n')

        # uncompress and scan the old tar file, extract regular files
        if type(old_filename) in string_types:
            (old_filename, old_filename_ext) = unzip(old_filename)
            oldtar = tarfile.open(TD + old_filename, "r")
        elif type(old_filename) in (FunctionType, LambdaType):
            old_filename_ext = None
            oldfileobj = old_filename()
            oldtar = tarfile.open(mode="r|", fileobj=oldfileobj)
        else:
            old_filename_ext = None
            oldtar = tarfile.open(mode="r|", fileobj=old_filename)
        oldnames = []
        oldtarinfos = {}
        for oldtarinfo in oldtar:
            oldname = de_bar(oldtarinfo.name)
            if old_forensic is not None:
                # fixme : devices are not supported (but debian policy does not allow them)
                old_forensic.append(
                    [
                        oldtarinfo.name,
                        oldtarinfo.mode,
                        oldtarinfo.type,
                        oldtarinfo.uid,
                        oldtarinfo.gid,
                        oldtarinfo.uname,
                        oldtarinfo.gname,
                        oldtarinfo.linkname,
                    ]
                )
            # this always happens
            # if VERBOSE > 3 and oldname != de_bar(oldname):
            #  print '     filename in old tar has weird ./ in front: ' , oldname

            if not oldtarinfo.isreg():
                if VERBOSE > 2:
                    logger.debug("  skipping old non-regular %r", oldname)
                continue

            if oldtarinfo.size == 0:
                if VERBOSE > 2:
                    logger.debug("  skipping old empty %r", oldname)
                continue

            if shell_not_allowed(oldname):
                if VERBOSE > 2:
                    logger.debug("  skipping non-allowed-name %r", oldname)
                continue

            for j in debdelta_conf_skip:
                if fnmatch.fnmatch(oldname, j):
                    if VERBOSE > 2:
                        logger.debug("  skipping following as per rule %r", j)
                    skip.append(oldname)
                    break

            if oldname in skip:
                if VERBOSE > 2:
                    logger.debug("  skipping %r", oldname)
                if old_forensic is not None:
                    oldtar.extract(oldtarinfo, TD + "OLD/" + CWD)
                    old_forensic.append(
                        old_forensic.pop()[:-1] + [hash_to_hex(sha1_hash_file(os.path.join(TD, "OLD", CWD, oldname)))]
                    )
                continue

            oldnames.append(oldname)
            oldtarinfos[oldname] = oldtarinfo
            oldtar.extract(oldtarinfo, TD + "OLD/" + CWD)
            if old_forensic is not None:
                old_forensic.append(
                    old_forensic.pop()[:-1] + [hash_to_hex(sha1_hash_file(os.path.join(TD, "OLD", CWD, oldname)))]
                )

        oldtar.close()
        if type(old_filename) in string_types:
            unlink(TD + old_filename)
        else:
            while oldfileobj.read(512):
                pass
        # scan the new tarfile, save info regarding regular files therein
        # save header part of new_filename, since it changes in newer versions
        f = open(TD + new_filename)
        new_file_zip_head = f.read(20)
        f.close()
        (new_filename, new_filename_ext) = unzip(new_filename)
        new_file_md5 = compute_md5(TD + new_filename)
        new_file_size = os.path.getsize(TD + new_filename)
        info_append(new_filename + ": " + new_file_md5 + " " + str(new_file_size))
        # scan the new tarfile, compare to the old tar contents
        assert 0 == (new_file_size % 512)
        newtar = tarfile.open(TD + new_filename, "r")
        newnames = []
        newtarinfos = {}
        for newtarinfo in newtar:
            newname = newtarinfo.name
            # just curious to know
            t = newtarinfo.type
            a = newtarinfo.mode
            if VERBOSE and (
                (t == "2" and a != 0o777) or (t == "0" and ((a & 0o400) == 0)) or (t == "5" and ((a & 0o500) == 0))
            ):
                logger.debug(" weird permission %r %r %r", newname, oct(a), repr(newtarinfo.type))
            ###
            if not newtarinfo.isreg():
                continue
            if VERBOSE > 3 and newname != de_bar(newname):
                logger.debug("    filename in new tar has weird ./ in front: %r", newname)
            newname = de_bar(newname)
            newnames.append(newname)
            newtarinfos[newname] = newtarinfo

        old_used = {}
        correspondence = {}

        # find correspondences between old tar and new tar contents
        global time_corr
        time_corr = -(time.time())

        if VERBOSE > 2:
            logger.debug("  finding correspondences for %r", new_filename)

        reverse_old_md5 = {}
        if old_md5:
            for o in old_md5:
                if o in oldnames:
                    reverse_old_md5[old_md5[o]] = o
                else:
                    # would you believe? many packages contain MD5 for files they do not ship...
                    if VERBOSE > 1 and o not in skip:
                        logger.debug("  hmmm... there is a md5 but not a file: %r", o)

        # database of databases of premangled old names , by "extension" and name
        oldnames_premangle = {}
        for o in oldnames:
            om = file_similarity_premangle(o)
            a = om[-1]  # "extension"
            if a not in oldnames_premangle:
                oldnames_premangle[a] = {}
            oldnames_premangle[a][o] = om

        for newname in newnames:
            newtarinfo = newtarinfos[newname]
            oldname = None
            # ignore empty files
            if newtarinfo.size == 0:
                continue
            # try correspondence by MD5
            if new_md5 and newname in new_md5:
                md5 = new_md5[newname]
                if md5 in reverse_old_md5:
                    oldname = reverse_old_md5[md5]
                    if VERBOSE > 2:
                        if oldname == newname:
                            logger.debug("   use identical old file: %r", newname)
                        else:
                            logger.debug("   use identical old file: %r %r", oldname, newname)
            # try correspondence by file name
            if oldname is None and newname in oldnames:
                oldname = newname
                if VERBOSE > 2:
                    logger.debug("   use same name old file: %r", newname)
            # try correspondence by file name and len similarity
            np = file_similarity_premangle(newname)
            ne = np[-1]  # "extension"
            if oldname is None and ne in oldnames_premangle:
                basescore = 1.6
                nl = newtarinfo.size
                for o in oldnames_premangle[ne]:
                    op = oldnames_premangle[ne][o]
                    l = oldtarinfos[o].size
                    sfile = files_similarity_score__noext__(op, np)
                    slen = abs(float(l - nl)) / float(l + nl)
                    s = slen + sfile
                    if VERBOSE > 3:
                        logger.debug("    name/len diff %.2f+%.2f=%.2f %r", slen, sfile, s, o)
                    if s < basescore:
                        oldname = o
                        basescore = s
                if oldname and VERBOSE > 2:
                    logger.debug("   best similar  ", "%.3f %r %r", basescore, newname, oldname)
            if not oldname:
                if VERBOSE > 2:
                    logger.debug("   no correspondence for: %r", newname)
                continue
            # we have correspondence, lets store
            if oldname not in old_used:
                old_used[oldname] = []
            old_used[oldname].append(newname)
            correspondence[newname] = oldname

        time_corr += time.time()
        if VERBOSE > 1:
            logger.debug("  time lost so far in finding correspondence %.2f", time_corr)

        # final pass : scan new tar, extract regular files, prepare deltas
        if VERBOSE > 2:
            logger.debug("  scanning %r", new_filename)

        script.start_rebuilding()

        current_chunk_name = a_numb_file.next()
        script.start_chunk(current_chunk_name)
        mega_cat = open(TD + "/" + current_chunk_name, "w")

        # helper function
        def _append_(p, w, rm):
            mega_cat.write(w + fake_tar_2nd)
            f = open(TD + p + "/" + w)
            a = f.read(1024)
            while a:
                try:
                    mega_cat.write(a)
                except OSError:
                    s = sys.exc_info()[1]
                    raise DebDeltaError(" OSError (at _a_) while writing: " + str(s), True)
                a = f.read(1024)
            f.close()
            if rm:
                script.write("ECR '" + w + "'\n")
                unlink(TD + p + "/" + w)
            else:
                script.write("EC '" + w + "'\n")

        global something_backgrounded  # FIXME I hate using globals for this :-(
        something_backgrounded = False
        # helper function

        def mega_cat_chunk(oldoffset, newoffset, background=True):
            global something_backgrounded
            p = a_numb_file.next()
            f = open(TD + new_filename)
            f.seek(oldoffset)
            of = open(TD + p, "w")
            l = oldoffset
            while l < newoffset:
                s = f.read(512)
                l += len(s)
                assert len(s)
                try:
                    of.write(s)
                except OSError:
                    s = sys.exc_info()[1]
                    raise DebDeltaError(" OSError (at MCK) while writing: " + str(s), True)
            f.close()
            of.close()
            # do delta, in background there
            if something_backgrounded:
                script.write("wait\n")
            if background:
                script.write("(")
            this_delta_piped = delta_files(current_chunk_name, p, True, script.the_fifo)
            if not this_delta_piped:
                script.write("cat " + p + "\n")
            if not this_delta_piped:
                script.write("rm " + p + "\n")
            if background:
                script.write(")&\n")  # the delta+cat is backgrounded
                something_backgrounded = True
            os.unlink(TD + p)

        # there may be files that have been renamed and edited...
        def some_old_file_gen():
            for oldname in oldnames:
                if (oldname in skip) or (oldname in old_used):
                    continue
                if VERBOSE > 2:
                    logger.debug("   provide also old file %r", oldname)
                yield oldname
            while True:
                yield None

        some_old_file = some_old_file_gen()
        one_old_file = some_old_file.next()

        max_chunk_size = MAXMEMORY / 12
        chunk_discount = 0.3

        progressive_new_offset = 0

        for newtarinfo in newtar:
            # progressive mega_cat
            a = mega_cat.tell()
            if chunked_p and (
                (a >= max_chunk_size * chunk_discount)
                or (a >= max_chunk_size * chunk_discount * 0.9 and one_old_file)
                or (a > 0 and (a + newtarinfo.size) >= max_chunk_size * chunk_discount)
            ):
                # provide some old unused files, if any
                while one_old_file:
                    _append_("OLD/" + CWD, one_old_file, False)
                    if mega_cat.tell() >= max_chunk_size * chunk_discount:
                        break
                    one_old_file = some_old_file.next()
                # write the chunk into a temporary
                mega_cat.close()
                script.end_chunk(current_chunk_name)
                # delta the chunk
                mega_cat_chunk(progressive_new_offset, newtarinfo.offset)
                # start a new chunk
                current_chunk_name = a_numb_file.next()
                script.start_chunk(current_chunk_name)
                mega_cat = open(TD + "/" + current_chunk_name, "w")
                #
                progressive_new_offset = newtarinfo.offset
                chunk_discount = min(1.0, chunk_discount * 1.2)
            #
            name = de_bar(newtarinfo.name)

            if newtarinfo.isdir():
                # recreate also parts of the tar headers
                mega_cat.write(newtarinfo.name + fake_tar_2nd)
                script.write("$E '" + prepare_for_echo(newtarinfo.name) + '\'"${FTH}"\n')
                if VERBOSE > 2:
                    logger.debug("   directory   in new : %r", name)
                continue

            if not newtarinfo.isreg():
                # recreate also parts of the tar headers
                mega_cat.write(newtarinfo.name + fake_tar_2nd)
                script.write("$E '" + prepare_for_echo(newtarinfo.name) + '\'"${FTH}"\n')
                if VERBOSE > 2:
                    logger.debug("   not regular in new : %r", name)
                continue

            if newtarinfo.size == 0:
                # recreate also parts of the tar headers
                mega_cat.write(newtarinfo.name + fake_tar_2nd)
                script.write("$E '" + prepare_for_echo(newtarinfo.name) + '\'"${FTH}"\n')
                if VERBOSE > 2:
                    logger.debug("   empty  new file    : %r", name)
                continue

            if name not in correspondence:
                # recreate also parts of the tar headers
                mega_cat.write(newtarinfo.name + fake_tar_2nd)
                script.write("$E '" + prepare_for_echo(newtarinfo.name) + '\'"${FTH}"\n')
                if VERBOSE > 2:
                    logger.debug("   no corresponding fil: %r", name)
                continue

            oldname = correspondence[name]

            mul = len(old_used[oldname]) > 1  # multiple usage

            if (
                not mul
                and oldname == name
                and oldname[-3:] == ".gz"
                and newtarinfo.size > 120
                and not (new_md5 and name in new_md5 and old_md5 and name in old_md5 and new_md5[name] == old_md5[name])
            ):
                newtar.extract(newtarinfo, TD + "NEW/" + CWD)
                delta_gzipped_files("OLD/" + CWD + "/" + name, "NEW/" + CWD + "/" + name)

            if VERBOSE > 2:
                logger.debug("   adding reg file: %r %r", oldname, mul and "(multiple)" or "")
            _append_("OLD/" + CWD, oldname, not mul)
            old_used[oldname].pop()
        # end of for loop

        # write the chunk into a temporary
        mega_cat.close()
        script.end_chunk(current_chunk_name)
        if os.path.exists(TD + "/OLD/" + CWD):
            rmtree(TD + "/OLD/" + CWD)
        if os.path.getsize(TD + "/" + current_chunk_name) > 0:
            mega_cat_chunk(progressive_new_offset, os.path.getsize(TD + new_filename), background=False)
        else:
            # the (tail of the) new tar did not match anything in the old tar, nothing to delta
            p = verbatim(new_filename)
            script.write("cat '" + p + "'\n")
        script.end_rebuilding()  # pipes the rebuilding part into the recompressing part
        if new_filename == "NEW/data.tar":
            script.recompressing_by_arg(new_filename, new_filename_ext, new_file_zip_head, new_file_size)
        else:
            script.recompressing(new_filename, new_filename_ext, new_file_zip_head)

    ####################  ^^^^    delta_tar    ^^^^ ###########################

    # start computing deltas
    def append_NEW_file(s):
        "appends some data to NEW.file"
        s = prepare_for_echo(s)
        script.write("$E '" + s + "' >> NEW.file\n")

    # this following is actually
    # def delta_debs_using_old(old,new):

    # start scanning the new deb
    newdeb_file = open(newdeb)
    # pop the "!<arch>\n"
    s = newdeb_file.readline()
    assert "!<arch>\n" == s
    append_NEW_file(s)

    if forensic_file is None:
        control_forensic = None
        data_forensic = None
    else:
        control_forensic = []
        data_forensic = []

    def decompress_pipe_from_ar(oldnew, name, p=None):
        " use p=False to not decompress"
        assert oldnew in ("OLD", "NEW")
        if p is None:
            p = os.path.splitext(name)[1]
        db = {".gz": ["gzip", "-cd"], ".bz2": ["bzip2", "-cd"], ".lzma": ["unlzma", "-c"], ".xz": ["unxz", "-c"]}
        assert p == False or p == ".tar" or p in db
        if p == ".tar" or p == False:

            def x():
                return PopenPipe(["ar", "p", oldnew + ".file", name], stdout=subprocess.PIPE, cwd=TD)

        else:

            def x():
                return PopenPipe(["ar", "p", oldnew + ".file", name, "|"] + db[p], stdout=subprocess.PIPE, cwd=TD)

        return x

    for name in ar_list_new:
        newname = "NEW/" + name
        system(("ar", "x", TD + "NEW.file", name), TD + "/NEW/")
        script.xz_parameters = None
        newsize = os.stat(TD + newname)[ST_SIZE]
        if VERBOSE > 1:
            logger.debug("  studying %r of len %dkB", name, (newsize / 1024))
        # add 'ar' structure
        ar_line = newdeb_file.read(60)
        if VERBOSE > 3:
            logger.debug("    ar line: %r", ar_line)
        assert ar_line[: len(name)] == name and ar_line[-2] == "`" and ar_line[-1] == "\n"
        # sometimes there is an extra \n, depending if the previous was odd length
        newdeb_file.seek(newsize, 1)
        if newsize & 1:
            extrachar = newdeb_file.read(1)
        else:
            extrachar = ""
        # add file to delta
        if newsize < 128:  # file is too short to compute a delta,
            append_NEW_file(ar_line)
            p = open(TD + newname)
            append_NEW_file(p.read(newsize))
            p.close()
            unlink(TD + newname)
            # pad new deb
            if extrachar:
                append_NEW_file(extrachar)
        elif not NEEDSOLD and (name[:11] == "control.tar" or name[:8] == "data.tar"):
            script.start_member(ar_line, newname, extrachar)
            basename, ext = os.path.splitext(name)
            xd = decompress_pipe_from_ar("NEW", name, False)
            # delta it
            if ".lzma" == ext:
                info_append("needs-lzma")
            elif ".xz" == ext:
                info_append("needs-xz")
                script.xz_parameters = guess_xz_parameters(xd)
                if not script.xz_parameters:
                    raise DebDeltaError("Cannot guess XZ parameters for new %r" % name)
            elif ".gz" == ext:
                script.gz_command = guess_gz_command(xd)
                if not script.gz_command:
                    raise DebDeltaError("Cannot guess GZ parameters for new %r" % name)
            del xd
            x = None
            for oldext in ("", ".gz", ".bz2", ".lzma", ".xz"):
                if basename + oldext in ar_list_old:
                    x = decompress_pipe_from_ar("OLD", basename + oldext)
                    break
            assert x
            if name[:11] == "control.tar":
                skip = []
                # avoid using strange files that dpkg may not install in /var...info/
                for a in os.listdir(TD + "OLD/CONTROL"):
                    if a not in dpkg_keeps_controls:
                        skip.append(a)
                delta_tar(x, newname, "CONTROL", control_forensic, skip)
            else:
                delta_tar(
                    x,
                    newname,
                    "DATA",
                    data_forensic,
                    old_conffiles,
                    old_md5,
                    new_md5,
                    debdelta_conf_skip=debdelta_conf_skip,
                )
            del x, basename, oldext
            script.end_member()
            if DEBUG > 3 and name[:11] == "control.tar":
                length = newdeb_file.tell()
                md5_len = compute_md5_up_to_len(newdeb, length)
                assert md5_len[1] == length
                script.md5_check_file("NEW.file", md5_len[0])
        elif not NEEDSOLD or name not in ar_list_old:  # or it is not in old deb
            append_NEW_file(ar_line)
            patchname = verbatim(newname)
            script.write("cat " + patchname + " >> NEW.file ; rm " + patchname + "\n")
            # pad new deb
            if extrachar:
                append_NEW_file(extrachar)
        elif NEEDSOLD:
            append_NEW_file(ar_line)
            # file is long, and has old version ; lets compute a delta
            oldname = "OLD/" + name
            system(("ar", "x", TD + "OLD.file", name), TD + "OLD")
            script.write("ar p OLD.file " + name + " >> " + oldname + "\n")
            (oldname, co) = unzip(oldname)
            (newname, cn) = unzip(newname)
            delta_files(oldname, newname)
            script.zip(newname, cn)
            script.write("cat " + newname + cn + " >> NEW.file ;  rm " + newname + cn + "\n")
            unlink(TD + newname)
            # pad new deb
            if extrachar:
                append_NEW_file(extrachar)
            del co, cn
        else:
            die("internal error j98")
    # put in script any leftover
    s = newdeb_file.read()
    if s:
        if VERBOSE > 2:
            logger.debug("   ar leftover character: %r", s)
        append_NEW_file(s)
    del s

    # this is done already from the receiving end
    if DEBUG > 2 and newdeb_md5sum:
        script.md5_check_file("NEW.file", md5=newdeb_md5sum)

    # script is done
    script.close()

    if forensic_file:
        forensics_rfc(forensic_file, info, True, control_forensic, data_forensic, old_conffiles)

    patchsize = os.stat(TD + "PATCH/patch.sh")[ST_SIZE]
    patch_files = []
    if "lzma" not in DISABLED_FEATURES and os.path.exists("/usr/bin/lzma"):
        system(("lzma", "-q", "-9", "-k", "PATCH/patch.sh"), TD)
        patch_files.append((os.path.getsize(TD + "PATCH/patch.sh.lzma"), "lzma", "patch.sh.lzma"))
    if "xz" not in DISABLED_FEATURES and os.path.exists("/usr/bin/xz"):
        system(("xz", "-q", "-9", "-k", "PATCH/patch.sh"), TD)
        patch_files.append((os.path.getsize(TD + "PATCH/patch.sh.xz"), "xz", "patch.sh.xz"))
    system(("bzip2", "-q", "--keep", "-9", "PATCH/patch.sh"), TD)
    patch_files.append((os.path.getsize(TD + "PATCH/patch.sh.bz2"), "bzip2", "patch.sh.bz2"))
    system(("gzip", "-q", "-9", "-n", "PATCH/patch.sh"), TD)
    patch_files.append((os.path.getsize(TD + "PATCH/patch.sh.gz"), "gzip", "patch.sh.gz"))

    # Use the smallest compressed patch.sh
    patch_files.sort()
    if VERBOSE > 1:
        logger.debug("  " + patch_files[0][1] + " wins on patch.sh")
    if patch_files[0][1] == "lzma":
        info_append("needs-lzma")
    if patch_files[0][1] == "xz":
        info_append("needs-xz")
    patch_append(patch_files[0][2])
    del patch_files

    # OK, OK... this is not yet correct, since I will add the info file later on
    elaps = time.time() - start_sec
    info.append("DeltaTime: %.2f" % elaps)
    deltasize = os.stat(delta)[ST_SIZE] + 60 + sum(map(len, info))
    percent = deltasize * 100.0 / newdebsize
    info.append("Ratio: %.4f" % (float(deltasize) / float(newdebsize)))

    if VERBOSE:
        # note that sizes are written as kB but are actually kibybytes, that is 1024 bytes
        logger.info(
            " " + _("delta is %(perc)3.1f%% of deb; that is, %(save)dkB are saved, on a total of %(tot)dkB."),
            {"perc": percent, "save": ((newdebsize - deltasize) / 1024), "tot": (newdebsize / 1024)},
        )
        logger.info(
            " "
            + _(
                "delta time %(time).2f sec, speed %(speed)dkB /sec, (%(algo)s time %(algotime).2fsec speed %(algospeed)dkB /sec) (corr %(corrtime).2f sec)"
            )
            % {
                "time": elaps,
                "speed": newdebsize / 1024.0 / (elaps + 0.001),
                "algo": USE_DELTA_ALGO,
                "algotime": bsdiff_time,
                "algospeed": bsdiff_datasize / 1024.0 / (bsdiff_time + 0.001),
                "corrtime": time_corr,
            }
        )
    return (delta, percent, elaps, info, gpg_hashes)


# compute many deltas


def info_by_pack_arch_add(f, info_by_pack_arch):
    pack = f["Package"]
    arch = f["Architecture"]
    if (pack, arch) not in info_by_pack_arch:
        info_by_pack_arch[(pack, arch)] = []
    info_by_pack_arch[(pack, arch)].append(f)


def iterate_Packages(packages, use_debian_822=True):
    fields = ("Package", "Architecture", "Version", "Filename")
    for f in fields:
        intern(f)

    packages = abspath(packages)
    assert os.path.isfile(packages)
    assert os.path.basename(packages) in ("Packages", "Packages.gz", "Packages.bz2", "Packages.xz")
    dir = os.path.dirname(packages)
    dir = dir.split("/")
    try:
        a = dir.index("dists")
    except ValueError:
        logger.error('Error: pathname "%s" does not contain "dists"\n' % packages)
        return
    base = string.join(dir[:a], "/")
    #
    cache = cache_same_dict(packages, fields)
    if DO_CACHE and cache.exists:
        for i in cache:
            i["Basepath"] = base
            yield i
        if not cache.broken:
            return
    #
    if packages[-3:] == ".gz":
        import gzip

        F = gzip.GzipFile(packages)
        SP = None
    elif packages[-4:] == ".bz2":
        import bz2

        F = bz2.BZ2File(packages)
        SP = None
    elif packages[-3:] == ".xz":
        SP = subprocess.Popen(["xzcat", packages], stdout=subprocess.PIPE, stdin=open(os.devnull), close_fds=True)
        F = SP.stdout
    else:
        F = open(packages)
        SP = None
    #
    if debian_deb822 and use_debian_822:  # use faster implementation
        # P=debian_deb822.Packages(F,fields=fields)
        for a in debian_deb822.Packages.iter_paragraphs(sequence=F, shared_storage=False, fields=fields):
            if DO_CACHE and not cache.exists:
                cache.write(a)
            a["Basepath"] = base
            yield a
        if SP:
            F.read()
            SP.wait()
        return
    #
    of, pack, vers, arch = None, None, None, None
    for l in F:
        l = l.rstrip("\n")
        if l[:9] == "Package: ":
            pack = l[9:]
        elif l[:14] == "Architecture: ":
            arch = l[14:]
        elif l[:9] == "Version: ":
            vers = l[9:]
        elif l[:10] == "Filename: ":
            of = l[10:]
        elif l == "":
            if of is None or pack is None or vers is None or arch is None:
                logger.warn("Warning, skipping incomplete record in index: %r %r %r", of, pack, vers, arch)
                continue
            if of[-4:] == ".udeb":
                if VERBOSE > 2:
                    logger.debug("   skip udeb")
                continue
            a = {}
            a["Filename"] = of
            a["Package"] = pack
            a["Architecture"] = arch
            a["Version"] = vers
            if DO_CACHE and not cache.exists:
                cache.write(a)
            a["Basepath"] = base
            yield a
            of, pack, vers, arch = None, None, None, None
    if SP:
        F.read()
        SP.wait()


def scan_deb_dir(d, debname, label, lazy, info_by_pack_arch, info_by_file):
    assert (debname is None or type(debname) in string_types) and type(label) in string_types
    if not os.path.isdir(d):
        logger.debug("Error, skip non dir: %r", d)
        return
    if lazy:
        scan = scan_deb_byfile_lazy
    else:
        scan = scan_deb_byfile
    for n in os.listdir(d):
        if n[-4:] != ".deb":
            continue
        if debname is not None and debname != n.split("_")[0]:
            continue
        a = scan(os.path.join(d, n), info_by_file)
        a["Label"] = label
        info_by_pack_arch_add(a, info_by_pack_arch)


def scan_deb_byfile_lazy(f, info_by_file):
    n = os.path.basename(f).split("_")
    a = {}
    a["File"] = f
    a["Package"] = n[0]
    # version cannot be trusted, due to epochs (deleted in filenames)
    # it is read using scan_deb_bydict, later on
    a["Architecture"] = n[2][:-4]
    return a


def scan_deb_byfile(f, info_by_file):
    # DEBUG: assert( os.path.isfile(f) )
    if f in info_by_file and "Version" in info_by_file[f]:
        # already scanned in non-lazy mode
        return info_by_file[f]
    a = {}
    a["File"] = f
    c, b, z = untar_control_in_deb(list_ar(f))
    p = PopenPipe(["ar", "p", f, c, "|", "tar", b, "-xp", "-f", "-", "-O", "./control"], stdout=subprocess.PIPE)
    scan_control(p.stdout, params=a)
    p.close()
    return a


def scan_deb_bydict(a):
    c, b, z = untar_control_in_deb(list_ar(a["File"]))
    p = PopenPipe(["ar", "p", a["File"], c, "|", "tar", b, "-xp", "-f", "-", "-O", "./control"], stdout=subprocess.PIPE)
    scan_control(p.stdout, params=a)
    p.close()
    return a


def scan_delta_dir(d, debname, scanned_delta_dirs, old_deltas_by_pack_arch):
    if (d, debname) in scanned_delta_dirs or (d, None) in scanned_delta_dirs:
        return
    if not os.path.isdir(d):
        if VERBOSE > 2 and DEBUG:
            logger.debug("   No such delta dir: %r", d)
        scanned_delta_dirs.add((d, None))  # trick, if aint there no need to retry
        return
    assert debname is None or type(debname) in string_types
    scanned_delta_dirs.add((d, debname))
    for n in os.listdir(d):
        if debname is not None and debname != n.split("_")[0]:
            continue
        scan_delta(os.path.join(d, n), old_deltas_by_pack_arch)


def scan_delta(f, old_deltas_by_pack_arch):
    assert os.path.isfile(f)
    if f[-9:] == ".debdelta":
        a = f[:-9]
    elif f[-17:] == ".debdelta-too-big":
        a = f[:-17]
    elif f[-15:] == ".debdelta-fails":
        a = f[:-15]
    else:
        return
    a = os.path.basename(a)
    a = a.split("_")
    pa = a[0]
    ar = a[3]
    if (pa, ar) not in old_deltas_by_pack_arch:
        old_deltas_by_pack_arch[(pa, ar)] = []
    ov = version_demangle(a[1])
    nv = version_demangle(a[2])
    if (f, ov, nv) not in old_deltas_by_pack_arch[(pa, ar)]:
        old_deltas_by_pack_arch[(pa, ar)].append((f, ov, nv))


def delta_dirname(f, altdir):
    "f=directory, altdir=ALT or DIR with // convention. Returns augmented dirname"
    if altdir is not None:
        if altdir[-2:] == "//":
            if "../" in f:
                logger.warn("Warning: cannot combine .. and // ! Saving in %r", altdir)
                return altdir
            # os.path.join has a weird behaviour with absolute paths!
            f = f.lstrip("/")
            return os.path.join(altdir[:-2], f)
        else:
            return altdir
    else:
        # this happens when DIR is not set, and the delta goes in the same directory as the deb
        return f


def go_fishing(deb, others, loglevel=logging.ERROR):
    "Find a package filepath if missing, save it in deb['File']. deb = dict representing package ; others: list of such dicts."
    if "File" in deb:
        assert os.path.isfile(deb["File"])
        return deb["File"]
    of = deb["Filename"]
    ob = os.path.basename(of)
    # try to build it from its own info
    if "Basepath" in deb:
        f = os.path.join(deb["Basepath"], of)
        if os.path.exists(f):
            deb["File"] = f
            if DEBUG > 1:
                logger.debug("Fish! %r", deb)
            return f
    # try to build it from others info
    others = [a for a in others if id(a) != id(deb)]
    for new in others:
        if "File" in new:
            f = new["File"]
            if os.path.basename(f) == ob:
                deb["File"] = f
                if DEBUG > 1:
                    logger.debug("Fish! %r %r", deb, new)
                return f
        if "Basepath" in new:
            for a in of, ob:
                f = os.path.join(new["Basepath"], a)
                if os.path.exists(f):
                    deb["File"] = f
                    if DEBUG > 1:
                        logger.debug("Fish! %r %r", deb, new)
                    return f
    logger.log(loglevel, "bad fishing for %r %r", deb, others)
    return False


def order_by_version(a, b, VersionCompare):
    # lazy packages do not have versions; but are always ALT, so we sort them at bottom
    if "Version" not in a:
        return -1
    if "Version" not in b:
        return 1
    return VersionCompare(a["Version"], b["Version"])


def iter_deltas_one_pack_arch(pa, ar, info_pack, thedir, theforensicdir, VersionCompare, loglevel=logging.ERROR):
    " iterate deltas to be created for package pa, architecture ar, by analyzing info_pack"
    if all([("CMDLINE" != a["Label"]) for a in info_pack]):
        # this happens a lot, e.g. when we are scanning non-free/Packages.gz,
        # all free packages in the trash are to be ignored
        if DEBUG > 2 or VERBOSE > 3:
            logger.debug("    No cmdline for: %r %r", pa, ar)
        return

    # do we need the versions of --alt packages ? seems not
    #  for a in info_pack:
    #    #scan all lazy packages
    #    if 'Version' not in a:
    #      assert a['Label'] == 'ALT'
    #      scan_deb_bydict(a)

    info_pack.sort(cmp=lambda x, y: order_by_version(x, y, VersionCompare))

    how_many = len(info_pack)

    if how_many <= 1:
        if VERBOSE > 3:
            logger.debug("    Only one version: %r %r", pa, ar)
        return

    newest = how_many - 1
    while newest >= 0:
        new = info_pack[newest]
        if new["Label"] != "CMDLINE":
            if VERBOSE > 3:
                logger.debug("    Newest version deb was not in cmdline, skip down one: %r", new)
        else:
            break
        newest -= 1

    if newest <= 0:
        if VERBOSE > 3:
            logger.debug("    No older versions: %r", new)
        return

    if not go_fishing(new, [], loglevel):
        logger.log(loglevel, "Cannot locate new file: %r", new)
        return

    if VERBOSE > 2:
        logger.debug(
            "   Package: %r %r Versions: %r",
            pa,
            ar,
            [(o.get("Version"), o["Label"], o.get("Packages"), o.get("File")) for o in info_pack],
        )

    newdebsize = os.path.getsize(new["File"])
    # very small packages cannot be effectively delta-ed
    if newdebsize <= MIN_DEB_SIZE:
        if VERBOSE > 1:
            logger.debug("  Skip , too small: %r", new["File"])
        return

    oldn = newest
    generated = 0
    seen_versions = []
    while oldn > 0:
        oldn -= 1

        old = info_pack[oldn]

        if old["Label"] != "OLD":
            if VERBOSE > 2:
                logger.debug("   Not old, skip: %r", old)
            continue

        if old["Version"] == new["Version"]:
            if VERBOSE > 3 and old != new:
                logger.debug("    Identical versions: %r %r", old, new)
            continue

        assert old["Package"] == pa and pa == new["Package"]
        deltabasename = delta_base_name(pa, old["Version"], new["Version"], ar)

        if "Filename" in new:
            deltadirname = delta_dirname(os.path.dirname(new["Filename"]), thedir)
        elif "File" in new:
            deltadirname = delta_dirname(os.path.dirname(new["File"]), thedir)
        else:
            assert 0
        if deltadirname == "":
            deltadirname = "."

        delta = os.path.join(deltadirname, deltabasename)

        generated += 1  # count also those already generated
        if N_DELTAS is not None and (generated > N_DELTAS):
            continue

        if os.path.exists(delta):
            if VERBOSE > 1:
                logger.debug("  Skip , already exists: %r", delta)
            continue

        if old["Package"] in seen_versions:
            if VERBOSE > 3:
                logger.debug("    Skip , already considered: %r", delta)
            continue

        if os.path.exists(delta + "-too-big"):
            if VERBOSE > 1:
                logger.debug("  Skip , tried and too big: %r", delta)
            continue

        if os.path.exists(delta + "-fails"):
            if VERBOSE > 1:
                logger.debug("  Skip , tried and fails: %r", delta)
            continue

        if not go_fishing(old, info_pack, loglevel):
            logger.log(loglevel, "Cannot locate old file: %r", old)
            continue

        forensicfile = None
        if theforensicdir:
            if "Filename" in new:
                forensicdirname = delta_dirname(os.path.dirname(new["Filename"]), theforensicdir)
            elif "File" in new:
                forensicdirname = delta_dirname(os.path.dirname(new["File"]), theforensicdir)
            else:
                assert 0
            forensicbasename = pa + "_" + version_mangle(old["Version"]) + "_" + ar + ".forensic"
            forensicfile = os.path.join(forensicdirname, forensicbasename)

        seen_versions.append(old["Package"])

        yield (old, new, delta, forensicfile)


def do_delta_and_test(old_File, new_File, delta, forensicfile):
    " returns (error_code, delta_size, delta_elaps, patch_elaps, info_delta, error_string) : for error_code, see EXIT STATUS in 'man debdelta' "
    exitstatus = 0
    if VERBOSE:
        logger.info("Creating: %r", delta)

    deltatmp = delta + "_tmp_"
    ret = None
    tdir = tempo()
    ret = None  # data returned from calls
    elaps = None  # delta time
    delta_size = None
    p_elaps = None  # patching time
    info_delta = []  # informations about created delta
    error_string = ""  # error when delta fails

    deltadirname = os.path.dirname(delta)
    if not os.path.exists(deltadirname):  # FIXME this does not respect --no-act
        os.makedirs(deltadirname)

    free = freespace(deltadirname)
    newdebsize = os.path.getsize(new_File)
    if free and (free < (newdebsize / 2 + 2 ** 15)):
        if VERBOSE:
            logger.warn(" " + (_("Not enough disk space for storing `%s'.")), delta)
        return (1, None, None, None, [], "not_enough_disk_space")

    if forensicfile and not os.path.exists(forensicfile):
        forensicdirname = os.path.dirname(forensicfile)
        if not os.path.exists(forensicdirname):  # FIXME this does not respect --no-act
            os.makedirs(forensicdirname)
        forensic_file = open(forensicfile, "w")
    else:
        forensic_file = None

    try:
        ret = do_delta_(old_File, new_File, deltatmp, TD=tdir, forensic_file=forensic_file, info=info_delta)
        (deltatmp_, percent, elaps, info_delta, gpg_hashes) = ret
        if os.path.exists(deltatmp):
            delta_size = os.path.getsize(deltatmp)
    except (KeyboardInterrupt, SystemExit):
        if os.path.exists(deltatmp):
            os.unlink(deltatmp)
        rmtree(tdir)
        raise
    except DebDeltaError:
        s = sys.exc_info()[1]
        error_string = str(s)
        if not VERBOSE:
            logger.info(_("Creating:") + " " + repr(delta))
        logger.info(" Creation of delta failed, reason: %r", error_string)
        if os.path.exists(deltatmp):
            if KEEP:
                logger.info(" " + _("You may want to examine:") + " " + str(deltatmp))
            else:
                os.unlink(deltatmp)
        if not s.retriable:
            open(delta + "-fails", "w").close()
        exitstatus = max(exitstatus, s.exitcode)
        ret = None
    except BaseException:
        exitstatus = 4
        if os.path.exists(deltatmp):
            os.unlink(deltatmp)
        puke(" *** Error while creating delta  " + delta)
        open(delta + "-fails", "w").close()
        ret = None

    rmtree(tdir)

    if ret is None:
        return (exitstatus, delta_size, elaps, p_elaps, info_delta, error_string)

    info_delta.append("ServerID: " + HOSTID)
    info_delta.append("ServerBogomips: " + str(BOGOMIPS))

    if MAX_DELTA_PERCENT and percent > MAX_DELTA_PERCENT:
        os.unlink(deltatmp)
        if VERBOSE:
            logger.info(" Warning, too big!")
        open(delta + "-too-big", "w").close()
        return (exitstatus, delta_size, elaps, p_elaps, info_delta, "too_big")
    #
    if DO_TEST:
        # patch test
        pret = None
        try:
            # test, ignoring gpg, that is added later on
            pret = do_patch(deltatmp, old_File, None, info=info_delta, do_gpg=None)
        except DebDeltaError:
            s = sys.exc_info()[1]
            logger.warn(" " + _("Error: testing of delta failed:") + " " + str(s))
            if os.path.exists(deltatmp):
                if KEEP:
                    logger.warn(" " + _("You may want to examine:") + " " + str(deltatmp))
                else:
                    os.unlink(deltatmp)
            if not s.retriable:
                open(delta + "-fails", "w").close()
        except (KeyboardInterrupt, SystemExit):
            if os.path.exists(deltatmp):
                os.unlink(deltatmp)
            raise
        except Exception:
            s = sys.exc_info()[1]
            exitstatus = max(exitstatus, 4)
            puke(" *** Error while testing delta  " + delta, s)
            if os.path.exists(deltatmp):
                if KEEP:
                    logger.warn(" " + _("You may want to examine:") + " " + str(deltatmp))
                else:
                    os.unlink(deltatmp)
            open(delta + "-fails", "w").close()
        if pret is None:
            return (max(exitstatus, 4), delta_size, elaps, p_elaps, info_delta, "patch_fails")

        (newdeb_, p_elaps) = pret
        info_delta.append("PatchTime: %.2f" % p_elaps)
        # end patch test
    # complete the delta file prepending to it the info
    try:
        hashes_info = append_info(deltatmp, info_delta)
        # sign the delta
        if DO_GPG:
            gpg_hashes["info"] = hashes_info
            sign_delta(deltatmp, gpg_hashes)
    except BaseException:
        puke("debdeltas signing")
        if os.path.exists(deltatmp):
            os.unlink(deltatmp)

    # eventually, put in its place
    if os.path.isfile(deltatmp):
        # update delta size , since info and signatures were added
        delta_size = os.path.getsize(deltatmp)
        os.rename(deltatmp, delta)
        return (exitstatus, delta_size, elaps, p_elaps, info_delta, "")
    else:
        return (max(exitstatus, 4), delta_size, elaps, p_elaps, info_delta, "no_delta")


def init_apt_return_VersionCompare():
    try:
        import apt_pkg

        if "init_system" in dir(apt_pkg):
            apt_pkg.init_system()
        elif "InitSystem" in dir(apt_pkg):
            apt_pkg.InitSystem()
        else:
            assert "fegrwq" == 0
        if "VersionCompare" in dir(apt_pkg):
            from apt_pkg import VersionCompare
        elif "version_compare" in dir(apt_pkg):
            from apt_pkg import version_compare as VersionCompare
        else:
            assert "lopadf" == 0
    except ImportError:
        raise DebDeltaError('python module "apt_pkg" is missing. Please install python-apt', retriable=True)
    return VersionCompare


############


def do_deltas(debs):
    exitstatus = 0

    VersionCompare = init_apt_return_VersionCompare()

    if not debs:
        logger.warn(_("Warning, no non-option arguments, debdeltas does nothing."))
        if not DEBUG:
            return
    elif not OLD and not CLEAN_DELTAS:
        logger.warn(_("Warning, no --old arguments, debdeltas will not generate any deltas."))
        if not DEBUG:
            return

    original_cwd = os.getcwd()
    start_time = time.time()

    info_by_pack_arch = {}

    info_by_file = {}  # cache to speed up scanning file packages

    scanned_delta_dirs = set()

    # contains list of triples (filename,oldversion,newversion)
    old_deltas_by_pack_arch = {}

    ALT_DOUBLEDIR = []  # directories ending in //
    for arg in ALT:
        if os.path.isfile(arg):
            if os.path.basename(arg) in ("Packages", "Packages.gz", "Packages.bz2"):
                for a in iterate_Packages(arg):
                    a["Label"] = "ALT"
                    # DEBUG a['Packages'] = arg
                    info_by_pack_arch_add(a, info_by_pack_arch)
            elif arg[-4:] == ".deb":
                a = scan_deb_byfile_lazy(arg, info_by_file)
                if a:
                    a["Label"] = "ALT"
                    info_by_pack_arch_add(a, info_by_pack_arch)
            else:
                logger.error("Error! skipping file --alt %r", arg)
        elif os.path.isdir(arg):
            if arg[-2:] != "//":
                scan_deb_dir(arg, None, "ALT", True, info_by_pack_arch)
            else:
                ALT_DOUBLEDIR.append(arg)
        else:
            logger.error("Error, ignored --alt %r", arg)

    for arg in OLD:
        if os.path.isfile(arg):
            if os.path.basename(arg) in ("Packages", "Packages.gz", "Packages.bz2"):
                for a in iterate_Packages(arg):
                    a["Label"] = "OLD"
                    # DEBUG a['Packages'] = arg
                    info_by_pack_arch_add(a, info_by_pack_arch)
            elif arg[-4:] == ".deb":
                a = scan_deb_byfile(arg, info_by_file)
                if a:
                    a["Label"] = "OLD"
                    info_by_pack_arch_add(a, info_by_pack_arch)
            else:
                logger.error("Error! skipping file --old %r", arg)
        elif os.path.isdir(arg):
            # no // support yet
            scan_deb_dir(arg, None, "OLD", False, info_by_pack_arch, info_by_file)
        else:
            logger.error("Error, ignored --old %r", arg)

    # scan cmdline arguments and prepare list of debs and deltas
    for arg in debs:
        if os.path.isfile(arg):
            if os.path.basename(arg) in ("Packages", "Packages.gz", "Packages.bz2"):
                for a in iterate_Packages(arg):
                    a["Label"] = "CMDLINE"  # note that, if a file is scanned more than once, the last label is CMDLINE
                    # DEBUG a['Packages'] = arg
                    ofd = os.path.dirname(a["Filename"])
                    pa = a["Package"]
                    info_by_pack_arch_add(a, info_by_pack_arch)
                    for alt in ALT_DOUBLEDIR:
                        scan_deb_dir(delta_dirname(ofd, alt), pa, "ALT", True, info_by_pack_arch)
                    if CLEAN_DELTAS:
                        scan_delta_dir(delta_dirname(ofd, DIR), pa, scanned_delta_dirs, old_deltas_by_pack_arch)
            elif arg[-4:] == ".deb":
                a = scan_deb_byfile(arg, info_by_file)
                if a:
                    a["Label"] = "CMDLINE"
                    info_by_pack_arch_add(a, info_by_pack_arch)
                    ofd = os.path.dirname(arg)
                    for alt in ALT_DOUBLEDIR:
                        scan_deb_dir(
                            delta_dirname(ofd, alt), a["Package"], "ALT", True, info_by_pack_arch, info_by_file
                        )
                    if CLEAN_DELTAS:
                        scan_delta_dir(
                            delta_dirname(ofd, DIR), a["Package"], scanned_delta_dirs, old_deltas_by_pack_arch
                        )
            else:
                logger.error("Error! skipping cmdline argument: %r", arg)
        elif os.path.isdir(arg):
            scan_deb_dir(arg, None, "CMDLINE", False, info_by_pack_arch, info_by_file)
            for alt in ALT_DOUBLEDIR:
                scan_deb_dir(delta_dirname(arg, alt), None, "ALT", True, info_by_pack_arch, info_by_file)
            if CLEAN_DELTAS:
                scan_delta_dir(delta_dirname(arg, DIR), None, scanned_delta_dirs, old_deltas_by_pack_arch)
        else:
            logger.error("Error, skipping cmd line argument: %r", arg)

    if VERBOSE > 1:
        logger.info("  total parsing time: %.1f ", (-start_time + time.time()))

    for pa, ar in info_by_pack_arch:
        info_pack = info_by_pack_arch[(pa, ar)]
        assert info_pack
        # delete old deltas
        if CLEAN_DELTAS:
            if (pa, ar) in old_deltas_by_pack_arch:
                versions = [(o["Version"]) for o in info_pack if (o["Label"] == "CMDLINE")]
                timegrace = time.time() - CLEAN_DELTAS_MTIME * 24 * 3600
                # DEBUG print pa,ar,versions
                for f_d, o_d, n_d in old_deltas_by_pack_arch[(pa, ar)]:
                    if n_d not in versions:
                        if os.path.exists(f_d):
                            if os.stat(f_d)[ST_MTIME] < timegrace:
                                if VERBOSE:
                                    logger.debug(" Removing: %r", f_d)
                                if ACT:
                                    os.unlink(f_d)
                            elif VERBOSE > 1:
                                logger.debug("  Obsolete but still young, graced: %r", f_d)
                        else:
                            logger.debug("bellandata %r", f_d)
                del versions
            elif DEBUG > 1:
                logger.debug("No deltas where found for: %r %r", pa, ar)
        if N_DELTAS is not None and 0 == N_DELTAS:
            # debdeltas was invoked just to clean the archive
            pass
        else:
            for old, new, delta, forensicfile in iter_deltas_one_pack_arch(
                pa, ar, info_pack, DIR, FORENSICDIR, VersionCompare
            ):
                if not ACT:
                    logger.info("Would create: %r", delta)
                else:
                    e = do_delta_and_test(old["File"], new["File"], delta, forensicfile)
                    exitstatus = max(exitstatus, e[0])

    if VERBOSE:
        logger.info(" " + (_("Total running time: %.1f")), (-start_time + time.time()))
    return exitstatus


# delta-upgrade


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

    import thread
    import threading
    import Queue
    import urllib2
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

    config = ConfigParser.SafeConfigParser()
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

    patching_queue = Queue.Queue()
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
                    thread.interrupt_main()
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
    import httplib
    from urlparse import urlparse, urlunparse

    # manage connections
    # keeps a cache of all connections, by URL
    http_conns = {}

    def conn_by_url(url):
        url = urlparse(url)[1]
        if url not in http_conns:
            if VERBOSE > 1:
                logger.debug("  Opening connection to: %r", url)
            http_conns[url] = httplib.HTTPConnection(url, timeout=TIMEOUT)
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
                conn.request("GET", urllib2.quote(uri_p[2]), headers=headers)
                r = conn.getresponse()
                return r, r.status, r.reason, r.msg
            except (httplib.HTTPException, socket.error):
                e = sys.exc_info()[1]
                if VERBOSE:
                    puke(" Connection error (retrying): ", uri_p[1])
                conn_close(uri)
                try:
                    conn = conn_by_url(uri)
                    conn.request("GET", urllib2.quote(uri_p[2]), headers=headers)
                    r = conn.getresponse()
                    return r, r.status, r.reason, r.msg
                except (httplib.HTTPException, socket.error):
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
                    a[2] = urllib2.quote(uri_p[2])
                    uri = urlunparse(a)
                req = urllib2.Request(uri, headers=headers)
                r = urllib2.urlopen(req)
                # print r.info(),dir(r),r.code
                return r, getattr(r, "code", None), getattr(r, "msg", "(no message)"), r.info()
            except urllib2.HTTPError:
                e = sys.exc_info()[1]
                return e.code, None, None, None
            except (httplib.HTTPException, socket.error, urllib2.URLError):
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
        conn.request("HEAD", urllib2.quote(uri_p[2]), headers=HTTP_USER_AGENT)
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
                l = long(responseheaders.get("Content-Length"))
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
            re["Range"] = "bytes=%li-" % ((long(l) - 1))
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
                total_len = long(responseheaders["Content-Length"])
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
                total_len = long(responseheaders.get("Content-length"))
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
            deb_path = string.split(deb_uri, "/")
            try:
                thepoolindex = deb_path.index("pool")
            except ValueError:
                logger.warn(
                    '! Package "%s" (version %s) does not have "pool" in the uri %s \n'
                    % (p.name, candidate_version, deb_uri)
                )
                continue
            deb_path = string.join(deb_path[thepoolindex:], "/")

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
                logger.warn("Delta is not downloadable (%s %s):%s", status, httplib.responses.get(status), uri)
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
    b = sum([int(s.get("NEW/Installed-Size", "0")) for s in params_of_delta.values()])
    c = sum([int(s.get("NEW/Size", "0")) for s in params_of_delta.values()]) / 1024
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
            if r is None or isinstance(r, httplib.HTTPException):
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
            if r is None or isinstance(r, httplib.HTTPException):
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

