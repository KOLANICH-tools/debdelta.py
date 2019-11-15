import sys
import subprocess, time, tarfile, stat, hashlib, random, gzip
import tempfile
from pathlib import Path, PurePath
import os
import arpy
import lzma, zlib, bz2

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



def my_popen_read(cmd):
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=open(os.devnull), close_fds=True).stdout


def freespace(w):
    assert os.path.exists(w)
    try:
        a = os.statvfs(w)
        freespace = int(a[0]) * int(a[4])
    except Exception:
        logger.exception("Statvfs error on %r", w)
        freespace = None
    return freespace


ext2CompressorMapping = {
    "gz": zlib,
    "xz": lzma,
    "bz2": bz2
}

TMPDIR = Path((os.getenv("TMPDIR") or "/tmp").rstrip("/"))

if sys.version_info.major == 2:
    string_types = (str, str)  # python2
else:
    string_types = (str, bytes)  # python3

#####################################################################


ALLOWED = set("<>()[]{}.,;:!_-+/ abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

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
    print(s)
    assert type(s) in string_types
    r = ""
    shortquoted = False
    for a in s:
        if isinstance(a, str):
            aO = ord(a)
        else:
            aO = a
            a = chr(aO)
        
        if a in ALLOWED:
            r += a
            shortquoted = False
        elif a in "0123456789":
            if shortquoted:
                a = "\\" + ("000" + oct(aO)[2:])[-4:]
            shortquoted = False
            r += a
        else:
            a = "\\" + '0'+oct(aO)[2:]
            r += a
            shortquoted = len(a) < 5
    return r


def apply_prepare_for_echo(shell, repres):
    a = ECHO_TEST + " $E '" + repres + "' \n exit "
    p = subprocess.Popen([shell], stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
    (i, o) = (p.stdout, p.stdin)
    o.write(a.encode("utf-8"))
    o.close()
    a = i.read()
    res = a.decode("utf-8")
    i.close()
    return res


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
        return "%3a".join(v.split(":"))
    else:
        return v


def version_demangle(v):
    if "%" in v:
        return ":".join(v.split("%3a"))
    else:
        return v


def delta_base_name(pkg, old_ver, new_ver, arch, ext=".debdelta"):
    assert ":" not in pkg
    return pkg + "_" + version_mangle(old_ver) + "_" + version_mangle(new_ver) + "_" + arch + ext


def tempo():
    td = tempfile.mkdtemp(prefix="debdelta", dir=TMPDIR)
    TD = Path(td).absolute()
    for i in "OLD", "NEW", "PATCH":
        (TD / i).mkdir()
    if VERBOSE > 2 or KEEP:
        logger.debug("Temporary in " + TD)
    return TD



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

    def __next__(self):
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

    def __next__(self):
        n = next(super(cache_same_dict, self))
        return dict(list(map(lambda x, y: (x, y), self.keys, n)))  # dict comprehension may be used instead


def list_tar(f):
    assert f.is_file()
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


def decompress_data(data, ext):
    return ext2CompressorMapping[ext].decompress(data)


def unzip(data, suffix):
    f = decompress_data(data, suffix)
    return (f, "." + suffix)


def decompress_file_from_ar(oldnew, name, p=None):
    shouldClose = False
    if not isinstance(oldnew, arpy.Archive):
        shouldClose = True
        oldnew = arpy.Archive(oldnew)
        headers = oldnew.read_all_headers()
    
    if isinstance(name, str):
        nameP = PurePath(name)
        name = name.encode("utf-8")
    else:
        nameP = PurePath(name.decode("utf-8"))
    
    f = oldnew.archived_files[name]
    res = f.read()
    f.seek(0)
    
    if shouldClose:
        oldnew.close()
    if nameP.suffix:
        s = nameP.suffix[1:]
        if s in ext2CompressorMapping:
            res = decompress_data(res, s)
    return res

def untar_control_in_deb(arOld=None):
    shouldClose = False
    if not isinstance(arOld, arpy.Archive):
        shouldClose = True
        arOld = arpy.Archive(ar_ls)
        headers = arOld.read_all_headers()
    
    ar_list_old = arOld.archived_files.keys()
    
    controlNamePrefix = b"control.tar."
    
    controlName = None
    for a in ar_list_old:
        if a.startswith(controlNamePrefix):
            controlName = a
            break
    
    res = decompress_file_from_ar(arOld, controlName)

    if shouldClose:
        arOld.close()
    return res


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
