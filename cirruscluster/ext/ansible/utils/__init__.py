# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import shlex
import yaml
import copy
import optparse
import operator
from cirruscluster.ext.ansible import errors
from cirruscluster.ext.ansible import __version__
from cirruscluster.ext.ansible.utils.template import *
from cirruscluster.ext.ansible.utils.plugins import *
import cirruscluster.ext.ansible.constants as C
import time
import StringIO
import stat
import termios
import tty
import pipes
import random

VERBOSITY=0

try:
    import json
except ImportError:
    import simplejson as json

try:
    from hashlib import md5 as _md5
except ImportError:
    from md5 import md5 as _md5

PASSLIB_AVAILABLE = False
try:
    import passlib.hash
    PASSLIB_AVAILABLE = True
except:
    pass

KEYCZAR_AVAILABLE=False
try:
    import keyczar.errors as key_errors
    from keyczar.keys import AesKey
    KEYCZAR_AVAILABLE=True
except ImportError:
    pass

###############################################################
# abtractions around keyczar

def key_for_hostname(hostname):
    # fireball mode is an implementation of ansible firing up zeromq via SSH
    # to use no persistent daemons or key management

    if not KEYCZAR_AVAILABLE:
        raise errors.AnsibleError("python-keyczar must be installed to use fireball mode")

    key_path = os.path.expanduser("~/.fireball.keys")
    if not os.path.exists(key_path):
        os.makedirs(key_path)
    key_path = os.path.expanduser("~/.fireball.keys/%s" % hostname)

    # use new AES keys every 2 hours, which means fireball must not allow running for longer either
    if not os.path.exists(key_path) or (time.time() - os.path.getmtime(key_path) > 60*60*2):
        key = AesKey.Generate()
        fh = open(key_path, "w")
        fh.write(str(key))
        fh.close()
        return key
    else:
        fh = open(key_path)
        key = AesKey.Read(fh.read())
        fh.close()
        return key

def encrypt(key, msg):
    return key.Encrypt(msg)

def decrypt(key, msg):
    try:
        return key.Decrypt(msg)
    except key_errors.InvalidSignatureError:
        raise errors.AnsibleError("decryption failed")

###############################################################
# UTILITY FUNCTIONS FOR COMMAND LINE TOOLS
###############################################################

def err(msg):
    ''' print an error message to stderr '''

    print >> sys.stderr, msg

def exit(msg, rc=1):
    ''' quit with an error to stdout and a failure code '''

    err(msg)
    sys.exit(rc)

def jsonify(result, format=False):
    ''' format JSON output (uncompressed or uncompressed) '''

    result2 = result.copy()
    if format:
        return json.dumps(result2, sort_keys=True, indent=4)
    else:
        return json.dumps(result2, sort_keys=True)

def write_tree_file(tree, hostname, buf):
    ''' write something into treedir/hostname '''

    # TODO: might be nice to append playbook runs per host in a similar way
    # in which case, we'd want append mode.
    path = os.path.join(tree, hostname)
    fd = open(path, "w+")
    fd.write(buf)
    fd.close()

def is_failed(result):
    ''' is a given JSON result a failed result? '''

    return ((result.get('rc', 0) != 0) or (result.get('failed', False) in [ True, 'True', 'true']))

def is_changed(result):
    ''' is a given JSON result a changed result? '''

    return (result.get('changed', False) in [ True, 'True', 'true'])

def check_conditional(conditional):

    def is_set(var):
        return not var.startswith("$")

    def is_unset(var):
        return var.startswith("$")

    try:
        return eval(conditional.replace("\n", "\\n"))
    except SyntaxError as e:
        raise errors.AnsibleError("Could not evaluate the expression: " + conditional)

def is_executable(path):
    '''is the given path executable?'''
    return (stat.S_IXUSR & os.stat(path)[stat.ST_MODE]
            or stat.S_IXGRP & os.stat(path)[stat.ST_MODE]
            or stat.S_IXOTH & os.stat(path)[stat.ST_MODE])

def prepare_writeable_dir(tree):
    ''' make sure a directory exists and is writeable '''

    if tree != '/':
        tree = os.path.realpath(os.path.expanduser(tree))
    if not os.path.exists(tree):
        try:
            os.makedirs(tree)
        except (IOError, OSError), e:
            exit("Could not make dir %s: %s" % (tree, e))
    if not os.access(tree, os.W_OK):
        exit("Cannot write to path %s" % tree)

def path_dwim(basedir, given):
    '''
    make relative paths work like folks expect.
    '''

    if given.startswith("/"):
        return given
    elif given.startswith("~/"):
        return os.path.expanduser(given)
    else:
        return os.path.join(basedir, given)

def json_loads(data):
    ''' parse a JSON string and return a data structure '''

    return json.loads(data)

def parse_json(raw_data):
    ''' this version for module return data only '''

    orig_data = raw_data

    # ignore stuff like tcgetattr spewage or other warnings
    data = filter_leading_non_json_lines(raw_data)

    try:
        return json.loads(data)
    except:
        # not JSON, but try "Baby JSON" which allows many of our modules to not
        # require JSON and makes writing modules in bash much simpler
        results = {}
        try:
            tokens = shlex.split(data)
        except:
            print "failed to parse json: "+ data
            raise

        for t in tokens:
            if t.find("=") == -1:
                raise errors.AnsibleError("failed to parse: %s" % orig_data)
            (key,value) = t.split("=", 1)
            if key == 'changed' or 'failed':
                if value.lower() in [ 'true', '1' ]:
                    value = True
                elif value.lower() in [ 'false', '0' ]:
                    value = False
            if key == 'rc':
                value = int(value)
            results[key] = value
        if len(results.keys()) == 0:
            return { "failed" : True, "parsed" : False, "msg" : orig_data }
        return results

def parse_yaml(data):
    ''' convert a yaml string to a data structure '''
    return yaml.load(data)

def parse_yaml_from_file(path):
    ''' convert a yaml file to a data structure '''

    try:
        data = file(path).read()
        return parse_yaml(data)
    except IOError:
        raise errors.AnsibleError("file not found: %s" % path)
    except yaml.YAMLError, exc:
        if hasattr(exc, 'problem_mark'):
            mark = exc.problem_mark
            if mark.line -1 >= 0:
                before_probline = data.split("\n")[mark.line-1]
            else:
                before_probline = ''
            probline = data.split("\n")[mark.line]
            arrow = " " * mark.column + "^"
            msg = """Syntax Error while loading YAML script, %s
Note: The error may actually appear before this position: line %s, column %s

%s
%s
%s""" % (path, mark.line + 1, mark.column + 1, before_probline, probline, arrow)
        else:
            # No problem markers means we have to throw a generic
            # "stuff messed up" type message. Sry bud.
            msg = "Could not parse YAML. Check over %s again." % path
        raise errors.AnsibleYAMLValidationFailed(msg)

def parse_kv(args):
    ''' convert a string of key/value items to a dict '''

    options = {}
    if args is not None:
        # attempting to split a unicode here does bad things
        vargs = shlex.split(str(args), posix=True)
        for x in vargs:
            if x.find("=") != -1:
                k, v = x.split("=",1)
                options[k]=v
    return options

def merge_hash(a, b):
    ''' merges hash b into a
    this means that if b has key k, the resulting has will have a key k
    which value comes from b
    said differently, all key/value combination from b will override a's '''

    # and iterate over b keys
    for k, v in b.iteritems():
        if k in a and isinstance(a[k], dict):
            # if this key is a hash and exists in a
            # we recursively call ourselves with 
            # the key value of b
            a[k] = merge_hash(a[k], v)
        else:
            # k is not in a, no need to merge b, we just deecopy
            # or k is not a dictionnary, no need to merge b either, we just deecopy it
            a[k] = v
    # finally, return the resulting hash when we're done iterating keys
    return a

def md5s(data):
    ''' Return MD5 hex digest of data. '''

    digest = _md5()
    digest.update(data)
    return digest.hexdigest()

def md5(filename):
    ''' Return MD5 hex digest of local file, or None if file is not present. '''

    if not os.path.exists(filename):
        return None
    digest = _md5()
    blocksize = 64 * 1024
    infile = open(filename, 'rb')
    block = infile.read(blocksize)
    while block:
        digest.update(block)
        block = infile.read(blocksize)
    infile.close()
    return digest.hexdigest()

def default(value, function):
    ''' syntactic sugar around lazy evaluation of defaults '''
    if value is None:
        return function()
    return value

def _gitinfo():
    ''' returns a string containing git branch, commit id and commit date '''
    result = None
    repo_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '.git')

    if os.path.exists(repo_path):
        # Check if the .git is a file. If it is a file, it means that we are in a submodule structure.
        if os.path.isfile(repo_path):
            try:
                gitdir = yaml.load(open(repo_path)).get('gitdir')
                # There is a posibility the .git file to have an absolute path.
                if os.path.isabs(gitdir):
                    repo_path = gitdir
                else:
                    repo_path = os.path.join(repo_path.split('.git')[0], gitdir)
            except (IOError, AttributeError):
                return ''
        f = open(os.path.join(repo_path, "HEAD"))
        branch = f.readline().split('/')[-1].rstrip("\n")
        f.close()
        branch_path = os.path.join(repo_path, "refs", "heads", branch)
        if os.path.exists(branch_path):
            f = open(branch_path)
            commit = f.readline()[:10]
            f.close()
            date = time.localtime(os.stat(branch_path).st_mtime)
            if time.daylight == 0:
                offset = time.timezone
            else:
                offset = time.altzone
            result = "({0} {1}) last updated {2} (GMT {3:+04d})".format(branch, commit,
                time.strftime("%Y/%m/%d %H:%M:%S", date), offset / -36)
    else:
        result = ''
    return result

def version(prog):
    result = "{0} {1}".format(prog, __version__)
    gitinfo = _gitinfo()
    if gitinfo:
        result = result + " {0}".format(gitinfo)
    return result

def getch():
    ''' read in a single character '''
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

####################################################################
# option handling code for /usr/bin/ansible and ansible-playbook
# below this line

class SortedOptParser(optparse.OptionParser):
    '''Optparser which sorts the options by opt before outputting --help'''

    def format_help(self, formatter=None):
        self.option_list.sort(key=operator.methodcaller('get_opt_string'))
        return optparse.OptionParser.format_help(self, formatter=None)

def increment_debug(option, opt, value, parser):
    global VERBOSITY
    VERBOSITY += 1

def base_parser(constants=C, usage="", output_opts=False, runas_opts=False,
    async_opts=False, connect_opts=False, subset_opts=False):
    ''' create an options parser for any ansible script '''

    parser = SortedOptParser(usage, version=version("%prog"))
    parser.add_option('-v','--verbose', default=False, action="callback",
        callback=increment_debug, help="verbose mode (-vvv for more)")

    parser.add_option('-f','--forks', dest='forks', default=constants.DEFAULT_FORKS, type='int',
        help="specify number of parallel processes to use (default=%s)" % constants.DEFAULT_FORKS)
    parser.add_option('-i', '--inventory-file', dest='inventory',
        help="specify inventory host file (default=%s)" % constants.DEFAULT_HOST_LIST,
        default=constants.DEFAULT_HOST_LIST)
    parser.add_option('-k', '--ask-pass', default=False, dest='ask_pass', action='store_true',
        help='ask for SSH password')
    parser.add_option('--private-key', default=C.DEFAULT_PRIVATE_KEY_FILE, dest='private_key_file',
        help='use this file to authenticate the connection')
    parser.add_option('-K', '--ask-sudo-pass', default=False, dest='ask_sudo_pass', action='store_true',
        help='ask for sudo password')
    parser.add_option('-M', '--module-path', dest='module_path',
        help="specify path(s) to module library (default=%s)" % constants.DEFAULT_MODULE_PATH,
        default=None)

    if subset_opts:
        parser.add_option('-l', '--limit', default=constants.DEFAULT_SUBSET, dest='subset',
            help='further limit selected hosts to an additional pattern')

    parser.add_option('-T', '--timeout', default=constants.DEFAULT_TIMEOUT, type='int',
        dest='timeout',
        help="override the SSH timeout in seconds (default=%s)" % constants.DEFAULT_TIMEOUT)

    if output_opts:
        parser.add_option('-o', '--one-line', dest='one_line', action='store_true',
            help='condense output')
        parser.add_option('-t', '--tree', dest='tree', default=None,
            help='log output to this directory')

    if runas_opts:
        parser.add_option("-s", "--sudo", default=False, action="store_true",
            dest='sudo', help="run operations with sudo (nopasswd)")
        parser.add_option('-U', '--sudo-user', dest='sudo_user', help='desired sudo user (default=root)',
            default=None)   # Can't default to root because we need to detect when this option was given
        parser.add_option('-u', '--user', default=constants.DEFAULT_REMOTE_USER,
            dest='remote_user',
            help='connect as this user (default=%s)' % constants.DEFAULT_REMOTE_USER)

    if connect_opts:
        parser.add_option('-c', '--connection', dest='connection',
                          default=C.DEFAULT_TRANSPORT,
                          help="connection type to use (default=%s)" % C.DEFAULT_TRANSPORT)

    if async_opts:
        parser.add_option('-P', '--poll', default=constants.DEFAULT_POLL_INTERVAL, type='int',
            dest='poll_interval',
            help="set the poll interval if using -B (default=%s)" % constants.DEFAULT_POLL_INTERVAL)
        parser.add_option('-B', '--background', dest='seconds', type='int', default=0,
            help='run asynchronously, failing after X seconds (default=N/A)')

    return parser

def do_encrypt(result, encrypt, salt_size=None, salt=None):
    if PASSLIB_AVAILABLE:
        try:
            crypt = getattr(passlib.hash, encrypt)
        except:
            raise errors.AnsibleError("passlib does not support '%s' algorithm" % encrypt)

        if salt_size:
            result = crypt.encrypt(result, salt_size=salt_size)
        elif salt:
            result = crypt.encrypt(result, salt=salt)
        else:
            result = crypt.encrypt(result)
    else:
        raise errors.AnsibleError("passlib must be installed to encrypt vars_prompt values")

    return result

def last_non_blank_line(buf):

    all_lines = buf.splitlines()
    all_lines.reverse()
    for line in all_lines:
        if (len(line) > 0):
            return line
    # shouldn't occur unless there's no output
    return ""

def filter_leading_non_json_lines(buf):
    '''
    used to avoid random output from SSH at the top of JSON output, like messages from
    tcagetattr, or where dropbear spews MOTD on every single command (which is nuts).

    need to filter anything which starts not with '{', '[', ', '=' or is an empty line.
    filter only leading lines since multiline JSON is valid.
    '''

    filtered_lines = StringIO.StringIO()
    stop_filtering = False
    for line in buf.splitlines():
        if stop_filtering or "=" in line or line.startswith('{') or line.startswith('['):
            stop_filtering = True
            filtered_lines.write(line + '\n')
    return filtered_lines.getvalue()

def boolean(value):
    val = str(value)
    if val.lower() in [ "true", "t", "y", "1", "yes" ]:
        return True
    else:
        return False

def compile_when_to_only_if(expression):
    '''
    when is a shorthand for writing only_if conditionals.  It requires less quoting
    magic.  only_if is retained for backwards compatibility.
    '''

    # when: set $variable
    # when: unset $variable
    # when: failed $json_result
    # when: changed $json_result
    # when: int $x >= $z and $y < 3
    # when: int $x in $alist
    # when: float $x > 2 and $y <= $z
    # when: str $x != $y

    if type(expression) not in [ str, unicode ]:
        raise errors.AnsibleError("invalid usage of when_ operator: %s" % expression)
    tokens = expression.split()
    if len(tokens) < 2:
        raise errors.AnsibleError("invalid usage of when_ operator: %s" % expression)

    # when_set / when_unset
    if tokens[0] in [ 'set', 'unset' ]:
        tcopy = tokens[1:]
        for (i,t) in enumerate(tokens[1:]):
            if t.find("$") != -1:
                tcopy[i] = "is_%s('''%s''')" % (tokens[0], t)
            else:
                tcopy[i] = t
        return " ".join(tcopy)



    # when_failed / when_changed
    elif tokens[0] in [ 'failed', 'changed' ]:
        tcopy = tokens[1:]
        for (i,t) in enumerate(tokens[1:]):
            if t.find("$") != -1:
                tcopy[i] = "is_%s(%s)" % (tokens[0], t)
            else:
                tcopy[i] = t
        return " ".join(tcopy)



    # when_integer / when_float / when_string
    elif tokens[0] in [ 'integer', 'float', 'string' ]:
        cast = None
        if tokens[0] == 'integer':
            cast = 'int'
        elif tokens[0] == 'string':
            cast = 'str'
        elif tokens[0] == 'float':
            cast = 'float'
        tcopy = tokens[1:]
        for (i,t) in enumerate(tokens[1:]):
            if t.find("$") != -1:
                # final variable substitution will happen in Runner code
                tcopy[i] = "%s('''%s''')" % (cast, t)
            else:
                tcopy[i] = t
        return " ".join(tcopy)

    # when_boolean
    elif tokens[0] in [ 'bool', 'boolean' ]:
        tcopy = tokens[1:]
        for (i, t) in enumerate(tcopy):
            if t.find("$") != -1:
                tcopy[i] = "(is_set('''%s''') and '''%s'''.lower() not in ('false', 'no', 'n', 'none', '0', ''))" % (t, t)
        return " ".join(tcopy)

    else:
        raise errors.AnsibleError("invalid usage of when_ operator: %s" % expression)

def make_sudo_cmd(sudo_user, executable, cmd):
    """
    helper function for connection plugins to create sudo commands
    """
    # Rather than detect if sudo wants a password this time, -k makes
    # sudo always ask for a password if one is required.
    # Passing a quoted compound command to sudo (or sudo -s)
    # directly doesn't work, so we shellquote it with pipes.quote()
    # and pass the quoted string to the user's shell.  We loop reading
    # output until we see the randomly-generated sudo prompt set with
    # the -p option.
    randbits = ''.join(chr(random.randint(ord('a'), ord('z'))) for x in xrange(32))
    prompt = '[sudo via ansible, key=%s] password: ' % randbits
    sudocmd = '%s -k && %s %s -S -p "%s" -u %s %s -c %s' % (
        C.DEFAULT_SUDO_EXE, C.DEFAULT_SUDO_EXE, C.DEFAULT_SUDO_FLAGS,
        prompt, sudo_user, executable or '$SHELL', pipes.quote(cmd))
    return ('/bin/sh -c ' + pipes.quote(sudocmd), prompt)
