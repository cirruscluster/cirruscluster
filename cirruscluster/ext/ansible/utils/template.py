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

import os
import re
import codecs
import jinja2
import yaml
import json
from cirruscluster.ext.ansible import errors
import cirruscluster.ext.ansible.constants as C
import time
import subprocess
import datetime
import pwd

# TODO: refactor this file

_LISTRE = re.compile(r"(\w+)\[(\d+)\]")
JINJA2_OVERRIDE='#jinja2:'

def _varFindLimitSpace(basedir, vars, space, part, lookup_fatal, depth):
    ''' limits the search space of space to part
    
    basically does space.get(part, None), but with
    templating for part and a few more things
    '''

    # Previous part couldn't be found, nothing to limit to
    if space is None:
        return space
    # A part with escaped .s in it is compounded by { and }, remove them
    if part[0] == '{' and part[-1] == '}':
        part = part[1:-1]
    # Template part to resolve variables within (${var$var2})
    part = varReplace(basedir, part, vars, lookup_fatal, depth=depth + 1)

    # Now find it
    if part in space:
        space = space[part]
    elif "[" in part:
        m = _LISTRE.search(part)
        if not m:
            return None
        else:
            try:
                space = space[m.group(1)][int(m.group(2))]
            except (KeyError, IndexError):
                return None
    else:
        return None

    # if space is a string, check if it's a reference to another variable
    if isinstance(space, basestring):
        space = template_ds(basedir, space, vars, lookup_fatal, depth)

    return space

def _varFind(basedir, text, vars, lookup_fatal, depth=0):
    ''' Searches for a variable in text and finds its replacement in vars

    The variables can have two formats;
    - simple, $ followed by alphanumerics and/or underscores
    - complex, ${ followed by alphanumerics, underscores, periods, braces and brackets, ended by a }

    Examples:
    - $variable: simple variable that will have vars['variable'] as its replacement
    - ${variable.complex}: complex variable that will have vars['variable']['complex'] as its replacement
    - $variable.complex: simple variable, identical to the first, .complex ignored

    Complex variables are broken into parts by separating on periods, except if enclosed in {}.
    ${variable.{fully.qualified.domain}} would be parsed as two parts, variable and fully.qualified.domain,
    whereas ${variable.fully.qualified.domain} would be parsed as four parts.

    Returns a dict(replacement=<value in vars>, start=<index into text where the variable stated>,
        end=<index into text where the variable ends>)
    or None if no variable could be found in text. If replacement is None, it should be replaced with the
    original data in the caller.
    '''

    start = text.find("$")
    if start == -1:
        return None
    # $ as last character
    if start + 1 == len(text):
        return None
    # Escaped var
    if start > 0 and text[start - 1] == '\\':
        return {'replacement': '$', 'start': start - 1, 'end': start + 1}

    var_start = start + 1
    if text[var_start] == '{':
        is_complex = True
        brace_level = 1
        var_start += 1
    else:
        is_complex = False
        brace_level = 1
    # is_lookup is true for $FILE(...) and friends
    is_lookup = False
    lookup_plugin_name = None
    end = var_start
    # part_start is an index of where the current part started
    part_start = var_start
    space = vars
    while end < len(text) and (((is_lookup or is_complex) and brace_level > 0) or (not is_complex and not is_lookup)):
        if text[end].isalnum() or text[end] == '_':
            pass
        elif not is_complex and not is_lookup and text[end] == '(' and text[part_start:end].isupper():
            is_lookup = True
            lookup_plugin_name = text[part_start:end]
            part_start = end + 1
        elif is_lookup and text[end] == '(':
            brace_level += 1
        elif is_lookup and text[end] == ')':
            brace_level -= 1
        elif is_lookup:
            # lookups are allowed arbitrary contents
            pass
        elif is_complex and text[end] == '{':
            brace_level += 1
        elif is_complex and text[end] == '}':
            brace_level -= 1
        elif is_complex and text[end] in ('$', '[', ']'):
            pass
        elif is_complex and text[end] == '.':
            if brace_level == 1:
                space = _varFindLimitSpace(basedir, vars, space, text[part_start:end], lookup_fatal, depth)
                part_start = end + 1
        else:
            # This breaks out of the loop on non-variable name characters
            break
        end += 1
    var_end = end
    # Handle "This has $ in it"
    if var_end == part_start:
        return {'replacement': None, 'start': start, 'end': end}

    # Handle lookup plugins
    if is_lookup:
        # When basedir is None, handle lookup plugins later
        if basedir is None:
            return {'replacement': None, 'start': start, 'end': end}
        var_end -= 1
    	from cirruscluster.ext.ansible import utils
        args = text[part_start:var_end]
        if lookup_plugin_name == 'LOOKUP':
            lookup_plugin_name, args = args.split(",", 1)
            args = args.strip()
        # args have to be templated
        args = varReplace(basedir, args, vars, depth=depth+1, expand_lists=True)
        instance = utils.plugins.lookup_loader.get(lookup_plugin_name.lower(), basedir=basedir)
        if instance is not None:
            try:
                replacement = instance.run(args, inject=vars)
            except errors.AnsibleError:
                if not lookup_fatal:
                    replacement = None
                else:
                    raise
        else:
            replacement = None
        return {'replacement': replacement, 'start': start, 'end': end}

    if is_complex:
        var_end -= 1
        if text[var_end] != '}' or brace_level != 0:
            return None
    space = _varFindLimitSpace(basedir, vars, space, text[part_start:var_end], lookup_fatal, depth)
    return {'replacement': space, 'start': start, 'end': end}

def varReplace(basedir, raw, vars, lookup_fatal=True, depth=0, expand_lists=False):
    ''' Perform variable replacement of $variables in string raw using vars dictionary '''
    # this code originally from yum

    if (depth > 20):
        raise errors.AnsibleError("template recursion depth exceeded")

    done = [] # Completed chunks to return

    while raw:
        m = _varFind(basedir, raw, vars, lookup_fatal, depth)
        if not m:
            done.append(raw)
            break

        # Determine replacement value (if unknown variable then preserve
        # original)

        replacement = m['replacement']
        if expand_lists and isinstance(replacement, (list, tuple)):
            replacement = ",".join(replacement)
        if isinstance(replacement, (str, unicode)):
            replacement = varReplace(basedir, replacement, vars, lookup_fatal, depth=depth+1, expand_lists=expand_lists)
        if replacement is None:
            replacement = raw[m['start']:m['end']]

        start, end = m['start'], m['end']
        done.append(raw[:start])          # Keep stuff leading up to token
        done.append(unicode(replacement)) # Append replacement value
        raw = raw[end:]                   # Continue with remainder of string

    return ''.join(done)

def template_ds(basedir, varname, vars, lookup_fatal=True, depth=0):
    ''' templates a data structure by traversing it and substituting for other data structures '''

    if isinstance(varname, basestring):
        m = _varFind(basedir, varname, vars, lookup_fatal, depth)
        if not m:
            return varname
        if m['start'] == 0 and m['end'] == len(varname):
            if m['replacement'] is not None:
                return template_ds(basedir, m['replacement'], vars, lookup_fatal, depth)
            else:
                return varname
        else:
            return template(basedir, varname, vars, lookup_fatal)
    elif isinstance(varname, (list, tuple)):
        return [template_ds(basedir, v, vars, lookup_fatal, depth) for v in varname]
    elif isinstance(varname, dict):
        d = {}
        for (k, v) in varname.iteritems():
            d[k] = template_ds(basedir, v, vars, lookup_fatal, depth)
        return d
    else:
        return varname

def template(basedir, text, vars, lookup_fatal=True, expand_lists=False):
    ''' run a text buffer through the templating engine until it no longer changes '''

    try:
        text = text.decode('utf-8')
    except UnicodeEncodeError:
        pass # already unicode
    text = varReplace(basedir, unicode(text), vars, lookup_fatal=lookup_fatal, expand_lists=expand_lists)
    return text

class _jinja2_vars(object):
    '''
    Helper class to template all variable content before jinja2 sees it.
    This is done by hijacking the variable storage that jinja2 uses, and
    overriding __contains__ and __getitem__ to look like a dict. Added bonus
    is avoiding duplicating the large hashes that inject tends to be.
    To facilitate using builtin jinja2 things like range, globals are handled
    here.
    extras is a list of locals to also search for variables. 
    '''
    def __init__(self, basedir, vars, globals, *extras):
        self.basedir = basedir
        self.vars = vars
        self.globals = globals
        self.extras = extras
    def __contains__(self, k):
        if k in self.vars:
            return True
        for i in self.extras:
            if k in i:
                return True
        if k in self.globals:
            return True
        return False
    def __getitem__(self, varname):
        if varname not in self.vars:
            for i in self.extras:
                if varname in i:
                    return i[varname]
            if varname in self.globals:
                return self.globals[varname]
            else:
                raise KeyError("undefined variable: %s" % varname)
        var = self.vars[varname]
        # HostVars is special, return it as-is
        if isinstance(var, dict) and type(var) != dict:
            return var
        else:
            return template_ds(self.basedir, var, self.vars)
    def add_locals(self, locals):
        '''
        If locals are provided, create a copy of self containing those
        locals in addition to what is already in this variable proxy.
        '''
        if locals is None:
            return self
        return _jinja2_vars(self.basedir, self.vars, self.globals, locals, *self.extras)

class J2Template(jinja2.environment.Template):
    '''
    This class prevents Jinja2 from running _jinja2_vars through dict()
    Without this, {% include %} and similar will create new contexts unlike
    the special one created in template_from_file. This ensures they are all
    alike, with the exception of potential locals.
    '''
    def new_context(self, vars=None, shared=False, locals=None):
        return jinja2.runtime.Context(self.environment, vars.add_locals(locals), self.name, self.blocks)

def template_from_file(basedir, path, vars):
    ''' run a file through the templating engine '''

    from cirruscluster.ext.ansible import utils
    realpath = utils.path_dwim(basedir, path)
    loader=jinja2.FileSystemLoader([basedir,os.path.dirname(realpath)])
    environment = jinja2.Environment(loader=loader, trim_blocks=True)
    for filter_plugin in utils.plugins.filter_loader.all():
        filters = filter_plugin.filters()
        if not isinstance(filters, dict):
            raise errors.AnsibleError("FilterModule.filters should return a dict.")
        environment.filters.update(filters)
    try:
        data = codecs.open(realpath, encoding="utf8").read()
    except UnicodeDecodeError:
        raise errors.AnsibleError("unable to process as utf-8: %s" % realpath)
    except:
        raise errors.AnsibleError("unable to read %s" % realpath)

    # Get jinja env overrides from template
    if data.startswith(JINJA2_OVERRIDE):
        eol = data.find('\n')
        line = data[len(JINJA2_OVERRIDE):eol]
        data = data[eol+1:]
        for pair in line.split(','):
            (key,val) = pair.split(':')
            setattr(environment,key.strip(),val.strip())

    environment.template_class = J2Template
    t = environment.from_string(data)
    vars = vars.copy()
    try:
        template_uid = pwd.getpwuid(os.stat(realpath).st_uid).pw_name
    except:
        template_uid = os.stat(realpath).st_uid
    vars['template_host']   = os.uname()[1]
    vars['template_path']   = realpath
    vars['template_mtime']  = datetime.datetime.fromtimestamp(os.path.getmtime(realpath))
    vars['template_uid']    = template_uid
    vars['template_fullpath'] = os.path.abspath(realpath)
    vars['template_run_date'] = datetime.datetime.now()

    managed_default = C.DEFAULT_MANAGED_STR
    managed_str = managed_default.format(
                    host = vars['template_host'],
                    uid  = vars['template_uid'],
                    file = vars['template_path']
                    )
    vars['ansible_managed'] = time.strftime(managed_str,
                                time.localtime(os.path.getmtime(realpath)))

    # This line performs deep Jinja2 magic that uses the _jinja2_vars object for vars
    # Ideally, this could use some API where setting shared=True and the object won't get
    # passed through dict(o), but I have not found that yet.
    res = jinja2.utils.concat(t.root_render_func(t.new_context(_jinja2_vars(basedir, vars, t.globals), shared=True)))

    if data.endswith('\n') and not res.endswith('\n'):
        res = res + '\n'
    return template(basedir, res, vars)

