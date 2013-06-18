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

#############################################

import fnmatch
import os
import re

import subprocess
import cirruscluster.ext.ansible.constants as C
from cirruscluster.ext.ansible.inventory.ini import InventoryParser
from cirruscluster.ext.ansible.inventory.script import InventoryScript
from cirruscluster.ext.ansible.inventory.group import Group
from cirruscluster.ext.ansible.inventory.host import Host
from cirruscluster.ext.ansible import errors
from cirruscluster.ext.ansible import utils

class Inventory(object):
    """
    Host inventory for cirruscluster.ext.ansible.
    """

    __slots__ = [ 'host_list', 'groups', '_restriction', '_also_restriction', '_subset', '_is_script',
                  'parser', '_vars_per_host', '_vars_per_group', '_hosts_cache', '_groups_list']

    def __init__(self, host_list=C.DEFAULT_HOST_LIST):

        # the host file file, or script path, or list of hosts
        # if a list, inventory data will NOT be loaded
        self.host_list = host_list

        # caching to avoid repeated calculations, particularly with
        # external inventory scripts.

        self._vars_per_host  = {}
        self._vars_per_group = {}
        self._hosts_cache    = {}
        self._groups_list    = {} 

        # the inventory object holds a list of groups
        self.groups = []

        # a list of host(names) to contain current inquiries to
        self._restriction = None
        self._also_restriction = None
        self._subset = None

        # whether the inventory file is a script
        self._is_script = False

        if type(host_list) in [ str, unicode ]:
            if host_list.find(",") != -1:
                host_list = host_list.split(",")
                host_list = [ h for h in host_list if h and h.strip() ]

        else:
            utils.plugins.vars_loader.add_directory(self.basedir())

        if type(host_list) == list:
            all = Group('all')
            self.groups = [ all ]
            for x in host_list:
                if x.find(":") != -1:
                    tokens = x.split(":",1)
                    all.add_host(Host(tokens[0], tokens[1]))
                else:
                    all.add_host(Host(x))
        elif utils.is_executable(host_list):
            self._is_script = True
            self.parser = InventoryScript(filename=host_list)
            self.groups = self.parser.groups.values()
        else:
            data = file(host_list).read()
            if not data.startswith("---"):
                self.parser = InventoryParser(filename=host_list)
                self.groups = self.parser.groups.values()
            else:
                raise errors.AnsibleError("YAML inventory support is deprecated in 0.6 and removed in 0.7, see the migration script in examples/scripts in the git checkout")

    def _match(self, str, pattern_str):
        if pattern_str.startswith('~'):
            return re.search(pattern_str[1:], str)
        else:
            return fnmatch.fnmatch(str, pattern_str)

    def get_hosts(self, pattern="all"):
        """ 
        find all host names matching a pattern string, taking into account any inventory restrictions or
        applied subsets.
        """

        # process patterns
        if isinstance(pattern, list):
            pattern = ';'.join(pattern)
        patterns = pattern.replace(";",":").split(":")
        hosts = self._get_hosts(patterns)

        # exclude hosts not in a subset, if defined
        if self._subset:
            subset = self._get_hosts(self._subset)
            hosts.intersection_update(subset)

        # exclude hosts mentioned in any restriction (ex: failed hosts)
        if self._restriction is not None:
            hosts = [ h for h in hosts if h.name in self._restriction ]
        if self._also_restriction is not None:
            hosts = [ h for h in hosts if h.name in self._also_restriction ]

        return sorted(hosts, key=lambda x: x.name)

    def _get_hosts(self, patterns):
        """
        finds hosts that match a list of patterns. Handles negative
        matches as well as intersection matches.
        """

        hosts = set()
        for p in patterns:
            if p.startswith("!"):
                # Discard excluded hosts
                hosts.difference_update(self.__get_hosts(p))
            elif p.startswith("&"):
                # Only leave the intersected hosts
                hosts.intersection_update(self.__get_hosts(p))
            else:
                # Get all hosts from both patterns
                hosts.update(self.__get_hosts(p))
        return hosts

    def __get_hosts(self, pattern):
        """ 
        finds hosts that postively match a particular pattern.  Does not
        take into account negative matches.
        """

        (name, enumeration_details) = self._enumeration_info(pattern)
        hpat = self._hosts_in_unenumerated_pattern(name)
        hpat = sorted(hpat, key=lambda x: x.name)

        return set(self._apply_ranges(pattern, hpat))

    def _enumeration_info(self, pattern):
        """
        returns (pattern, limits) taking a regular pattern and finding out
        which parts of it correspond to start/stop offsets.  limits is
        a tuple of (start, stop) or None
        """

        if not "[" in pattern or pattern.startswith('~'):
            return (pattern, None)
        (first, rest) = pattern.split("[")
        rest = rest.replace("]","")
        if "-" in rest:
            (left, right) = rest.split("-",1)
            return (first, (left, right))
        else:
            return (first, (rest, rest))

    def _apply_ranges(self, pat, hosts):
        """
        given a pattern like foo, that matches hosts, return all of hosts
        given a pattern like foo[0:5], where foo matches hosts, return the first 6 hosts
        """ 

        (loose_pattern, limits) = self._enumeration_info(pat)
        if not limits:
            return hosts

        (left, right) = limits
        enumerated = enumerate(hosts)
        if left == '':
            left = 0
        if right == '':
            right = 0
        left=int(left)
        right=int(right)
        enumerated = [ h for (i,h) in enumerated if i>=left and i<=right ]
        return enumerated

    # TODO: cache this logic so if called a second time the result is not recalculated
    def _hosts_in_unenumerated_pattern(self, pattern):
        """ Get all host names matching the pattern """

        hosts = {}
        # ignore any negative checks here, this is handled elsewhere
        pattern = pattern.replace("!","").replace("&", "")

        groups = self.get_groups()
        for group in groups:
            for host in group.get_hosts():
                if pattern == 'all' or self._match(group.name, pattern) or self._match(host.name, pattern):
                    hosts[host.name] = host
        return sorted(hosts.values(), key=lambda x: x.name)

    def groups_for_host(self, host):
        results = []
        groups = self.get_groups()
        for group in groups:
            for hostn in group.get_hosts():
                if host == hostn.name:
                    results.append(group)
                    continue
        return results

    def groups_list(self):
        if not self._groups_list:
            groups = {}
            for g in self.groups:
                groups[g.name] = [h.name for h in g.get_hosts()]
                ancestors = g.get_ancestors()
                for a in ancestors:
                    groups[a.name] = [h.name for h in a.get_hosts()]
            self._groups_list = groups
        return self._groups_list

    def get_groups(self):
        return self.groups

    def get_host(self, hostname):
        if hostname not in self._hosts_cache:
            self._hosts_cache[hostname] = self._get_host(hostname)
        return self._hosts_cache[hostname]

    def _get_host(self, hostname):
        for group in self.groups:
            for host in group.get_hosts():
                if hostname == host.name:
                    return host
        return None

    def get_group(self, groupname):
        for group in self.groups:
            if group.name == groupname:
                return group
        return None

    def get_group_variables(self, groupname):
        if groupname not in self._vars_per_group:
            self._vars_per_group[groupname] = self._get_group_variables(groupname)
        return self._vars_per_group[groupname]

    def _get_group_variables(self, groupname):
        group = self.get_group(groupname)
        if group is None:
            raise Exception("group not found: %s" % groupname)
        return group.get_variables()

    def get_variables(self, hostname):
        if hostname not in self._vars_per_host:
            self._vars_per_host[hostname] = self._get_variables(hostname)
        return self._vars_per_host[hostname]

    def _get_variables(self, hostname):

        host = self.get_host(hostname)
        if host is None:
            raise errors.AnsibleError("host not found: %s" % hostname)

        vars = {}
        for updated in map(lambda x: x.run(host), utils.plugins.vars_loader.all(self)):
            if updated is not None:
                vars.update(updated)

        vars.update(host.get_variables())
        if self._is_script:
            cmd = [self.host_list,"--host",hostname]
            try:
                sp = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError, e:
                raise errors.AnsibleError("problem running %s (%s)" % (' '.join(cmd), e))
            (out, err) = sp.communicate()
            results = utils.parse_json(out)

            vars.update(results)
        return vars

    def add_group(self, group):
        self.groups.append(group)

    def list_hosts(self, pattern="all"):
        return [ h.name for h in self.get_hosts(pattern) ]

    def list_groups(self):
        return sorted([ g.name for g in self.groups ], key=lambda x: x)

    # TODO: remove this function
    def get_restriction(self):
        return self._restriction

    def restrict_to(self, restriction):
        """ 
        Restrict list operations to the hosts given in restriction.  This is used
        to exclude failed hosts in main playbook code, don't use this for other
        reasons.
        """
        if type(restriction) != list:
            restriction = [ restriction ]
        self._restriction = restriction

    def also_restrict_to(self, restriction):
        """
        Works like restict_to but offers an additional restriction.  Playbooks use this
        to implement serial behavior.
        """
        if type(restriction) != list:
            restriction = [ restriction ]
        self._also_restriction = restriction
    
    def subset(self, subset_pattern):
        """ 
        Limits inventory results to a subset of inventory that matches a given
        pattern, such as to select a given geographic of numeric slice amongst
        a previous 'hosts' selection that only select roles, or vice versa.  
        Corresponds to --limit parameter to ansible-playbook
        """        
        if subset_pattern is None:
            self._subset = None
        else:
            subset_pattern = subset_pattern.replace(',',':')
            self._subset = subset_pattern.replace(";",":").split(":")

    def lift_restriction(self):
        """ Do not restrict list operations """
        self._restriction = None
    
    def lift_also_restriction(self):
        """ Clears the also restriction """
        self._also_restriction = None

    def is_file(self):
        """ did inventory come from a file? """
        if not isinstance(self.host_list, basestring):
            return False
        return os.path.exists(self.host_list)

    def basedir(self):
        """ if inventory came from a file, what's the directory? """
        if not self.is_file():
            return None
        return os.path.dirname(self.host_list)
