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

class AnsibleError(Exception):
    ''' The base Ansible exception from which all others should subclass '''

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class AnsibleFileNotFound(AnsibleError):
    pass

class AnsibleConnectionFailed(AnsibleError):
    pass

class AnsibleYAMLValidationFailed(AnsibleError):
    pass
