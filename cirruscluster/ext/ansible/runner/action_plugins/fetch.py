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
import pwd
import random
import traceback
import tempfile
import base64

import ansible.constants as C
from ansible import utils
from ansible import errors
from ansible import module_common
from ansible.runner.return_data import ReturnData

class ActionModule(object):

    def __init__(self, runner):
        self.runner = runner

    def run(self, conn, tmp, module_name, module_args, inject):
        ''' handler for fetch operations '''

        # load up options
        options = utils.parse_kv(module_args)
        source = options.get('src', None)
        dest = options.get('dest', None)
        if source is None or dest is None:
            results = dict(failed=True, msg="src and dest are required")
            return ReturnData(conn=conn, result=results)

        # files are saved in dest dir, with a subdir for each host, then the filename
        dest   = "%s/%s/%s" % (utils.path_dwim(self.runner.basedir, dest), conn.host, source)
        dest   = dest.replace("//","/")

        # calculate md5 sum for the remote file
        remote_md5 = self.runner._remote_md5(conn, tmp, source)

        # use slurp if sudo and permissions are lacking
        remote_data = None
        if remote_md5 in ('1', '2') and self.runner.sudo:
            slurpres = self.runner._execute_module(conn, tmp, 'slurp', 'src=%s' % source, inject=inject)
            if slurpres.is_successful():
                if slurpres.result['encoding'] == 'base64':
                    remote_data = base64.b64decode(slurpres.result['content'])
                if remote_data is not None:
                    remote_md5 = utils.md5s(remote_data)

        # these don't fail because you may want to transfer a log file that possibly MAY exist
        # but keep going to fetch other log files
        if remote_md5 == '0':
            result = dict(msg="unable to calculate the md5 sum of the remote file", file=source, changed=False)
            return ReturnData(conn=conn, result=result)
        if remote_md5 == '1':
            result = dict(msg="the remote file does not exist, not transferring, ignored", file=source, changed=False)
            return ReturnData(conn=conn, result=result)
        if remote_md5 == '2':
            result = dict(msg="no read permission on remote file, not transferring, ignored", file=source, changed=False)
            return ReturnData(conn=conn, result=result)

        # calculate md5 sum for the local file
        local_md5 = utils.md5(dest)

        if remote_md5 != local_md5:
            # create the containing directories, if needed
            if not os.path.isdir(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))

            # fetch the file and check for changes
            if remote_data is None:
                conn.fetch_file(source, dest)
            else:
                f = open(dest, 'w')
                f.write(remote_data)
                f.close()
            new_md5 = utils.md5(dest)
            if new_md5 != remote_md5:
                result = dict(failed=True, md5sum=new_md5, msg="md5 mismatch", file=source, dest=dest)
                return ReturnData(conn=conn, result=result)
            result = dict(changed=True, md5sum=new_md5, dest=dest)
            return ReturnData(conn=conn, result=result)
        else:
            result = dict(changed=False, md5sum=local_md5, file=source, dest=dest)
            return ReturnData(conn=conn, result=result)

