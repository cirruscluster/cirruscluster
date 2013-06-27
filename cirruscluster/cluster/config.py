# The MIT License (MIT)
# 
# Copyright (c) 2013 Kyle Heath
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from cirruscluster import core

class CirrusConfig(object):
  """
  Cirrus Configuration for a cluster and associated dev workstations.
  """  
  def __init__(self):
    super(CirrusConfig, self).__init__()
    self.region_name = 'us-east-1'
    self.prefered_availability_zone = self.region_name + 'b'
    self.ubuntu_release_name = 'precise'
    # Default is to use standard ami.  You can set this to your own AWS user
    # account id (only available from AWS management console) to use custom
    # AMI versions you created with ami_cli.py
    self.mapr_ami_owner_id = core.default_ami_owner_id
    self.ami_release_name =  core.default_ami_release_name
    
    # cluster params
    self.cluster_instance_type = 'c1.xlarge'  # ex: c1.xlarge, cc2.8xlarge
    self.mapr_version = 'v2.1.3'
    self.zones = ['b']
    # determines the nfs mount point on desktop /mapr/<cluster_name>
    # and name of cluster set by mapr's configure.sh
    self.cluster_name = 'iwct'
    self.master_on_spot_instances = True
    self.workers_on_spot_instances = True
    return
  
  def __repr__(self):
    #return '<%s >' % (self.region_name, self.prefered_availability_zone, self.ubuntu_release_name, self.mapr_ami_owner_id, self.cluster_instance_type, self.mapr_version, self.zones, self.cluster_name, master_on_spot_instances, self.workers_on_spot_instances)
    attrs = vars(self)
    data =  ', '.join("%s: %s" % item for item in attrs.items())
    return data
  
def GetConfiguration():
  conf = CirrusConfig()   
  return conf 

