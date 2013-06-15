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

import os

class CirrusConfig(object):
  """
  Cirrus Configuration for a cluster and associated dev workstations.
  """  
  def __init__(self):
    super(CirrusConfig, self).__init__()
    self.region_name = 'us-east-1'
    self.prefered_availability_zone = self.region_name + 'b'
    self.ubuntu_release_name = 'precise'
    self.mapr_ami_owner_id = None # Default is to use standard ami.  You can set this to your own AWS user account id (only available from AWS management console) to use custom AMI versions you created with ami_cli.py
    
    
    # cluster params
    self.cluster_instance_type = 'c1.xlarge'        
    #self.cluster_instance_type = 'cc2.8xlarge'        
    #self.cluster_instance_type = 'cc1.4xlarge'
    self.mapr_version = 'v2.1.3'
    self.zones = ['b'] # list like this ['a','c','e']
    self.cluster_name = 'iwct' # determines the nfs mount point on desktop /mapr/<cluster_name> and name of cluster set by mapr's configure.sh 
    return
  
def GetConfiguration():
  conf = CirrusConfig()   
  return conf 

