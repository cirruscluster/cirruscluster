#!/usr/bin/python
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


""" Command Line Tool for creating Cirrus AMI releases."""
from cirruscluster import core
from cirruscluster.ami import builder
from boto.ec2 import connection  
import os
#import logging

def main():
  
  role = None
  while role not in core.valid_instance_roles:
    role = raw_input('What role %s: ' % core.valid_instance_roles)
  
  virt_type = None
  if role == 'workstation':
    virt_type = 'paravirtual'
    
  while virt_type not in core.valid_virtualization_types:
    virt_type = raw_input('Which virtualization type %s: ' % \
                           core.valid_virtualization_types)
  
  # TODO(heathkh): Give this a proper Command Line Interface instead of editing
  # the script directly  
  region_name = 'us-east-1'
  ubuntu_release_name = 'precise'
  ami_release_name = core.default_ami_release_name 
  mapr_version = 'v2.1.3'
  
  #########################################################################
  instance_type = None
  if role == 'workstation':
    if virt_type != 'paravirtual':
      raise RuntimeError('workstation must use virt_type paravirtual')
    instance_type = 'c1.xlarge'
  else:
    virt_type_to_instance_template_type = {'paravirtual' : 'c1.xlarge',
                                           'hvm' : 'cc2.8xlarge'}
    instance_type = virt_type_to_instance_template_type[virt_type]
  assert(instance_type)
  ec2 = None
  try:
    ec2 = connection.EC2Connection(region = core.GetRegion(region_name))
  except boto.exception.NoAuthHandlerFound:
    print 'Can not authenticate.  Make sure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY env variables are set!'   
  
  ami_spec = builder.AmiSpecification(ami_release_name, region_name, 
                                      instance_type, ubuntu_release_name, 
                                      mapr_version, role)  
  keypair_name = 'cirrus_ami_maker_tmp1'
  # TODO(heathkh): Change this to use OS specific home directory (win, mac)
  key_dir_path = os.path.expanduser('~/keys/')
  private_key_filename = '%s/%s.pem' % (key_dir_path, keypair_name)
  if not os.path.exists(key_dir_path):
    os.mkdir(key_dir_path)  
  try:
    keypair = ec2.create_key_pair(keypair_name)
    keypair.save(key_dir_path)
  except:
    pass
  ssh_key = open(private_key_filename, 'r').read()
  ami_maker = builder.AmiBuilder(ec2, ami_spec, keypair_name, ssh_key)  
  ami_maker.Run()
  #TODO(heathkh): Copy the ami to all other regions and set the required 
  # permissions and tags as well
  return

if __name__ == "__main__":
  main()
