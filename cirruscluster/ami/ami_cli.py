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
from cirrus.ami import manager
from boto.ec2.connection import EC2Connection
from cirruscluster import core
import os
import logging

def main():
  # TODO(heathkh): Give this a proper Command Line Interface instead of editing
  # the script directly  
  #########################################################################
  # Params you can change...
  #########################################################################
  
  #role = 'workstation'
  #role = 'master'
  role = 'worker'
  virt_type = 'hvm'
  #virt_type = 'paravirtual'
  region_name = 'us-east-1'
  ubuntu_release_name = 'precise'
  mapr_version = 'v2.1.3'
  
  #########################################################################
  instance_type = None
  if role == 'workstation':
    CHECK_EQ(virt_type, 'paravirtual', 'workstation must use virt_type pv')
    instance_type = 'c1.xlarge'
  else:
    virt_type_to_instance_template_type = {'paravirtual' : 'c1.xlarge',
                                           'hvm' : 'cc2.8xlarge'}
    instance_type = virt_type_to_instance_template_type[virt_type]
  assert(instance_type)
  ec2 = EC2Connection(region = core.GetRegion(region_name))
  ami_spec = manager.AmiSpecification(region_name, instance_type, 
                                      ubuntu_release_name, mapr_version, role)  
  keypair_name = 'cirrus_ami_maker_tmp'
  # TODO(heathkh): Change this to use OS specific home directory (win, mac)
  key_dir_path = os.path.expanduser('~/ec2/')
  private_key_filename = '%s/%s.pem' % (key_dir_path, keypair_name)
  if not os.path.exists(key_dir_path):
    os.mkdir(key_dir_path)  
  try:
    keypair = ec2.create_key_pair(keypair_name)
    keypair.save(key_dir_path)
  except:
    pass
  ssh_key = open(private_key_filename, 'r').read()
  ami_maker = manager.AmiMaker(ec2, ami_spec, keypair_name, ssh_key)  
  ami_maker.Run()
  #TODO(heathkh): Copy the ami to all other regions and set the required 
  # permissions and tags as well
  return

if __name__ == "__main__":
  main()
