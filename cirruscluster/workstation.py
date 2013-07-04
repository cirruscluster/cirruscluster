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

""" Automates connecting and managing a remote Cirrus Workstation in EC2. """

import boto
from cirruscluster.ext.nx import password
from boto.ec2 import connection as ec2_connection 
from boto.iam import connection as iam_connection
from boto.s3 import connection as s3_connection
from boto.s3 import key as s3_key
from cirruscluster import core
import pkg_resources 
import string
import logging
import time

cirrus_iam_username = 'cirrus'
workstation_profile = 'cirrus_workstation_profile'

class UnsupportedAwsRegion(Exception):
  pass


class InvalidAwsCredentials(Exception):
  pass


class InstanceInfo(object):
  def __init__(self, name, id, state, hostname):
    self.name = name
    self.id = id
    self.state = state
    self.hostname = hostname
    return

  



def CirrusIamUserReady(iam_aws_id, iam_aws_secret):
  """ Returns true if provided IAM credentials are ready to use. """
  is_ready = False
  try:
    s3 = core.CreateTestedS3Connection(iam_aws_id, iam_aws_secret)
    if s3:
      if core.CirrusAccessIdMetadata(s3, iam_aws_id).IsInitialized():
        is_ready = True            
  except boto.exception.BotoServerError as e:
    print e 
    
  return is_ready


def GetCirrusIamUserCredentials(root_aws_id, root_aws_secret):
  return CirrusIamUserManager(root_aws_id, root_aws_secret).GetCredentials()
  

def NoSuchEntityOk(f):
  """ Decorator to remove NoSuchEntity exceptions, and raises all others. """
  def ExceptionFilter(*args):
    try:
      return f(*args)
    except boto.exception.BotoServerError as e:
      if e.error_code == 'NoSuchEntity':
        pass
      else:
        raise
    except:  
      raise
    return False
  return ExceptionFilter
  
  
class CirrusIamUserManager(object):
  """ Creates the IAM user and the required policies. """
  def __init__(self, root_aws_id, root_aws_secret):
    self.root_aws_id = root_aws_id
    self.root_aws_secret = root_aws_secret
    self.iam = core.CreateTestedIamConnection(root_aws_id, root_aws_secret)
    if not self.iam:
      raise InvalidAwsCredentials()
    self.s3 = core.CreateTestedS3Connection(root_aws_id, root_aws_secret)
    if not self.s3:
      raise InvalidAwsCredentials()    
    
    self.role_name = 'cirrus_workstation'    
    return
    
  def GetCredentials(self):
    if not self.__IsInitialized():
      self.__Create()      
    iam_id = self.GetAccessKeyId()
    iam_secret = core.CirrusAccessIdMetadata(self.s3, iam_id).GetSecret()
    return iam_id, iam_secret
    
  def __IsInitialized(self):      
    """ Returns true if IAM user initialization has completed. """  
    is_initialized = False
    iam_id = self.GetAccessKeyId()
    if iam_id:
      if core.CirrusAccessIdMetadata(self.s3, iam_id).IsInitialized():
        is_initialized = True
    return is_initialized
  
  def __Cleanup(self):
    logging.info('Cleaning up iam user...')
    NoSuchEntityOk(self.iam.remove_role_from_instance_profile)(workstation_profile, self.role_name)
    NoSuchEntityOk(self.iam.delete_instance_profile)(workstation_profile)
    role_policy_names = []
    response = NoSuchEntityOk(self.iam.list_role_policies)(self.role_name)
    if response:
      role_policy_names = response['list_role_policies_response'] \
                                  ['list_role_policies_result']['policy_names']                                        
      for role_policy_name in role_policy_names:
        self.iam.delete_role_policy(self.role_name, role_policy_name)
    NoSuchEntityOk(self.iam.delete_role)(self.role_name)
    user_policy_names = []    
    response = NoSuchEntityOk(self.iam.get_all_user_policies)(cirrus_iam_username)
    if response:
      user_policy_names = response['list_user_policies_response'] \
                                  ['list_user_policies_result']['policy_names']
      for user_policy_name in user_policy_names:
        self.iam.delete_user_policy(cirrus_iam_username, user_policy_name)
    response = NoSuchEntityOk(self.iam.get_all_access_keys)(cirrus_iam_username)
    if response:
      access_keys = response['list_access_keys_response'] \
                            ['list_access_keys_result']['access_key_metadata']
      for access_key in access_keys:
        self.iam.delete_access_key(access_key['access_key_id'], 
                                   access_key['user_name'])                             
    NoSuchEntityOk(self.iam.delete_user)(cirrus_iam_username)
    return
  
  def __Create(self):
    self.__Cleanup()    
    response = self.iam.create_user(cirrus_iam_username)
    # setup role so workstation can assume IAM credentials without additional
    # configuration    
    power_user_policy_json = """{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*"
            }
        ]
    }"""
    self.iam.put_user_policy(cirrus_iam_username, 'power_user_policy', power_user_policy_json)
    # ensure no conflicting role exists with same name
    self.iam.create_instance_profile(workstation_profile)
    workstation_role_arn = None
    response = self.iam.create_role(self.role_name)
    workstation_role_arn = response['create_role_response'] \
                                   ['create_role_result']['role']['arn']
    assert(workstation_role_arn)
    self.iam.add_role_to_instance_profile(workstation_profile, self.role_name)
    self.iam.put_role_policy(self.role_name, 'power_user_policy', power_user_policy_json)
    # update iam user to have right to launch instances with the 
    # cirrus_workstatio_role
    assume_role_policy_json = '{"Version": "2012-10-17", ' \
                  '"Statement": [{"Effect": "Allow", "Action":"iam:PassRole",' \
                  ' "Resource": "%s"}]}' % (workstation_role_arn)
    self.iam.put_user_policy(cirrus_iam_username, 
                        'assume_cirrus_workstation_role', assume_role_policy_json)
    logging.info('Creating new aws credentials for IAM user %s.'\
                  % cirrus_iam_username)
    response = self.iam.create_access_key(cirrus_iam_username)
    new_key = response['create_access_key_response']\
                      ['create_access_key_result']\
                      ['access_key']
    iam_id = new_key['access_key_id']
    assert(iam_id)
    iam_secret = new_key['secret_access_key']
    metadata = core.CirrusAccessIdMetadata(self.s3, iam_id)
    metadata.SetSecret(iam_secret)  
    metadata.SetInitialized()
    
    
    self.__WaitForCredentialsLive(iam_id, iam_secret)
    return
  
  def __WaitForCredentialsLive(self, iam_aws_id, iam_aws_secret):
    """ Wait until the new credentials are accepted in all regions and for ec2 and boto services.
       If we don't do this, we may have a race condition where calls fail (and we can't tell if the credentials are bad (stop) or not yet valid (keep trying))
    """
    print 'waiting for credentials to go live...'
    for region in core.tested_region_names:
      core.WaitForEc2Connection(iam_aws_id, iam_aws_secret, region)
    core.WaitForS3Connection(iam_aws_id, iam_aws_secret)
    
    print 'done'
    return
    
  def GetAccessKeyId(self):
    access_key_id = None
    response = NoSuchEntityOk(self.iam.get_all_access_keys)(cirrus_iam_username)
    if response:
      for key in response['list_access_keys_response'] \
                         ['list_access_keys_result'] \
                         ['access_key_metadata']:
        if key['status'] == 'Active':
          access_key_id = key['access_key_id']
          break
    return access_key_id


class Manager(object):
  def __init__(self, region_name, iam_aws_id, iam_aws_secret):
    if not iam_aws_id or not iam_aws_secret:
      raise InvalidAwsCredentials()
    if region_name not in core.tested_region_names:
      raise UnsupportedAwsRegion()
    self.region_name = region_name
    if not CirrusIamUserReady(iam_aws_id, iam_aws_secret):
      raise InvalidAwsCredentials()
    self.iam_aws_id = iam_aws_id
    self.iam_aws_secret = iam_aws_secret    
    self.ec2 = core.CreateTestedEc2Connection(iam_aws_id, iam_aws_secret, 
                                              region_name)
    if not self.ec2:
      raise InvalidAwsCredentials()
    self.s3 = core.CreateTestedS3Connection(iam_aws_id, iam_aws_secret)
    if not self.s3:
      raise InvalidAwsCredentials()    
    self.workstation_tag = 'cirrus_workstation'
    self.workstation_keypair_name = 'cirrus_workstation'
    self.ssh_key = None
    src_region = self.region_name
    dst_regions = core.tested_region_names
    self.ssh_key = core.InitKeypair(self.iam_aws_id, self.iam_aws_secret, 
                                    self.ec2, self.s3,  
                                    self.workstation_keypair_name, src_region,
                                    dst_regions)
    return


  def Debug(self):
    res = self.ec2.get_all_instances(instance_ids=['i-b65fbbda'])
    instance = res[0].instances[0]
    params = {'InstanceId' : instance.id,
              'BlockDeviceMapping.1.DeviceName' : '/dev/sda1',
              'BlockDeviceMapping.1.Ebs.VolumeId' : 'vol-c3516299',
              'BlockDeviceMapping.1.Ebs.DeleteOnTermination' : 'true'}
    instance.connection.get_status('ModifyInstanceAttribute', params, verb='POST')
    instance.update()
    return
  
  def ListInstances(self):
    ec2_instances = [i for i in self.__GetInstances() 
                     if i.state != 'terminated' 
                        and self.workstation_tag in i.tags
                        and 'Name' in i.tags]
    instance_info = []
    for i in ec2_instances:
      instance_info.append(InstanceInfo(i.tags['Name'], i.id, i.state, i.public_dns_name))
    return instance_info

  def GetInstanceInfo(self, instance_id):
    instance = self.__GetInstanceById(instance_id)
    assert(instance)
    info = InstanceInfo(instance.tags['Name'], instance.id, instance.state, 
                        instance.public_dns_name)
    return info

  def TerminateInstance(self, instance_id):
    instance = self.__GetInstanceById(instance_id)
    assert(instance)
    instance.modify_attribute('disableApiTermination', False)
    self.ec2.terminate_instances([instance_id])
    return

  def StopInstance(self, instance_id):
    instance = self.__GetInstanceById(instance_id)
    assert(instance)
    self.ec2.stop_instances([instance_id])
    return
    
  def StartInstance(self, instance_id):
    instance = self.__GetInstanceById(instance_id)
    if instance.state != 'running':
      instance.start()
    return    

  def CreateInstance(self, workstation_name, instance_type, ubuntu_release_name,
                     mapr_version, ami_release_name, ami_owner_id):
    role = 'workstation'
    ami = core.LookupCirrusAmi(self.ec2, instance_type, ubuntu_release_name,
                               mapr_version, role, ami_release_name, 
                               ami_owner_id)
    if not ami:
      args = [workstation_name, instance_type, ubuntu_release_name,
                     mapr_version, ami_release_name, ami_owner_id]
      raise RuntimeError('Failed to find a suitable ami: %s' % (args))
    self.__CreateWorkstationSecurityGroup() # ensure the security group exists
    # find the IAM Policy Profile
    logging.info( 'Attempting to launch instance with ami: %s' % (ami.id))
    logging.info( 'workstation_profile: %s' % (workstation_profile))
    reservation = self.ec2.run_instances(ami.id,
       key_name = self.workstation_keypair_name,
       security_groups = [core.workstation_security_group],
       instance_type = instance_type,
       #placement = prefered_availability_zone,
       disable_api_termination = True,
       instance_initiated_shutdown_behavior = 'stop',
       instance_profile_name = workstation_profile # IAM instance profile 
       )
    assert(len(reservation.instances) == 1)
    instance = reservation.instances[0]
    instance.add_tag(self.workstation_tag, 'true')
    instance.add_tag('Name', workstation_name) # shown in AWS management console
    core.WaitForInstanceRunning(instance)
    core.WaitForInstanceReachable(instance, self.ssh_key)
    return

  def DeviceExists(self, device_name, instance):
    exists = core.FileExists(device_name, instance.dns_name, self.ssh_key)
    return exists

  def ResizeRootVolumeOfInstance(self, instance_id, new_vol_size_gb):
    # check inputs are valid
    assert(new_vol_size_gb >= 1)
    if new_vol_size_gb > 1000: # probably spending too much if you go bigger
      raise RuntimeError('Adding volumes this large has not been tested.')
    instance = self.__GetInstanceById(instance_id)
    assert(instance)
    # get info about current ebs root volume
    instance.update()
    root_device_name = instance.root_device_name
    if not root_device_name:
      raise RuntimeError('This instance has no root device.')
    logging.info( 'root_device_name: %s' % (root_device_name))
    root_block_map = instance.block_device_mapping[root_device_name]
    assert(root_block_map.volume_id)
    orig_root_volume_id = str(root_block_map.volume_id)
    logging.info( 'orig_root_volume_id: %s' % (orig_root_volume_id))
    orig_root_volume_termination_setting = root_block_map.delete_on_termination
    logging.info( 'orig_root_volume_termination_setting: %s'\
                  % (orig_root_volume_termination_setting))
    vols = self.ec2.get_all_volumes([orig_root_volume_id])
    assert(len(vols) >= 1)
    orig_root_volume = vols[0]
    orig_root_volume_size = orig_root_volume.size
    logging.info( 'orig_root_volume_size: %s' % (orig_root_volume_size))
    orig_root_volume_zone = str(orig_root_volume.zone)
    assert(orig_root_volume_zone)
    logging.info( 'orig_root_volume_zone: %s' % (orig_root_volume_zone))
    assert(instance.root_device_type == 'ebs')
    if new_vol_size_gb < orig_root_volume_size:
      raise RuntimeError('You asked to decrease root vol size.  ' \
        'Only increasing volume size is currently tested and supported.')
    # stop the instance
    # if not stopped, stop the instance
    if core.GetInstanceState(instance) != 'stopped':
      self.ec2.stop_instances([instance_id])
      logging.info( 'stopping instance')
      core.WaitForInstanceStopped(instance)
    logging.info( 'Instance is stopped')
    # if volume not detached, detach it
    if root_block_map.status != 'detached':
      logging.info( 'root_block_map.status: %s' % (root_block_map.status))
      logging.info( 'detaching root volume')
      self.ec2.detach_volume(orig_root_volume_id, instance_id, 
                             root_device_name)
      core.WaitForVolumeAvailable(orig_root_volume)
    logging.info( 'Root volume is detached')
    # Create a snapshot
    name =   'temporary snapshot of root vol for resize'
    snapshot = self.ec2.create_snapshot(orig_root_volume_id, name)
    core.WaitForSnapshotCompleted(snapshot)
    # Create a new larger volume from the snapshot
    new_volume = self.ec2.create_volume(new_vol_size_gb, 
                                        orig_root_volume_zone,
                                        snapshot = snapshot)
    core.WaitForVolumeAvailable(new_volume)
    # Attach the new volume as the root device
    new_volume.attach(instance_id, '/dev/sda1')
    core.WaitForVolumeAttached(new_volume)
    snapshot.delete()
    self.ec2.delete_volume(orig_root_volume_id)
    dot_value = 'false'
    if orig_root_volume_termination_setting:
      dot_value = 'true'
    # restore the del on terminate property
    params = {'InstanceId' : instance.id,
              'BlockDeviceMapping.1.DeviceName' : '/dev/sda1',
              'BlockDeviceMapping.1.Ebs.VolumeId' : new_volume.id,
              'BlockDeviceMapping.1.Ebs.DeleteOnTermination' : dot_value}
    instance.connection.get_status('ModifyInstanceAttribute', params, verb='POST')
    instance.update()
    return

  def AddNewVolumeToInstance(self, instance_id, vol_size_gb):
    """ Returns the volume id added... mount point is /mnt/vol-<id>/. """
    assert(vol_size_gb >= 1)
    if vol_size_gb > 1000: # probably spending too much if you go bigger
      raise RuntimeError('Adding volumes this large has not been tested.')
    instance = self.__GetInstanceById(instance_id)
    assert(instance)
    # select an unused device
    # see http://askubuntu.com/questions/47617/
    # how-to-attach-new-ebs-volume-to-ubuntu-machine-on-aws
    potential_device_names = ['/dev/xvdf',
                              '/dev/xvdg',
                              '/dev/xvdh', 
                              '/dev/xvdi']
    device_name = None
    for name in potential_device_names:
      if not self.DeviceExists(name, instance):
        device_name = name
        break
    if not device_name:
      raise RuntimeError('No suitable device names available')
    # Attach volume
    volume = self.ec2.create_volume(vol_size_gb, instance.placement)
    volume.attach(instance.id, device_name)
    # wait for volume to attach
    core.WaitForVolumeAttached(volume)
    while not self.DeviceExists(device_name, instance):
        logging.info( 'waiting for device to be attached...')
        time.sleep(5)
    assert(volume.id)
    assert(volume.attach_data.device == device_name)
    # format file system, mount the file system, update fstab to automount
    hostname = instance.dns_name
    add_ebs_volume_playbook = pkg_resources.resource_filename(__name__,
      'ami/playbooks/workstation/add_ebs_volume.yml')
    extra_vars = {}
    extra_vars['volume_name'] = volume.id
    extra_vars['volume_device'] = device_name
    assert(core.RunPlaybookOnHost(add_ebs_volume_playbook, hostname, 
                                  self.ssh_key, extra_vars))      
    return volume.id

  def CreateRemoteSessionConfig(self, instance_id):
    instance = self.__GetInstanceById(instance_id)
    if instance.state != 'running':
      instance.start()
      core.WaitForInstanceRunning(instance)
      core.WaitForHostsReachable([instance.public_dns_name], self.ssh_key)
    nx_key = core.ReadRemoteFile('/usr/NX/share/keys/default.id_dsa.key',
                                  instance.public_dns_name, self.ssh_key)
    assert(nx_key)
    assert(instance.state == 'running')
    nx_scrambled_password = password.ScrambleString(core.default_workstation_password)
    params = {'public_dns_name' : instance.public_dns_name,
              'nx_key' : nx_key,
              'nx_scrambled_password' : nx_scrambled_password,
              }
    config_content = string.Template(GetNxsTemplate()).substitute(params)
    # TODO(heathkh): Once this operation is performed at ami creatio ntime, 
    # this shouldn't be needed at login time
    rm_nx_known_hosts = 'sudo rm /usr/NX/home/nx/.ssh/known_hosts'
    core.RunCommandOnHost(rm_nx_known_hosts, instance.public_dns_name, 
                          self.ssh_key)
    return config_content

  def __GetInstanceById(self, instance_id):
    instances = self.__GetInstances()
    desired_instance = None
    for instance in instances:
      if instance.id == instance_id:
        desired_instance = instance
        break
    return desired_instance

  def __GetInstances(self, group_name = None, state_filter=None):
    """
    Get all the instances in a group, filtered by state.

    @param group_name: the name of the group
    @param state_filter: the state that the instance should be in
      (e.g. "running"), or None for all states
    """
    all_instances = self.ec2.get_all_instances()
    instances = []
    for res in all_instances:
      for group in res.groups:
        if group_name and group.name != group_name:
          continue
        for instance in res.instances:
          if state_filter == None or instance.state == state_filter:
            instances.append(instance)
    return instances

  def __CreateWorkstationSecurityGroup(self):
    group_name = core.workstation_security_group
    group = None
    try:
      groups = self.ec2.get_all_security_groups([group_name])
      assert(len(groups) == 1)
      group = groups[0]
    except:
      pass
    if not group:
      group_desc = 'Group for development workstations'
      group = self.ec2.create_security_group(group_name, group_desc)
      # allow ssh connection to this group from anywhere
      group.authorize('tcp', 22, 22, '0.0.0.0/0')
    return

 
#   def LaunchSpotFromSnapshot(self, snapshot_id):
#     name = 'clone of %s' % (snapshot_id)
#     description = name
#     root_device_name = '/dev/sda1'
#     block_device_map = BlockDeviceMapping()
#     bdt = BlockDeviceType(snapshot_id=snapshot_id, 
#                           delete_on_termination=False)
#     block_device_map[root_device_name] = bdt
#     architecture = 'x86_64'
#     kernel_id = 'aki-9ba0f1de'
#     new_ami_id = self.ec2.register_image(name=name, description=description,
#                                          architecture=architecture, 
#                                          kernel_id=kernel_id, 
#                                          block_device_map=block_device_map, 
#                                          root_device_name=root_device_name )
#     price = 0.5
#     role = 'test-cluster'
#     instance_type = 'c1.xlarge'
#     availability_zone = self.ec2_region_name + 'a'
#     private_key_name = 'west_kp1'
#     group_names = ['test-cluster']
#     security_groups = self.ec2.get_all_security_groups(groupnames=group_names)
#     spot_instances = self._LaunchSpotInstances(price, security_groups, 
#                                                new_ami_id, kernel_id, 
#                                                instance_type, 
#                                                availability_zone,
#                                                private_key_name)
#     new_instance = spot_instances[0]
#     self.LaunchRemoteSession(new_instance.id)
#     return
# 
# 
#   def _LaunchSpotInstances(self, price, security_groups, image_id, kernel_id,
#                            instance_type, availability_zone, 
#                            private_key_name):
#     spot_instance_request_ids = []
#     spot_request = self.ec2.request_spot_instances(price=price,
#       image_id=image_id,
#       count=1,
#       type='one-time',
#       valid_from=None,
#       valid_until=None,
#       launch_group=None, #'maprcluster-spotstartgroup',
#       availability_zone_group=None, #availability_zone,
#       key_name=private_key_name,
#       security_groups=security_groups,
#       user_data=None,
#       instance_type=instance_type,
#       placement=availability_zone)
#     spot_instance_request_ids.extend([request.id for request in spot_request])
#     instances = self._WaitForSpotInstances(spot_instance_request_ids)
#     return instances
# 
#   def _WaitForSpotInstances(self, request_ids, timeout=1200):
#     start_time = time.time()
#     instance_id_set = set()
#     print 'waiting for spot requests to be fulfilled'
#     while True:
#       for request in self.ec2.get_all_spot_instance_requests(request_ids):
#         #print request
#         #print dir(request)
#         if request.instance_id:
#           print 'request.instance_id %s' % request.instance_id
#           instance_id_set.add(request.instance_id)
#       num_fulfilled = len(instance_id_set)
#       num_requested = len(request_ids)
# 
#       if num_fulfilled == num_requested:
#         break
# 
#       print 'fulfilled %d of %d' % (num_fulfilled, num_requested)
#       time.sleep(15)
# 
#     instance_ids = [id for id in instance_id_set]
# 
#     time.sleep(5)
#     print 'waiting for spot instances to start'
#     while True:
# 
#       try:
#         if NonePending(self.ec2.get_all_instances(instance_ids)):
#           break
#        # don't timeout for race condition where instance is not yet registered
#       except EC2ResponseError as e:
#         print e
# 
# 
#       instances = None
#       try:
#         instances = self.ec2.get_all_instances(instance_ids)
#        # don't timeout for race condition where instance is not yet registered
#       except EC2ResponseError as e:
#         print e
#         continue
# 
#       num_started = NumberInstancesInState(instances, "running")
#       num_pending = NumberInstancesInState(instances, "pending")
#       print 'started: %d pending: %d' % (num_started, num_pending)
# 
#       time.sleep(15)
# 
#     instances = []
#     for reservation in self.ec2.get_all_instances(instance_ids):
#       for instance in reservation.instances:
#         instances.append(instance)
#     return instances



def GetNxsTemplate():
    template = """
    <!DOCTYPE NXClientSettings>
  <NXClientSettings application="nxclient" version="1.3" >
  <group name="Advanced" >
  <option key="Cache size" value="128" />
  <option key="Cache size on disk" value="256" />
  <option key="Current keyboard" value="true" />
  <option key="Custom keyboard layout" value="" />
  <option key="Disable DirectDraw" value="false" />
  <option key="Disable ZLIB stream compression" value="false" />
  <option key="Disable deferred updates" value="false" />
  <option key="Enable HTTP proxy" value="false" />
  <option key="Enable SSL encryption" value="true" />
  <option key="Enable response time optimisations" value="false" />
  <option key="Grab keyboard" value="false" />
  <option key="HTTP proxy host" value="" />
  <option key="HTTP proxy port" value="8080" />
  <option key="HTTP proxy username" value="" />
  <option key="Remember HTTP proxy password" value="false" />
  <option key="Restore cache" value="true" />
  <option key="StreamCompression" value="" />
  </group>
  <group name="Environment" >
  <option key="CUPSD path" value="/usr/sbin/cupsd" />
  </group>
  <group name="General">
  <option key="Automatic reconnect" value="true" />
  <option key="Command line" value="" />
  <option key="Custom Unix Desktop" value="application" />
  <option key="Desktop" value="gnome" />
  <option key="Disable SHM" value="false" />
  <option key="Disable emulate shared pixmaps" value="false" />
  <option key="Link speed" value="adsl" />
  <option key="Remember password" value="true" />
  <option key="Resolution" value="available" />
  <option key="Resolution height" value="600" />
  <option key="Resolution width" value="800" />
  <option key="Server host" value="${public_dns_name}" />
  <option key="Server port" value="22" />
  <option key="Session" value="unix" />
  <option key="Spread over monitors" value="false" />
  <option key="Use default image encoding" value="0" />
  <option key="Use render" value="true" />
  <option key="Use taint" value="true" />
  <option key="Virtual desktop" value="false" />
  <option key="XAgent encoding" value="true" />
  <option key="displaySaveOnExit" value="false" />
  <option key="xdm broadcast port" value="177" />
  <option key="xdm list host" value="localhost" />
  <option key="xdm list port" value="177" />
  <option key="xdm mode" value="server decide" />
  <option key="xdm query host" value="localhost" />
  <option key="xdm query port" value="177" />
  </group>
  <group name="Images" >
  <option key="Disable JPEG Compression" value="0" />
  <option key="Disable all image optimisations" value="false" />
  <option key="Disable backingstore" value="false" />
  <option key="Disable composite" value="false" />
  <option key="Image Compression Type" value="3" />
  <option key="Image Encoding Type" value="0" />
  <option key="Image JPEG Encoding" value="false" />
  <option key="JPEG Quality" value="6" />
  <option key="RDP Image Encoding" value="3" />
  <option key="RDP JPEG Quality" value="6" />
  <option key="RDP optimization for low-bandwidth link" value="false" />
  <option key="Reduce colors to" value="" />
  <option key="Use PNG Compression" value="true" />
  <option key="VNC JPEG Quality" value="6" />
  <option key="VNC images compression" value="3" />
  </group>
  <group name="Login" >
  <option key="Auth" value="${nx_scrambled_password}" />
  <option key="User" value="ubuntu" />
  <option key="Guest Mode" value="false" />
  <option key="Guest password" value="" />
  <option key="Guest username" value="" />
  <option key="Public Key" value="${nx_key}" />
  <option key="Login Method" value="nx" />
  </group>
  <group name="Services" >
  <option key="Audio" value="false" />
  <option key="IPPPort" value="631" />
  <option key="IPPPrinting" value="false" />
  <option key="Shares" value="false" />
  </group>
  <group name="VNC Session" >
  <option key="Display" value="0" />
  <option key="Remember" value="false" />
  <option key="Server" value="" />
  </group>
  <group name="Windows Session" >
  <option key="Application" value="" />
  <option key="Authentication" value="2" />
  <option key="Color Depth" value="8" />
  <option key="Domain" value="" />
  <option key="Image Cache" value="true" />
  <option key="Password" value="EMPTY_PASSWORD" />
  <option key="Remember" value="true" />
  <option key="Run application" value="false" />
  <option key="Server" value="" />
  <option key="User" value="" />
  </group>
  <group name="share chosen" >
  <option key="Share number" value="0" />
  </group>
  </NXClientSettings>
  """
    return template
