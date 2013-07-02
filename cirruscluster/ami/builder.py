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

""" Tools to automate creation of workstation, master, and worker AMIs. """ 
from cirruscluster import core
import logging
import pkg_resources

class AmiSpecification(object):
  """ Parameters of the ami to be created. """
  def __init__(self, ami_release_name, region_name, instance_type, 
               ubuntu_release_name, mapr_version, role, owner_id = 'self'):    
    assert(region_name in ['us-west-1', 'us-east-1'])
    assert(instance_type in ['c1.xlarge', 'cc2.8xlarge'])
    assert(ubuntu_release_name in ['precise'])
    assert(mapr_version in ['v2.1.3'])
    assert(role in ['workstation', 'master', 'worker'])
    self.ami_release_name = ami_release_name
    self.owner_id = owner_id    
    self.region_name = region_name
    self.instance_type = instance_type
    self.ubuntu_release_name = ubuntu_release_name
    self.mapr_version = mapr_version
    self.role = role        
    self.root_store_type, self.virtualization_type = \
      core.GetRootStoreAndVirtualizationType(self.instance_type)
    # Currently only have tools to create ebs backed amis... 
    self.root_store_type = 'ebs'
    self.ami_name = core.AmiName(ami_release_name, ubuntu_release_name, 
                                    self.virtualization_type, self.mapr_version,
                                    self.role)
    return
  
def GetAmi(ec2, ami_spec):
    """ Get the boto ami object given a AmiSpecification object. """ 
    images = ec2.get_all_images(owners=[ami_spec.owner_id] )
    requested_image = None
    for image in images:
      if image.name == ami_spec.ami_name:
        requested_image = image
        break
    return requested_image

class AmiBuilder(object):  
  """ Creates an ubuntu ami pre-configured for different cirrus roles. """  
  def __init__(self, ec2, ami_spec, key_pair_name, ssh_key):
    self.ec2 = ec2
    self.ami_spec = ami_spec
    self.key_pair = ec2.get_key_pair(key_pair_name)
    self.ssh_key = ssh_key
    
    # Fail if an image matching this spec already exists
    if GetAmi(self.ec2, self.ami_spec):
      ami_webui_url = 'https://console.aws.amazon.com/ec2/home?' \
                      'region=%s#s=Images' % self.ami_spec.region_name     
      raise RuntimeError('An AMI for this role already exists.  Please manually'
                         ' delete it here: %s' % ami_webui_url)      
    return
  
  def Run(self):
    """ Build the Amazon Machine Image. """
    template_instance = None
    res = self.ec2.get_all_instances( \
            filters={'tag-key': 'spec', 
                     'tag-value' : self.ami_spec.ami_name,
                     'instance-state-name' : 'running'})    
    if res:
      running_template_instances = res[0].instances
      if running_template_instances:
        assert(len(running_template_instances) == 1)
        template_instance = running_template_instances[0]    
    # if there is not a currently running template instance, start one
    if not template_instance:
      template_instance = self.__CreateTemplateInstance()
      template_instance.add_tag('spec', self.ami_spec.ami_name)
    assert(template_instance)  
    if self.ami_spec.role == 'workstation':
      self.__ConfigureAsWorkstation(template_instance)
    elif self.ami_spec.role == 'master':
      self.__ConfigureAsClusterMaster(template_instance)
    elif self.ami_spec.role == 'worker':
      self.__ConfigureAsClusterWorker(template_instance)
    else: 
      raise RuntimeError('unknown role: %s' % (self.ami_spec.role))        
    
    
    
    print 'Please login and perform any custom manipulations before '\
          'snapshot is made!'
    
    raw_input('Press any key to shutdown and begin creating AMI. '\
              '(or ctrl-c to quit and re-run config process).')
    
    self.__SecurityScrub(template_instance)
    
    ami_id = None
    if self.ami_spec.root_store_type == 'ebs':  
      ami_id = self.__CreateEbsAmi(template_instance)
    else:
      logging.info('Support for creating instance-store backed images has been'
                   ' disabled in this version because it required much greater'
                   ' complexity.')
      ami_id = self.__CreateEbsAmi(template_instance)
    
    logging.info('ami id: %s' % (ami_id))
    # TODO(heathkh): implement these features...
    
    #self.__SetImagePermissions(ami_id)
    #self.__DistributeImageToAllRegions(ami_id)
      
    print 'terminating template instance'
    self.ec2.terminate_instances(instance_ids=[template_instance.id])
    core.WaitForInstanceTerminated(template_instance)    
    return
  
  def GetInstanceById(self, instance_id):
    reservations = self.ec2.get_all_instances([instance_id])  
    instance = None
    for r in reservations:
       for i in r.instances:         
         if i.id == instance_id:
           instance = i
           break
    return instance
  
  def __CreateTemplateInstance(self):     
    template_image = self.__GetTemplateImage()
    self.__CreateSshSecurityGroup()    
    reservation = template_image.run(key_name=self.key_pair.name, 
                                     security_groups=['ssh'], 
                                     instance_type=self.ami_spec.instance_type)
    instance = reservation.instances[0]
    core.WaitForInstanceRunning(instance)    
    core.WaitForHostsReachable([instance.public_dns_name], self.ssh_key)    
    return instance
  
  def __ConfigureAsWorkstation(self, instance):
    logging.info('Configuring a workstation...')
    playbook = pkg_resources.resource_filename(__name__, 
      'playbooks/workstation/workstation.yml')
    extra_vars = {'mapr_version' : self.ami_spec.mapr_version,
                  'ubuntu_password': core.default_workstation_password}
    assert(core.RunPlaybookOnHost(playbook, instance.dns_name, self.ssh_key, 
                                  extra_vars = extra_vars))
    
    dsa_key = '/usr/NX/share/keys/default.id_dsa.key'
    nx_client_ssh_key = core.ReadRemoteFile(dsa_key, instance.dns_name, 
                                            self.ssh_key)    
    print 'To connect with NX Client, you must paste this key into the gui '\
          'advanced settings config.'
    print nx_client_ssh_key
    return
  
  def __ConfigureAsClusterMaster(self, instance):
    logging.info('Configuring a cluster master...')
    #playbook = os.path.dirname(__file__) + '/templates/cluster/master.yml'
    playbook = pkg_resources.resource_filename(__name__,
                                               'playbooks/cluster/master.yml')
    extra_vars = {'mapr_version' : self.ami_spec.mapr_version,
                  'is_master' : True}
    assert(core.RunPlaybookOnHost(playbook, instance.dns_name, self.ssh_key, 
                                  extra_vars = extra_vars))
    return
  
  def __ConfigureAsClusterWorker(self, instance):
    logging.info('Configuring a cluster worker...')
    #playbook = os.path.dirname(__file__) + '/templates/cluster/worker.yml'
    playbook = pkg_resources.resource_filename(__name__,
                                               'playbooks/cluster/worker.yml')
    extra_vars = {'mapr_version' : self.ami_spec.mapr_version}
    assert(core.RunPlaybookOnHost(playbook, instance.dns_name, self.ssh_key, 
                                  extra_vars = extra_vars))
    return
   
  def __SecurityScrub(self, instance):
    
    # ensure no cirrus keys directory remains (workstation)
    cmd = 'sudo rm -rf /home/ubuntu/.ec2'
    assert(core.RunCommandOnHost(cmd, instance.dns_name, self.ssh_key))
    
    # delete the shell history 
    cmd = 'sudo find /root/.*history /home/*/.*history -exec rm -f {} \\;'
    assert(core.RunCommandOnHost(cmd, instance.dns_name, self.ssh_key))
    # Clear cache of known hosts, otherwise first login fails
    cmd = 'sudo rm /usr/NX/home/nx/.ssh/known_hosts'
    core.RunCommandOnHost(cmd, instance.dns_name, self.ssh_key)
    # Only run this right before you create the ami
    # After you do this, you can't make a new connection via shared key auth
    cmd = 'sudo find / -name "authorized_keys" -exec rm -f {} \\;'
    assert(core.RunCommandOnHost(cmd, instance.dns_name, self.ssh_key))
    return
     
  def __CreateEbsAmi(self, instance):    
    # details here: 
    #http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/creating-an-ami-ebs.html
    # step 1: stop the instance so it is in a consistent state
    self.ec2.stop_instances(instance_ids=[instance.id])
    # wait till stopped
    core.WaitForInstanceStopped(instance)
    logging.info('instance stopped...'
                 ' ready to create image: %s' % (instance.id))
    ami_description = self.ami_spec.ami_name
    new_ami_id = self.ec2.create_image(instance.id, self.ami_spec.ami_name, 
                                       ami_description)
    logging.info('new ami: %s' % (new_ami_id))
    return new_ami_id
  
  def __SetImagePermissions(self, ami_id):
    new_images = self.ec2.get_all_images(image_ids=[ami_id])
    assert(len(new_images) == 1)
    new_image = new_images[0]    
    new_image.set_launch_permissions(group_names=['all'])
    return    
      
  def __CreateSshSecurityGroup(self):
    ssh_group = None
    try:      
      groups = self.ec2.get_all_security_groups(['ssh'])
      ssh_group = groups[0]
    except:
      pass
      
    if not ssh_group:          
      ssh_group = self.ec2.create_security_group('ssh', 'Our ssh group')
      ssh_group.authorize('tcp', 22, 22, '0.0.0.0/0')    
    return
     
  def __GetTemplateImage(self):
    template_ami_id = core.SearchUbuntuAmiDatabase(
      self.ami_spec.ubuntu_release_name, self.ami_spec.region_name, 
      self.ami_spec.root_store_type, self.ami_spec.virtualization_type)
    template_images = self.ec2.get_all_images([template_ami_id])
    if (len(template_images) != 1):
      raise RuntimeError('Can\'t find image: %s' % (template_images))
    template_image = template_images[0]      
    return template_image
   
  
  

  

                         