#!/env/bin/python
""" Command Line Tool for connecting and managing remote Cirrus workstations."""
from cirruscluster import core
from cirruscluster import workstation
import ConfigParser
import os
import sys
import platform
import tempfile
import logging

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)

def PrintInstances(manager):
  for instance in manager.ListInstances():
    print 'id: %s name: %s state: %s host: %s' % (instance.id, instance.name, instance.state, instance.hostname)
  return
  

class Cli(object):
  """ CLI for operations on Cirrus workstations."""
  def __init__(self):
    self.aws_id = None
    self.aws_secret = None
    self.region = 'us-east-1'
    self.instance_type = 'c1.xlarge'
    self.ubuntu_release_name = 'precise'
    self.mapr_version = 'v2.1.3'
    self.ami_release_name = core.default_ami_release_name
    self.ami_owner_id = core.default_ami_owner_id
    self.config_filename = os.path.expanduser('~/.cirrus-workstation')    
    self._LoadConfigFile()
    
    if not self.ami_owner_id:
      self.ami_owner_id = core.default_ami_owner_id
    
    while self.region not in core.tested_region_names:
      print 'Valid regions are: %s' % (core.tested_region_names)
      region = raw_input('Which AWS Region do you want to use: ')
      if region not in core.tested_region_names:
        print 'Invalid region: %s' % (region)
      self.region = region
    
    self.manager = None
    while not self.manager:
      try:
        self.manager = workstation.Manager(self.region, self.aws_id,
                                           self.aws_secret)
        break
      except workstation.InvalidAwsCredentials:
        # try to get root AWS account from AWS default environment variables
        root_aws_id = os.environ.get('AWS_ACCESS_KEY_ID')
        root_aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
        # otherwise, ask the user directly
        while not root_aws_id or not root_aws_secret:
          print 'No IAM user configured, please provide your' \
                ' AWS key id and secret.'
          root_aws_id = raw_input('ROOT aws key id: ')
          root_aws_secret = raw_input('ROOT aws key secret: ')
        iam_user = workstation.InitCirrusIAMUser(root_aws_id, root_aws_secret)
        self.aws_id, self.aws_secret = iam_user
      except:
        raise
    self.__SaveConfigFile()
    return

  def ListWorkstations(self):
    PrintInstances(self.manager)
    return

  def ConnectToWorkstation(self):
    PrintInstances(self.manager)
    instance_id = raw_input('Instance id would you like to connect to: ')
    config_content = self.manager.CreateRemoteSessionConfig(instance_id)
    #config_filename = '/tmp/%s.nxs' % instance_id
    #config_file = open(config_filename, 'w')
    
    fd, config_filename = tempfile.mkstemp()
    config_file = os.fdopen(fd, "w")
    config_file.write(config_content)
    config_file.close()
    
    p = platform.system()
    cmd = None
    if p == 'Darwin':
      # Use Mac 'open' command assuming files with extension nxs are registered
      cmd = 'open %s' % config_filename  
    elif p == 'Windows':
      cmd = 'nxclient --session %s' % config_filename  
    elif p == 'Linux':
      cmd = 'nxclient --session %s' % config_filename
    else:
      print 'Command may not work. Unknown platform type: %s' % p
      cmd = 'nxclient --session %s' % config_filename  
    result = core.ExecuteCmd(cmd)
    print result
    if result != 0:
      print 'Could not launch nxclient.'
      print 'Please install it from http://www.nomachine.com'
    return

  def StopWorkstation(self):
    PrintInstances(self.manager)
    instance_id = raw_input('Which instance id would you like to stop: ')
    self.manager.StopInstance(instance_id)
    return
  
  def StartWorkstation(self):
    PrintInstances(self.manager)
    instance_id = raw_input('Which instance id would you like to start: ')
    self.manager.StartInstance(instance_id)
    return

  def DestroyWorkstation(self):
    PrintInstances(self.manager)
    instance_id = raw_input('Which instance id would you like to destroy: ')
    confirm = raw_input('If you are sure, enter "yes": ')
    if confirm == 'yes':
      self.manager.TerminateInstance(instance_id)
    return

  def CreateWorkstation(self):
    workstation_name = raw_input('Unique name to give new workstation: ')
    self.manager.CreateInstance(workstation_name, self.instance_type,
                                self.ubuntu_release_name, self.mapr_version,
                                self.ami_release_name, self.ami_owner_id)
    return

  def ResizeWorkstationRootVolume(self):
    PrintInstances(self.manager)
    instance_id = raw_input('Which instance id would you like to modify: ')
    vol_size_gb = long(raw_input('Size for resized volume (in GB): '))
    self.manager.ResizeRootVolumeOfInstance(instance_id, vol_size_gb)
    return

  def AddVolumeToWorkstation(self):
    PrintInstances(self.manager)
    instance_id = raw_input('To which instance gets the new volume: ')
    vol_size_gb = long(raw_input('Desired size for new volume (in GB): '))
    vol_id = self.manager.AddNewVolumeToInstance(instance_id, vol_size_gb)
    print 'New volume mounted here (on instance %s): /mnt/vol-%s' % \
      (instance_id, vol_id)
    return

  def _LoadConfigFile(self):
    config = ConfigParser.RawConfigParser()
    config.read(self.config_filename)
    sec = 'credentials'
    try:    
      self.aws_id = config.get(sec, 'aws_id')
    except:
      pass
    
    try:
      self.aws_secret = config.get(sec, 'aws_secret')
    except:
      pass
      
    sec = 'defaults'
    try:
      self.region = config.get(sec, 'region')
    except:
      pass
    
    try:
      self.instance_type = config.get(sec, 'instance_type')
    except:
      pass
    
    try:
      self.ubuntu_release_name = config.get(sec, 'ubuntu_release_name')
    except:
      pass
    
    try:
      self.mapr_version = config.get(sec, 'mapr_version')
    except:
      pass
    
    try:
      self.ami_release_name = config.get(sec, 'ami_release_name')
    except:
      pass
    
    try:
      self.ami_owner_id = config.get(sec, 'ami_owner_id')
    except:
      pass   
    
    return

  def __SaveConfigFile(self):
    config = ConfigParser.RawConfigParser()
    sec = 'credentials'
    config.add_section(sec)
    config.set(sec, 'aws_id', self.aws_id)
    config.set(sec, 'aws_secret', self.aws_secret)
    sec = 'defaults'
    config.add_section(sec)
    config.set(sec, 'region', self.region)
    config.set(sec, 'instance_type', self.instance_type)
    config.set(sec, 'ubuntu_release_name', self.ubuntu_release_name)
    config.set(sec, 'mapr_version', self.mapr_version)
    
    config.set(sec, 'ami_release_name', self.ami_release_name)
    config.set(sec, 'ami_owner_id', self.ami_owner_id)    
    
    f = open(self.config_filename, 'wb')
    config.write(f)
    return

  def Debug(self):
    self.manager.Debug()
    return

def main():
  cli = Cli()
  if (len(sys.argv) < 2):
    
    print """Usage:
         list
         connect
         start
         stop
         create
         destroy 
         add_volume
         resize_root
    """
    return 1
  cmd = sys.argv[1]
  
  if cmd == 'list':
    cli.ListWorkstations()
  elif cmd == 'connect':
    cli.ConnectToWorkstation()
  elif cmd == 'start':
    cli.StartWorkstation()
  elif cmd == 'stop':
    cli.StopWorkstation()
  elif cmd == 'create':
    cli.CreateWorkstation()
  elif cmd == 'destroy':
    cli.DestroyWorkstation()
  elif cmd == 'add_volume':
    cli.AddVolumeToWorkstation()
  elif cmd == 'resize_root':
    cli.ResizeWorkstationRootVolume()  
  elif cmd == 'debug':
    cli.Debug()
  else:
      print 'unknown operation requested: ' + cmd
  return

if __name__ == "__main__":
    main()
