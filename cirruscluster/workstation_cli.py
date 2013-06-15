#!/env/bin/python
""" Command Line Tool for connecting and managing remote Cirrus workstations."""
from cirruscluster import core
from cirruscluster import workstation
import ConfigParser
import os
import sys

class Cli(object):
  """ CLI for operations on Cirrus workstations."""
  def __init__(self):
    self.region = None
    self.aws_id = None
    self.aws_secret = None
    self.instance_type = None
    self.ubuntu_release_name = None
    self.mapr_version = None
    self.config_filename = os.path.expanduser('~/.cirrus-workstation')
    self._LoadConfigFile()
    if not workstation.IAMUserReady(self.aws_id, self.aws_secret):
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
    while not self.region:
      print 'No region has been configured'
      print 'Please select one: %s' % (core.tested_region_names)
      region = raw_input('AWS Region: ')
      while region not in core.tested_region_names:
        print 'Invalid region: %s' % (region)
      self.region = region
    self.__SaveConfigFile()
    if not workstation.IAMUserReady(self.aws_id, self.aws_secret):
      raise RuntimeError('Invalid credentials. Please delete configuration' \
                         ' here: %s' % (self.config_filename))
    self.manager = workstation.Manager(self.region, self.aws_id, self.aws_secret)
    return

  def ListWorkstations(self):
    self.manager.ListInstances()
    return

  def ConnectToWorkstation(self):
    self.manager.ListInstances()
    instance_id = raw_input('Instance id would you like to connect to: ')
    config_content = self.manager.CreateRemoteSessionConfig(instance_id)
    config_filename = '/tmp/%s.nxs' % instance_id
    config_file = open(config_filename, 'w')
    config_file.write(config_content)
    config_file.close()
    cmd = 'nxclient --session %s' % config_filename
    core.ExecuteCmd(cmd)
    return

  def StopWorkstation(self):
    self.manager.ListInstances()
    instance_id = raw_input('Which instance id would you like to stop: ')
    self.manager.StopInstance(instance_id)
    return

  def DestroyWorkstation(self):
    self.manager.ListInstances()
    instance_id = raw_input('Which instance id would you like to destroy: ')
    confirm = raw_input('If you are sure, enter "yes": ')
    if confirm == 'yes':
      self.manager.TerminateInstance(instance_id)
    return

  def CreateWorkstation(self):
    workstation_name = raw_input('Unique name to give new workstation: ')
    self.manager.CreateInstance(workstation_name, self.instance_type,
                                self.ubuntu_release_name, self.mapr_version)
    return

  def ResizeWorkstationRootVolume(self):
    self.manager.ListInstances()
    instance_id = raw_input('Which instance id would you like to modify: ')
    vol_size_gb = long(raw_input('Size for resized volume (in GB): '))
    self.manager.ResizeRootVolumeOfInstance(instance_id, vol_size_gb)
    return

  def AddVolumeToWorkstation(self):
    self.manager.ListInstances()
    instance_id = raw_input('To which instance gets the new volume: ')
    vol_size_gb = long(raw_input('Desired size for new volume (in GB): '))
    self.manager.AddNewVolumeToInstance(instance_id, vol_size_gb)
    return

  def _LoadConfigFile(self):
    config = ConfigParser.RawConfigParser()
    config.read(self.config_filename)
    try:
      sec = 'credentials'
      self.aws_id = config.get(sec, 'aws_id')
      self.aws_secret = config.get(sec, 'aws_secret')
      sec = 'defaults'
      self.region = config.get(sec, 'region')
      self.instance_type = config.get(sec, 'instance_type')
      self.ubuntu_release_name = config.get(sec, 'ubuntu_release_name')
      self.mapr_version = config.get(sec, 'mapr_version')

      # configure defaults
      self.instance_type = 'c1.xlarge'
      self.ubuntu_release_name = 'precise'
      self.mapr_version = 'v2.1.3'
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
    f = open(self.config_filename, 'wb')
    config.write(f)
    return

  def __Debug(self):
    res = self.manager.Debug()
    return

def main():
  cli = Cli()
  if (len(sys.argv) < 2):
    print 'Usage: commands are: list, connect, stop, create, add_volume'
    return 1
  cmd = sys.argv[1]
  
  if cmd == 'list':
    cli.ListWorkstations()
  elif cmd == 'connect':
    cli.ConnectToWorkstation()
  elif cmd == 'stop':
    cli.StopWorkstation()
  elif cmd == 'create':
    cli.CreateWorkstation()
  elif cmd == 'add_volume':
    cli.AddVolumeToWorkstation()
  elif cmd == 'resize':
    cli.ResizeWorkstationRootVolume()
  elif cmd == 'destroy':
    cli.DestroyWorkstation()
  elif cmd == 'debug':
    cli.Debug()
  else:
      print 'unknown operation requested: ' + cmd
  return

if __name__ == "__main__":
    main()
