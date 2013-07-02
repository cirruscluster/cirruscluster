from Crypto.PublicKey import RSA
from Crypto import Random
from boto import ec2 as boto_ec2
from boto import exception as boto_exception
from boto.s3.key import Key
from boto.ec2 import connection as ec2_connection
from boto.iam import connection as iam_connection 
from boto.s3 import connection as s3_connection
from cirruscluster.ext import ansible
from cirruscluster.ext.ansible import callbacks
from cirruscluster.ext.ansible import inventory as ansible_inventory
from cirruscluster.ext.ansible import playbook
from cirruscluster.ext.ansible import runner
import StringIO
import base64
import logging
import math
import multiprocessing
import os
import paramiko
import socket
import subprocess
import sys
import time
import urllib2

################################################################################
# Cirrus global parameters
################################################################################
tested_region_names = ['us-east-1', 'us-west-1']
valid_instance_roles = ['workstation', 'master', 'worker']
valid_virtualization_types = ['paravirtual', 'hvm']
hpc_instance_types = ['cc1.4xlarge', 'cc2.8xlarge', 'cr1.8xlarge']
workstation_security_group = 'cirrus_workstation'
default_workstation_password = 'cirrus_workstation'

# Users are encouraged to fork cirrus and publish their own amis.
# Using a github style mode, user-published sets of amis can be used by others
# by the unique identifer: <ami_owner_id>/<ami_release_name>
default_ami_owner_id = '925479793144'
default_ami_release_name = 'latest'


##############################################################################
# Decorator
##############################################################################

# Retry decorator with exponential backoff
def RetryUntilReturnsTrue(tries, delay=2, backoff=1.5):
  '''Retries a function or method until it returns True.

  delay sets the initial delay in seconds, and backoff sets the factor by which
  the delay should lengthen after each failure. backoff must be greater than 1,
  or else it isn't really a backoff. tries must be at least 0, and delay
  greater than 0.'''

  if backoff <= 1:
    raise ValueError("backoff must be greater than 1")

  tries = math.floor(tries)
  if tries < 0:
    raise ValueError("tries must be 0 or greater")

  if delay <= 0:
    raise ValueError("delay must be greater than 0")

  def deco_retry(f):
    def f_retry(*args, **kwargs):
      mtries, mdelay = tries, delay # make mutable

      rv = f(*args, **kwargs) # first attempt
      while mtries > 0:
        if rv: # Done on success
          return rv

        mtries -= 1      # consume an attempt
        time.sleep(mdelay) # wait...
        mdelay *= backoff  # make future wait longer
       
        rv = f(*args, **kwargs) # Try again

      return False # Ran out of tries :-(

    return f_retry # true decorator -> decorated function
  return deco_retry  # @retry(arg[, ...]) -> true decorator

################################################################################
# Ansible helper functions
################################################################################
def GetNumCoresOnHosts(hosts, private_key):
  """ Returns list of the number of cores for each host requested in hosts. """
  results = runner.Runner(host_list=hosts, private_key=private_key,
                          module_name='setup').run()
  num_cores_list = []
  for _, props in results['contacted'].iteritems():
    cores = props['ansible_facts']['ansible_processor_cores']
    val = 0
    try:
      val = int(cores)
    except ValueError:
      pass
    num_cores_list.append(val)
  return num_cores_list

def RunPlaybookOnHosts(playbook_path, hosts, private_key, extra_vars=None):
  """ Runs the playbook and returns True if it completes successfully on all
  hosts. """
  inventory = ansible_inventory.Inventory(hosts)
  if not inventory.list_hosts():
    raise RuntimeError("Host list is empty.")
  stats = callbacks.AggregateStats()
  verbose = 0
  playbook_cb = ansible.callbacks.PlaybookCallbacks(verbose=verbose)
  runner_cb = ansible.callbacks.PlaybookRunnerCallbacks(stats, verbose=verbose)
  pb = playbook.PlayBook(playbook=playbook_path,
                                  host_list=hosts,
                                  remote_user='ubuntu',
                                  private_key_file=None,
                                  private_key=private_key,
                                  stats=stats,
                                  callbacks=playbook_cb,
                                  runner_callbacks=runner_cb,
                                  extra_vars=extra_vars)
  results = pb.run()
  # Check if all hosts completed playbook without error
  success = True
  if 'dark' in results:
    if len(results['dark']) > 0:
      print "Contact failures:"
      for host, reason in results['dark'].iteritems():
        print "  %s (%s)" % (host, reason['msg'])
      success = False
  for host, status in results.iteritems():
      if host == 'dark':
        continue
      failures = status['failures']
      if failures:
        logging.info( '%s %s' % (host, status))
        success = False
  return success

def RunPlaybookOnHost(playbook_path, host, private_key, extra_vars=None):
  """ 
  Runs the playbook and returns True if it completes successfully on 
  a single host.
  """
  return RunPlaybookOnHosts(playbook_path, [host], private_key, extra_vars)

################################################################################
# Local execution helpers
################################################################################

def ExecuteCmd(cmd, quiet=False):
  """ Run a command in a shell. """
  result = None
  if quiet:
    with open(os.devnull, "w") as fnull:
      result = subprocess.call(cmd, shell=True, stdout=fnull, stderr=fnull)
  else:
    result = subprocess.call(cmd, shell=True)
  return result

def CheckOutput(*popenargs, **kwargs):
  """
  Run command with arguments and return its output as a byte string.
  Backported from Python 2.7 as it's implemented as pure python on stdlib.
  """
  process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
  output, _ = process.communicate()
  retcode = process.poll()
  if retcode:
      cmd = kwargs.get("args")
      if cmd is None:
          cmd = popenargs[0]
      error = subprocess.CalledProcessError(retcode, cmd)
      error.output = output
      raise error
  return retcode, output

def UrlGet(url, timeout=10, retries=0):
  """ Retrieve content from the given URL. """
   # in Python 2.6 we can pass timeout to urllib2.urlopen
  socket.setdefaulttimeout(timeout)
  attempts = 0
  content = None
  while not content:
      try:
          content = urllib2.urlopen(url).read()
      except urllib2.URLError:
          attempts = attempts + 1
          if attempts > retries:
              raise IOError('Failed to fetch url: %s' % url)
  return content

################################################################################
# Remote execution helpers
################################################################################

def RunCommandOnHosts(cmd, hostnames, ssh_key):
  """ Executes a command via ssh and sends back the exit status code. """
  if not hostnames:
    return
  p = multiprocessing.Pool(1)
  remote_command_args = [(cmd, hostname, ssh_key) for hostname in hostnames]
  #print remote_command_args
  result = None
  while not result:
    try:    
      result = p.map_async(__RemoteExecuteHelper, remote_command_args).get(999999) # allows for keyboard interrupt
    except paramiko.SSHException as e:      
      logging.info( 'failure in RunCommandOnHosts: %s' % (e))
      time.sleep(5)
    
  p.close()
  p.join()
  return result

def RunCommandOnHost(cmd, hostname, ssh_key):
  """ Executes a command via ssh and sends back the exit status code. """
  hostnames = [hostname]
  results = RunCommandOnHosts(cmd, hostnames, ssh_key)
  assert(len(results) == 1)
  return results[0]

def ReadRemoteFile(remote_file_path, hostname, ssh_key):
  """ Reads a remote file into a string. """
  cmd = 'sudo cat %s' % remote_file_path
  exit_code, output = RunCommandOnHost(cmd, hostname, ssh_key)
  if exit_code:
    raise IOError('Can not read remote path: %s' % (remote_file_path))
  return output

def FileExists(remote_file_path, hostname, ssh_key):
  cmd = 'ls %s' % remote_file_path
  exit_code, _ = RunCommandOnHost(cmd, hostname, ssh_key)
  exists = (exit_code == 0)
  return exists  


def __RemoteExecuteHelper(args):
  """ Helper for multiprocessing. """
  cmd, hostname, ssh_key = args
  #Random.atfork()  # needed to fix bug in old python 2.6 interpreters
  private_key = paramiko.RSAKey.from_private_key(StringIO.StringIO(ssh_key))
  client = paramiko.SSHClient()
  client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
  while True:
      try:
          client.connect(hostname, username='ubuntu', pkey=private_key, 
                         allow_agent=False, look_for_keys=False)
          break
      except socket.error as e:
          print '.'
          time.sleep(5)
      except paramiko.AuthenticationException as e:
          print e
          time.sleep(5)
  channel = client.get_transport().open_session()
  channel.exec_command(cmd)
  exit_code = channel.recv_exit_status()
  output = channel.recv(1000000)
  client.close()
  return exit_code, output

################################################################################
# Host reachable tests
################################################################################

def WaitForInstanceReachable(instance, ssh_key):  
  if not instance:
    raise RuntimeError('No instance provided.')
  hostname = instance.dns_name
  while True:
    unreachable = GetUnreachableHosts([hostname], ssh_key)
    if unreachable:
      print 'waiting for unreachable hosts: %s' % unreachable
      time.sleep(5)
    else:
      break
  return

def WaitForHostsReachable(hostnames, ssh_key):
  """ Blocks until host is reachable via ssh. """
  while True:
    unreachable = GetUnreachableHosts(hostnames, ssh_key)
    if unreachable:
      print 'waiting for unreachable hosts: %s' % unreachable
      time.sleep(5)
    else:
      break
  return

def GetUnreachableInstances(instances, ssh_key):
  """ Returns list of instances unreachable via ssh. """
  hostnames = [i.private_ip for i in instances]
  ssh_status = AreHostsReachable(hostnames, ssh_key)
  assert(len(hostnames) == len(ssh_status))
  nonresponsive_instances = [instance for (instance, ssh_ok) in
                             zip(instances, ssh_status) if not ssh_ok]
  return nonresponsive_instances

def GetUnreachableHosts(hostnames, ssh_key):
  """ Returns list of hosts unreachable via ssh. """
  ssh_status = AreHostsReachable(hostnames, ssh_key)
  assert(len(hostnames) == len(ssh_status))
  nonresponsive_hostnames = [host for (host, ssh_ok) in
                             zip(hostnames, ssh_status) if not ssh_ok]
  return nonresponsive_hostnames

def AreHostsReachable(hostnames, ssh_key):
  """ Returns list of bools indicating if host reachable via ssh. """
  # validate input
  for hostname in hostnames:
    assert(len(hostname))
  ssh_ok = [exit_code == 0 for (exit_code, _) in
            RunCommandOnHosts('echo test > /dev/null', hostnames, ssh_key)]
  return ssh_ok

################################################################################
# 
################################################################################

def AmiName(ami_release_name, ubuntu_release_name, virtualization_type,
            mapr_version, role):
  """ Returns AMI name using Cirrus ami naming convention. """
  if not role in valid_instance_roles:
    raise RuntimeError('Specified role (%s) not a valid role: %s' %
                         (role, valid_instance_roles))
  if virtualization_type not in valid_virtualization_types:
    raise RuntimeError('Specified virtualization type (%s) not valid: %s' %
                         (virtualization_type, valid_virtualization_types))
  ami_name = 'cirrus-%s-ubuntu-%s-%s-mapr%s-%s' % (ami_release_name,
                                                   ubuntu_release_name,
                                                   virtualization_type,
                                                   mapr_version, role)
  return ami_name

# def LookupCirrusAmi(ec2, instance_type, ubuntu_release_name, mapr_version, role,
#                     ami_release_name = default_ami_release_name,
#                     ami_owner_id = default_ami_owner_id):
def LookupCirrusAmi(ec2, instance_type, ubuntu_release_name, mapr_version, role,
                    ami_release_name,
                    ami_owner_id):  
  """ Returns AMI satisfying provided constraints. """
  if not role in valid_instance_roles:
    raise RuntimeError('Specified role (%s) not a valid role: %s' % (role, 
                       valid_instance_roles))
  virtualization_type = 'paravirtual'
  if IsHPCInstanceType(instance_type):
    virtualization_type = 'hvm'
  assert(ami_owner_id)  
  images = ec2.get_all_images(owners=[ami_owner_id])
  ami = None
  ami_name = AmiName(ami_release_name, ubuntu_release_name, virtualization_type,
                     mapr_version, role)
  for image in images:
    if image.name == ami_name:
        ami = image
        break
  return ami

###############################################################################
# EC2 Helpers
###############################################################################


def GetRegion(region_name):
  """ Converts region name string into boto Region object. """
  regions = boto_ec2.regions()
  region = None
  valid_region_names = []
  for r in regions:
    valid_region_names.append(r.name)
    if r.name == region_name:
        region = r
        break
  if not region:
    logging.info( 'invalid region name: %s ' % (region_name))
    logging.info( 'Try one of these:\n %s' % ('\n'.join(valid_region_names)))
    assert(False)
  return  region



def CredentialsValid(aws_id, aws_secret):
  valid = False
  try:
    ec2_conn = ec2_connection.EC2Connection(aws_id, aws_secret)        
    ec2_conn.get_all_images(owners=['self'])
    valid = True      
  except boto_exception.BotoServerError:
    pass
  return valid
    

@RetryUntilReturnsTrue(4)
def CreateTestedEc2Connection(iam_aws_id, iam_aws_secret, region_name):
  """ Retries in case IAM fails because IAM credentials are new and not yet
      propagated to all regions.
  """ 
  region = GetRegion(region_name)
  conn = ec2_connection.EC2Connection(iam_aws_id, iam_aws_secret, 
                                          region = region)
  # test that ec2 connection works
  try:        
    conn.get_all_images(owners=['self'])      
  except boto_exception.EC2ResponseError as e:
    #if e.error_code == 'AuthFailure' or e.error_code == 'InvalidAccessKeyId':
    print 'ec2 connect failed... will retry...'
    return False
  except:
    raise
  return conn

@RetryUntilReturnsTrue(4)
def CreateTestedS3Connection(iam_aws_id, iam_aws_secret):
  conn = s3_connection.S3Connection(iam_aws_id, iam_aws_secret)
  try:        
    conn.get_all_buckets()
  except boto_exception.S3ResponseError as e:
    #if e.error_code == 'AuthFailure' or e.error_code == 'InvalidAccessKeyId':
    print 's3 connect failed... will retry...'
    return False
  except:
    raise
  return conn

@RetryUntilReturnsTrue(4)
def CreateTestedIamConnection(iam_aws_id, iam_aws_secret):
  conn = iam_connection.IAMConnection(iam_aws_id, iam_aws_secret)
  try:        
    conn.get_all_users()
  except boto_exception.BotoServerError as e:
    #if e.error_code == 'AuthFailure' or e.error_code == 'InvalidAccessKeyId':
    print 'iam connect failed... will retry...'
    return False
  except:
    raise
  return conn



def PrivateToPublicOpenSSH(key, host):
  """ Computes the OpenSSH public key format given a private key. """
  # Create public key from private key.
  ssh_rsa = '00000007' + base64.b16encode('ssh-rsa')
  # Exponent.
  exponent = '%x' % (key.e,)
  if len(exponent) % 2:
      exponent = '0' + exponent
  ssh_rsa += '%08x' % (len(exponent) / 2,)
  ssh_rsa += exponent
  modulus = '%x' % (key.n,)
  if len(modulus) % 2:
      modulus = '0' + modulus
  if modulus[0] in '89abcdef':
      modulus = '00' + modulus
  ssh_rsa += '%08x' % (len(modulus) / 2,)
  ssh_rsa += modulus
  hash_string = base64.b64encode(base64.b16decode(ssh_rsa.upper()))
  public_key = 'ssh-rsa %s %s' % (hash_string, host)
  return public_key

@RetryUntilReturnsTrue(4)
def InitKeypair(aws_id, aws_secret, ec2, s3, config_bucket_name, keypair_name, src_region, 
                dst_regions):
  """ 
  Returns the ssh private key for the given keypair name Cirrus created bucket.
  Creates the keypair if it doesn't yet exist and stores private key in S3. 
  """
  ssh_key = None
  try:
    # check if a keypair has been created
    config_bucket = s3.lookup(config_bucket_name)
    if not config_bucket:
      config_bucket = s3.create_bucket(config_bucket_name, policy='private')  
    keypair = ec2.get_key_pair(keypair_name)
    if keypair:
      # if created, check that private key is available in s3
      s3_key = config_bucket.lookup('ssh_key')
      if s3_key:
        ssh_key = s3_key.get_contents_as_string()
  
    # if the private key is not created or not available in s3, recreate it
    if not ssh_key:
      if keypair:
        ec2.delete_key_pair(keypair_name)
  
      print 'recreating keypair: %s' % (keypair_name)
      # create new key in current region_name
      keypair = ec2.create_key_pair(keypair_name)
      ssh_key = keypair.material
      # store key in s3
      k = Key(config_bucket)
      k.key = 'ssh_key'
      k.set_contents_from_string(ssh_key)
      DistributeKeyToRegions(src_region, dst_regions, keypair, aws_id, aws_secret)
  except boto_exception.S3ResponseError:
    return False
    
  assert(keypair)
  assert(ssh_key)
  return ssh_key


def DistributeKeyToRegions(src_region, dst_regions, private_keypair,
                           aws_id, aws_secret):
  """
  Copies the keypair from the src to the dst regions. 
  Note: keypair must be a newly created key... that is the key material is 
  the private key not the public key.
  """
  private_key = RSA.importKey(private_keypair.material)
  public_key_material = PrivateToPublicOpenSSH(private_key,
                                               private_keypair.name)
  for dst_region in dst_regions:
    if dst_region == src_region:
      continue
    logging.info( 'distributing key %s to region %s' % (private_keypair.name,
                                                        dst_region))
    dst_region_ec2 = CreateTestedEc2Connection(aws_id, aws_secret,
                                                    dst_region)
    try:
      dst_region_ec2.delete_key_pair(private_keypair.name)
    except:
      raise
    dst_region_ec2.import_key_pair(private_keypair.name, public_key_material)
  return

def WaitForVolumeAvailable(volume):
  """ Blocks until EBS volume is available. """
  __WaitForVolume(volume, 'available')
  return

def WaitForVolumeAttached(volume):
  """ Blocks until EBS volume is attached. """
  __WaitForVolume(volume, 'in-use')
  return

def __WaitForVolume(volume, desired_state):
  """ Blocks until EBS volume is in desired state. """
  print 'Waiting for volume %s to be %s...' % (volume.id, desired_state)
  while True:
    volume.update()
    sys.stdout.write('.')
    sys.stdout.flush()
    #print 'status is: %s' % volume.status
    if volume.status == desired_state:
        break
    time.sleep(5)  
  return

def WaitForSnapshotCompleted(snapshot):
  """ Blocks until snapshot is complete. """
  print 'Waiting for snapshot %s to be completed...' % (snapshot)
  while True:
      snapshot.update()
      sys.stdout.write('.')
      sys.stdout.flush()
      #print 'status is: %s' % snapshot.status
      if snapshot.status == 'completed':
          break
      time.sleep(5)
  return



def GetInstanceState(instance):
  instance.update()
  return instance.state

def __WaitForInstance(instance, desired_state):
  """ Blocks until instance is in desired_state. """
  print 'Waiting for instance %s to change to %s' % (instance.id, desired_state)
  while True:
      try:
          instance.update()
          state = instance.state
          sys.stdout.write('.')
          sys.stdout.flush()
          if state == desired_state:
              break
      except boto_exception.EC2ResponseError as e:
          logging.info(e)
      #except boto_exception.ResponseError as e:  # This is an alias
      #    logging.info(e)
      time.sleep(5)  
  return

def WaitForInstanceRunning(instance):
  """ Blocks until instance is running. """
  __WaitForInstance(instance, u'running')
  return

def WaitForInstanceStopped(instance):
  """ Blocks until instance is stopped. """
  __WaitForInstance(instance, u'stopped')
  return

def WaitForInstanceTerminated(instance):
  """ Blocks until instance is terminated. """
  __WaitForInstance(instance, u'terminated')
  return

def NonePending(reservations):
  for res in reservations:
    for instance in res.instances:
      if instance.state == "pending":
        return False
  return True

def NumberInstancesInState(reservations, state):
  number_instances = 0
  for res in reservations:
      for instance in res.instances:
          if instance.state == state:
              number_instances += 1
  return number_instances

def SearchUbuntuAmiDatabase(release_name, region_name, root_store_type,
                            virtualization_type):
  """ Returns the ubuntu created ami matching the given criteria. """
  ami_list_url = 'http://cloud-images.ubuntu.com/query/%s/server/released.txt' \
   % (release_name)
  url_file = urllib2.urlopen(ami_list_url)
  # The mapping of columns names to col ids in the ubuntu release txt file.
  release_name_col = 0
  release_tag_col = 2
  release_date_col = 3
  root_store_type_col = 4
  arch_col = 5
  region_col = 6
  ami_col = 7
  matching_amis = []  # list of tuples (ami_id, tokens)
  
  for line in url_file:
    tokens = line.split()
    # lines have different number of columns (one fewer for hvm)
    if (len(tokens) == 9):
      virtualization_type_col = 8
    elif (len(tokens) == 10):
      virtualization_type_col = 9
    else:
      raise RuntimeError('invalid line format: %s' % line)
    if tokens[release_name_col] == release_name \
       and tokens[release_tag_col] == 'release' \
       and tokens[root_store_type_col] == root_store_type \
       and tokens[arch_col] == 'amd64' \
       and tokens[region_col] == region_name \
       and tokens[virtualization_type_col] == virtualization_type: 
       matching_amis.append((tokens[ami_col], tokens))
  matching_amis.sort(key=lambda (ami, tokens) : tokens[release_date_col], 
                     reverse=True)  # order newest first  
  if not matching_amis:
    params = [release_name, root_store_type, region_name,  virtualization_type]
    raise RuntimeError('Failed to find matching ubuntu ami: %s', params)
  selected_ami = matching_amis[0][0]
  return selected_ami

def IsHPCInstanceType(instance_type):
  return instance_type in hpc_instance_types

def GetRootStoreAndVirtualizationType(instance_type):
  root_store_type = ''
  if IsHPCInstanceType(instance_type):
    root_store_type = 'ebs'
    virtualization_type = 'hvm'
  else:
    root_store_type = 'instance-store'
    virtualization_type = 'paravirtual'
  return  root_store_type, virtualization_type





