from setuptools import setup, find_packages

setup(
  name='cirruscluster',
  version='0.1dev',
  packages=[find_packages()],
  license='MIT',
  long_description=open('README.rst').read(),
  install_requires=['distribute', 'docutils>=0.3', 'boto>=2.9.5'],
  entry_points = {
   'console_scripts': [
     'cirrus_workstation_cli = cirruscluster.workstation_cli:main',
     'cirrus_cluster_cli = cirruscluster.cluster.cluster_cli:main',
     #'cirrus_ami_cli = cirruscluster.ami.ami_cli:main',      
   ]
  }    
)