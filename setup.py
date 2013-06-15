from setuptools import setup 
from setuptools import find_packages

setup(
  name='cirruscluster',
  version='0.1dev',
  packages= find_packages(),
  license='MIT',
  long_description=open('README.rst').read(),
  install_requires=['distribute', 
                    'docutils>=0.3', 
                    'boto>=2.9.5',
                    'pycrypto>=2.6',
                    'pyyaml>=3.10',
                    'Jinja2>=2.7',
                    'paramiko>=1.10.1',
                    'python-dateutil>=2.1',
                    'requests>=1.2'
                    ],
  entry_points = {
   'console_scripts': [
     'cirrus_workstation_cli = cirruscluster.workstation_cli:main',
     'cirrus_cluster_cli = cirruscluster.cluster.cluster_cli:main',
     #'cirrus_ami_cli = cirruscluster.ami.ami_cli:main',      
   ]
  }    
)