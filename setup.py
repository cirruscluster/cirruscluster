from setuptools import setup 
from setuptools import find_packages

setup(
  name='cirruscluster',
  version='0.0.1-14', # use semantic version conventions
  packages= find_packages(),
  license='MIT',
  #long_description=open('README.md').read(),
  install_requires=['distribute>=0.6.45',
                    'passlib>=1.6.1',
                    'paramiko>=1.10.1', 
                    'boto>=2.9.5',                    
                    'pyyaml>=3.10',
                    'Jinja2>=2.7',                    
                    'requests>=1.2',
                    'python-dateutil', #'python-dateutil>=2.1',
                    'pycrypto', # this seems hard to satisfy on Win
                    ],
  package_data={'cirruscluster': ['cluster/playbooks/*', 'ami/playbooks/cluster/*', 'ami/playbooks/workstation/*']},
  include_package_data=True,    
  entry_points = {
   'console_scripts': [
     'cirrus_workstation_cli = cirruscluster.workstation_cli:main',
     'cirrus_cluster_cli = cirruscluster.cluster.cluster_cli:main',
     'cirrus_ami_cli = cirruscluster.ami.ami_cli:main',      
   ]
  },
  author = "Kyle Heath",
  author_email = "cirruscluster@gmail.com",
  description = "A batteries-included MapReduce cluster-in-a-can for scientists, researchers, and engineers.",
  keywords = "hadoop MapR mapreduce cluster cloud",
  url = "https://github.com/heathkh/cirruscluster",   # project home page, if any    
)
