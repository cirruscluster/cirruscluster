from setuptools import setup 
from setuptools import find_packages

setup(
  name='cirruscluster',
  version='0.0.1-3', # use semantic version conventions
  packages= find_packages(),
  license='MIT',
  #long_description=open('README.md').read(),
  install_requires=['distribute', 
                    'docutils>=0.3', 
                    'boto>=2.9.5',
                    'pycrypto', # this seems hard to satisfy on Win
                    'pyyaml>=3.10',
                    'Jinja2>=2.7',
                    'paramiko>=1.10.1',
                    'python-dateutil>=2.1',
                    'requests>=1.2',
                    'passlib>=1.6.1',
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
  author_email = "heathkh@gmail.com",
  description = "A batteries-included MapReduce cluster-in-a-can for scientists, researchers, and engineers.",
  keywords = "hadoop MapR mapreduce cluster cloud",
  url = "https://github.com/heathkh/cirruscluster",   # project home page, if any    
)
