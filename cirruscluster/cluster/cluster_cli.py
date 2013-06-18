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

import sys
from cirruscluster.cluster import mapr
from cirruscluster.cluster import config


def main():  
  if (len(sys.argv) < 2):
    print 'Usage:'
    print ' urls - Print the urls Web UI'
    print ' create <num_instances> - Launch a cluster with N nodes'
    print ' resize <num_instance> - Resize a cluster to have N nodes'
    print ' destroy <num_instance> - Shutdown all nodes' \
          ' (warning: all data on maprfs:// is destroyed)'
    print ' see source for additional experimental commands...'
    return 1
  cmd = sys.argv[1]  
  cluster = mapr.MaprCluster(config.GetConfiguration())
  
  if cmd == 'urls':    
    cluster.ShowUiUrls()  
  elif cmd == 'create':
    assert(len(sys.argv) == 3)    
    num_instances = long(sys.argv[2])
    cluster.Create(num_instances)
    cluster.ShowUiUrls()
  elif cmd == 'resize':    
    assert(len(sys.argv) == 3)    
    num_instances = long(sys.argv[2])
    cluster.Resize(num_instances)
    cluster.ShowUiUrls()
  elif cmd == 'destroy':
    cluster.Destroy()
  # Experimental commands  
  elif cmd == 'push_config':
    cluster.PushConfig()      
  elif cmd == 'reset':
    cluster.Reset()  
  elif cmd == 'config_client':
    cluster.ConfigureClient()  
  elif cmd == 'config_lazy':
    cluster.ConfigureLazyWorkers()  
  elif cmd == 'debug':
    cluster.Debug()        
  elif cmd == 'get_property':
    assert(len(sys.argv) == 3)    
    property_name = sys.argv[2]
    print cluster.GetProperty(property_name)      
  elif cmd == 'set_map_reduce_slots_per_node':
    # since hadoop 20.2 has no working capacity scheduler, this hack allows 
    # manual reconfiguration of slots per node to indirectly enforce 
    # resource guarantees
    num_slots_map = long(sys.argv[2])
    num_slots_reduce = long(sys.argv[3])
    assert(cluster.SetNumMapReduceSlotsPerNode(num_slots_map, num_slots_reduce))
  else:
    print 'unknown operation requested: ' + cmd    
    return 1
  return 0

if __name__ == "__main__":
  main()




