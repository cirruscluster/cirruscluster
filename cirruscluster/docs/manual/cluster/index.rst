.. _manual_workstation: 

#######
Cluster
#######

The command-line tool ``cirrus_cluster_cli`` can be used on the cirrus workstation to create and manage a cirrus cluster. Run the command with no arguments for help.

.. code-block:: bash

   cirrus_cluster_cli

urls
----

Display the url of the MapR console.

create
------

Prompts you for how many workers you want in your cluster.  It first launches the master node, asks you to perform the free M3 MapR license, and then launches the worker nodes.

resize
------
Allows you to add more nodes to a running cluster.

destroy
-------
Terminates the cluster.  Any data on the MapR filesystem will be lost.  Transfer anything you wish to keep to the workstation first.

