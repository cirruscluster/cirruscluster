.. _manual_workstation: 

###########
Workstation
###########

The command-line tool ``cirrus_workstation_cli`` can be used to connect and manage your workstations. Run the command with no arguments for help.

.. code-block:: bash

   cirrus_workstation_cli

list
----

List all running workstations (instance id, state, and current public dns name)

connect
-------

Prompts you to select which workstation you want to connect to, starts it if not yet running, and then launches NX client using a custom nxs session file configured to point at your running workstation instance.

start
-----
Starts a stopped workstation.  You begin paying the on-demand price when your instances is running.

stop
----
Stop a running workstation.  You stop paying the on-demand price when your instances is stopped (but continue to pay for the root ebs volumne until it is destroyed).

create
------

Allows you to create a new workstation from the default machine image.

destroy
-------

Destroys the instance and deletes the root EBS volumne.  All data on this workstation will be lost.

add_volume
----------

Adds additional storage as a EBS volume.  Prompts you for the size in GB for the new volume.

.. tip:: 
 
   This is good if you want to store data that might have a lifetime longer than the workstation.  You can attach and detach this volume to other workstations and move it around like you would an external USB hardrive.


resize_root
-----------

Let's you add addtional storage to the root partition.   The default root volume is ~8GB.  This command stops your instance, takes a snapshot, creates a new larger EBS volume, and transfers the snapshot to the new root partition.

.. tip::

   This option is good if you want the storage to have the same lifetime as the workstation. 

