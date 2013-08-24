KFS 0.1
===

This is a virtual filesystem for sending signals to processes.

Install
=======

To install KFS copy the directory kfs to the fs directory in the kernel
tree.

   cp -r kfs linux-3.10.x/fs/

Edit the Makefile inside the fs directory by adding the following line
in the list of filesystems to be built.

   obj-y kfs.o

Compile the kernel. KFS will be available to be mounted using the
following command:

   mount -t kfs img kfs/

Bug Report
==========

Please, report bugs to <krisman.gabriel@gmail.com>

Usage
=====

After mounted, KFS will create one file for each process running in the
computer. You can send a POSIX signal to a process by simply writing the
signal number into the file with the correspondent PID.

For Instance, the following command would send a SIGKILL to the process
with PID 103.

   echo 9 > kfs/103

Known limitations
=================

Currently, KFS is limited to handle 256 processes. Further development
should make it capable of supporting any number of processes.
