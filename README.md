=========================================================================
 csz - Citon ZFS Seed System
=========================================================================

These scripts are for use with seeding ZFS replication for remote sites with
limited bandwidth and related functions.


COMPONENTS
----------

* czs-targetcontrol.py - Python script for use with Linux LIO "injector" system.
* czs-targetcontrol.conf - Configuration file.  Normally kept in /etc
* czs-targetcontrol-dummy-lun0.img - Small disk image to back always-on LUN0

REQUIREMENTS
------------

* czs-targetcontrol.py Requires Python 3.2+, py3dns, and pyudev.  A dedicated
  Linux workstation is suggested with two NICs.  One for management and one
  for storage networking.


INSTALLATION
------------


Instructions are for Debian based systems, including TurnKey Linux.  (TurnKey
Core amd64 is recommended for czs
* Install python3, python3-dns, python3-pip, lio-utils, targetcli, and sudo packages

 apt-get install python3 python3-dns lio-utils targetcli sudo

* Install the RTSLib-FB Python framework for LIO management:

 pip-3.2 install rtslib-fb

* Copy czs-targetcontrol.py into /usr/local/bin and fix permissions

 cp czs-targetcontrol.py /usr/local/bin
 chown root.root /usr/local/bin/czs-targetcontrol.py
 chmod 755 /usr/local/bin/czs-targetcontrol.py

* Copy examples/czs-targetcontrol.conf into /etc and fix permissions  

 cp examples/czs-targetcontrol.conf /etc
 chown root.root /etc/czs-targetcontrol.conf
 chmod 640 /etc/czs-targetcontrol.conf

* Copy examples/czs-targetcontrol-dummy-lun0.img to permanent location

 cp examples/czs-targetcontrol-dummy-lun0.img /root
 chown root.root /root/czs-targetcontrol-dummy-lun0.img
 chmod 600 /root/czs-targetcontrol-dummy-lun0.img

* Use targetcli to setup your LUN 0 back store
  and target group

 targetcli

 cd backstores/fileio
 create czs-dummy-lun0 /root/czs-targetcontrol-dummy-lun0.img 666k

* Create your new target.  The IQN below should be modified to match
  your environment.  Using the FQDN of your injector, reversed, is 
  recommended.  For instance, if your injector is named "test.example.com"
  and example.com was registered in May of 2014, your IQN could be:
  iqn.2014-05.com.example.test:czs.

 cd /iscsi 
 create IQN

* Configure a portal on your storage target IP.  Please consider using a 2nd
  NIC and isolated storage network!  If you do not, you MUST configure some
  sort of authentication to prevent unauthorized access to the iSCSI targets
  on the machine.  Replace TARGETIP with your storage IP:
 
 portals/ create TARGETIP

* Configure authentication for the portal.  This example opens all access and
  can ONLY be used with an isolated storage network. See LIO documentation
  for other authentication setup information. ( http://www.linux-iscsi.org/Doc/RTS%20OS%20Admin%20Manual.pdf )

 set  attribute authentication=0 demo_mode_write_protect=0 generate_node_acls=1 cache_dynamic_acls=1

* Map LUN0 to the new target.

 cd <
 luns/ create /backstores/fileio/dummy0
 cd <

* See what you did
 
 cd /
 ls

* Save it!

 saveconfig



CONFIGURATION
-------------

All configuration for czs-targetcontrol is done by way of a single configuration
file - czs-targetcontrol.conf.   The following parameters can be adjusted:

[system] Section:

* Set the overall verbosity of console and syslog messages to one of debug, info, warning, error, or critical.  Note that the email alerts are always at the "info" level

 loglevel = info

* Set the target IQN to present mapped LUNs under.  This is the target your iSCSI initiators should scan. 

::

 target_name = iqn.1997-03.com.citon:target0

* Set the pid file for this script to use to prevent multiple instances from modifying configurations at the same time.

::

 czstc_pid = /var/run/czs-targetcontrol.pid



[lookup] Section:

* Enable the device serial number to name lookup feature which will attempt to resolve a CNAME for serial-SERIAL.DOMAINNAME when a device is attached.  ("SERIAL" is the reported serial number of the device and "DOMAINNAME" is the DNS domain to search, defined below.)  The CNAME returned should be in the same domain.  The host portion is then used as the device name.  Example: If you attach device serial number 1234 and the domain "czs.example.com" is configured, a DNS CNAME for serial-1234.czs.example.com will be requested.  If the result were "bobs-drive.czs.example.com" then the name of the device will be recorded as "bobs-drive".

::

 enable = true

* Set the DNS domain to pull CNAME records from.  This domain is also required in the CNAME answers, and is stripped from the result.

 domain = czs.example.com
 


[syslog] Section:

* Enable syslogging

::

 enable = true

* Set the syslog facility to log to.  Should be one of: user, daemon, syslog, or local0 through local7

::

 facility = daemon


[mail] Section:

* Enable email reports

::

 enable = true

* You must configure an SMTP server IP or domain name - SMTP auth is not supported at this time, so add the management IP of the injector workstation to the list of allowed IPs in your SMTP server

::

 smtp_server = 10.11.12.13

* Set the "from" email address 

::

 sender  = czs-targetcontrol@example.int

* This also requires one or more email addresses to notify via email - Separate multiple addresses with commas

::
 
 recipients = jerry.only@misfits.int, danzig@danzigcorp.net


* Set the prefix for the Subject: line in email notices.

::

 subject_prefix = CZS-TargetControl:



USAGE
-----

TBC



ADDITIONAL INFORMATION
----------------------





:Authors:

Paul M. Hirsch <paul.hirsch@citon.com>


