=========================================================================
 csz-targetcontrol - Citon ZFS Seed iSCSI Injector Station Device Mapper 
=========================================================================

These scripts are for use with seeding ZFS replication for remote sites with
limited bandwidth.


COMPONENTS
----------

* czs-targetcontrol.py - Python script for use with FreeBSD "injector" system.
* czs-targetcontrol.conf - Configuration file.  Normally kept in /etc

REQUIREMENTS
------------

* Requires Python 3.2+


INSTALLATION
------------

TBC


CONFIGURATION
-------------

All configuration for czs-targetcontrol is done by way of a single configuration
file - czs-targetcontrol.conf.   The following parameters can be adjusted:

* DESCRIPTION

::

 KEY = VALUE

[system] Section:

* Set the overal verbosity of console and syslog messages to one of debug, info, warning, error, or critical.  Note that the email alerts are always at the "info" level

 loglevel = info

* Set the target IQN to present mapped LUNs under.  This is the target your iSCSI initiators should scan. 

::

target_name = iqn.1997-03.com.citon:target0

* Set the ctld "auth-group" to use.  If you are not using an isolated storage network it is strongly advised that you enable authentication for iSCSI access. Define your auth settings in ctl.conf then reference the section with this variable.

auth_group = no-authentication

* Set the iSCSI portal-group to use.  A portal group defines what address(es) the iSCSI target daemon listens on and common settings for conections to the group.  This MUST be defined in the ctl.conf file!

::

portal_group = pg0

* Set the pid file for this script to use to prevent multiple instances from modifying configurations at the same time.

::

czstc_pid = /var/run/czs-targetcontrol.pid

* Direct the script to the ctl.conf ctld config file.  This file will be manipulated directly.

::

ctld_conf = /etc/ctl.conf

* Point to the pid file for the ctld daemon.  This is required in order to issue a HUP signal to the daemon, triggering a graceful configuration update.

::

ctld_pid = /var/run/ctld.pid

* Define a command line to execute that will return the serial number for a given block device.  The first line of output will be used.

::

fetch_serial_command = /sbin/camcontrol -S {device}


[syslog] Section:

* Enable syslogging

::

 enable = true

[mail] Section:

* Enable email reports

::

 enable = true

* If emailon is set, you must configure an SMTP server IP or domain name - SMTP auth is not supported at this time, so add the IP of the machine running encrarch to the list of allowed IPs in your SMTP server

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
::



USAGE
-----

TBC



ADDITIONAL INFORMATION
----------------------
* *pydoc czs-targetcontrol.py* - Embedded documentation
* *man ctl.conf* - Documentation for the ctld configuration file
* *man ctld* - Documentation for the cltd daemon 
* *https://www.freebsd.org/doc/handbook/network-iscsi.html* - FreeBSD Handbook section for iSCSI




:Authors:

Paul M. Hirsch <paul.hirsch@citon.com>


