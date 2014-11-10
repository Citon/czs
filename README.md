=========================================================================
 csz-targetcontrol - Citon ZFS Seed iSCSI Injector Station Device Mapper 
=========================================================================

These scripts are for use with seeding ZFS replication for remote sites with
limited bandwidth.


COMPONENTS
----------

* czs-targetcontrol.py - Python script for use with FreeBSD "injector" system.
* czs-targetcontrol.conf - Configuration file.  Normally kept in /etc
* ctl.conf - iSCSI target configuration file.  Normally kept in /etc
* czs-targetcontrol-dummy-lun0.img - Small disk image to back always-on LUN0

REQUIREMENTS
------------

* Requires Python 3.2+ and py3dns


INSTALLATION
------------

TBC


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

* Set the ctld "auth-group" to use.  If you are not using an isolated storage network it is strongly advised that you enable authentication for iSCSI access. Define your auth settings in ctl.conf then reference the section with this variable.

 auth_group = no-authentication

* Set the iSCSI portal-group to use.  A portal group defines what address(es) the iSCSI target daemon listens on and common settings for connections to the group.  This MUST be defined in the ctl.conf file!

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

* Path to the "dummy LUN0" disk image.  This is a small (666KB if using the provided file) FAT formatted disk image.  ctld requires that LUN 0 is always present for a given target.  This is a problem for czs-targetcontrol since it allows removing/adding devices in any order.  By always serving up a LUN 0, ctld will be happy.

::

 dummy_lun_img = /root/czs-targetcontrol-dummy-lun0.img

* Define a command line to execute that will return the serial number for a given block device.  The first line of output will be used.

::

 fetch_serial_command = /sbin/camcontrol inquiry {device} -S


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
* *pydoc czs-targetcontrol.py* - Embedded documentation
* *man ctl.conf* - Documentation for the ctld configuration file
* *man ctld* - Documentation for the cltd daemon 
* *https://www.freebsd.org/doc/handbook/network-iscsi.html* - FreeBSD Handbook section for iSCSI




:Authors:

Paul M. Hirsch <paul.hirsch@citon.com>


