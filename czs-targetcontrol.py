#!/usr/bin/python3

# czs-targetcontrol - Citon ZFS Seed iSCSI injection station control script.

# Copyright(c) 2014, Citon Computer Corporation
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of CITON COMPUTER CORPORATION nor the names of
#    its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

##
# This is designed to run on a  system with a multitude of USB/other
# ports allowing attachment of seed data drives.  When a drive is attached
# it is automatically shared as a iSCSI LUN.  The LUN is destroyed when the
# drive is detached.
#
# Requires Python 3.2+ because the future is now
##

VERSION = "v0.2 (2014-11-15)"

# General imports
import sys, os, stat, signal, subprocess, time, re, datetime

# Logging and alerting
import logging, logging.handlers, smtplib, email.message, syslog

# rtslib - The LIO API
import rtslib

# PyUDEV used for device query
import pyudev

# Configuration handling
import configparser, argparse

# Optional DNS based device serial number to name lookup service.
# Requires the pydns (py3dns) package which provides the DNS module
import DNS

# Set the number of seconds to wait if a previous instance is detected as running
# and the maximum times to check before dying out
WAIT_SECONDS = 10
WAIT_RETRIES = 6

# The name we want to report in logs and files for this script
IDENT = 'csz-targetcontrol'

# Default location of config
CONFFILE = "/etc/czs-targetcontrol.conf"

# Create our global config dict
config = configparser.ConfigParser()

# Our logger will be global
logger = logging.getLogger(IDENT)



class Error(Exception):
    """
    Base class for custom exceptions
    """
    pass


class GeneralError(Error):
    """
    Well handled exceptions - These represent normal operation errors and not
    coding or critical system problems
    """

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class EmailReportHandler(logging.Handler):
    """
    Buffer and generate email reports
    """

    def __init__(self, smtpserver, fromaddr, toaddrs, subjectprefix):
        """
        Setup email reporter:

         smtpserver - Hostname or IP of SMTP relay
         fromaddr - String with email address of sender
         toaddrs - Array of email addresses to send to
         subjectprefix - Common prefix to prepend to all subject lines
        """

        logging.Handler.__init__(self)

        self.smtpserver = smtpserver
        self.fromaddr = fromaddr
        # From a CSV to an array.  Look ma - no regex!
        self.toaddrs = [to.strip() for to in toaddrs.split(',')]
        self.subjectprefix = subjectprefix

        # Start with an empty buffer and a NOTSET (0) level high water mark
        self.buf = ""
        self.maxlevel = 0
        self.starttime = time.strftime("%Y-%m-%d %H:%M:%S")

    def emit(self, record):
        """
        Add line to buffer (This is different than most logging handlers,
        which would ship the message immediately on an emit)
        """

        # Save the text
        self.buf += self.format(record) + "\r\n"

        # Update our high water mark for collected messaged
        if record.levelno > self.maxlevel: self.maxlevel = record.levelno

    def send(self, subject, body):
        """
        Send email report with a given subject line and body
        """
        
        body += self.buf

        msg = email.message.Message()

        # Check maximum level and add a special note in the subject for anything
        # above INFO
        if self.maxlevel > 20:
            notice = "(" + logging.getLevelName(self.maxlevel) + " ALERT) "
        else:
            notice = ""

        # Build our message header
        msg.add_header('From', self.fromaddr)
        for t in self.toaddrs:
            msg.add_header('To', t)
        msg.add_header('Subject', "%s %s %s" % (self.subjectprefix, notice, subject))
        msg.set_payload(body)

        # Fire!
        server = smtplib.SMTP(self.smtpserver)

        # server.set_debuglevel(1)

        server.sendmail(msg['From'], msg.get_all('To'), msg.as_string())
        server.quit()


class singleInstance(object):
    """
    PID file based single-instance check - Required since we are modifying a
    single config file.  Based on recipe from:
    http://code.activestate.com/recipes/546512-creating-a-single-instance-application-linux-versi/
    """
                        
    def __init__(self, pidPath):
        '''
        pidPath - Full path to pid file to store running pid in
        '''
        self.pidPath = pidPath

        # Default - Assume not running
        self.lasterror = False

        # Attempt to open pid file and check for running process
        try:
            # Errors out if not present
            pid = open(pidPath, 'r').read().strip()

            # Errors out if process is not running
            os.kill(int(pid), 0)
            
            # Looks like it IS running already
            self.lasterror = True

        except (IOError, OSError):
            # Could not open pid file, or process not running - Either way,
            # we are clear
            self.lasterror = False

        except ValueError as err:
            # Malformed pid file - Die
            raise GeneralError("Unable to process pid file %s: %s" % (pidPath, err))

        if not self.lasterror:
            try:
                # Attempt to write out new pid file
                fp = open(pidPath, 'w')
                fp.write(str(os.getpid()))
                fp.close()

            except (IOError, OSError) as err:
                # Permission or similar issue - Die
                raise GeneralError("Unable to write pid file %s: %s" % (pidPath, err))

    def alreadyrunning(self):
        return self.lasterror

    def __del__(self):
        if not self.lasterror:
            os.unlink(self.pidPath)


def configure (conffile):
    """
    Read configuration file into the global config dictionary and ensure
    sections are present
    """

    # Perform a quick (but race vulnerable) config file existence and permission
    # check.
    try:
        # Open the config for reading (or fail)
        conffilefp = open(conffile, 'r')

        # Check the permissions on it
        if (os.stat(conffile).st_mode & stat.S_IWOTH):
            raise GeneralError("Configuration file %s is world writable.  Please remove the 'kick-me' sign with 'chmod og-wx %s'" % (conffile, conffile))

    except (IOError, OSError) as err:
        raise GeneralError("Unable to read configuration file %s: %s" % (conffile, err))

    # Read in the config and perish if nothing is read
    config.readfp(conffilefp)
    
    if not config.has_section('system'):
        raise GeneralError("No [system] section in configuration file %s - EXITING" % conffile)

    # System config. Items commented out are features from the FreeBSD
    # code that need to be recoded into the LIO version.
    config['system']['loglevel'] = config.get('system', 'loglevel', fallback='info')
    config['system']['target_name'] = config.get('system', 'target_name', fallback='iqn.1997-03.com.citon:target0')
    config['system']['serial_attribute'] = config.get('system', 'serial_attribute', fallback='ID_SERIAL_SHORT')
    config['system']['czstc_pid'] = config.get('system', 'czstc_pid', fallback='/var/run/czs-targetcontrol.pid') 

    # XXX Not yet implemented - Will need more sanity check code to prevent
    # swapping device LUNs on reboot
    #config['system']['save_changes'] = config.get('system', 'save_changes', fallback='true')

    # XXX Implemented for attach but not detach
    # # Set to "true" to normalize all devices to use the by-id path for access.
    # This is recommended for most uses. When enabled, the /dev/disk/by-id/
    # path will automatically be selected regardless of how the device ID is
    # passed.
    # !!! DO NOT CHANGE THIS UNLESS ALL DEVICES ARE UNMAPPED !!!  If some devices
    # are already mapped, you may be unable to add/remove devices accurately.
    #by_id = true
    config['system']['by_id'] = config.get('system', 'by_id', fallback='false')

    # Gone for now.  May work back in for easier startup or updated FreeBSD port
    #config['system']['auth_group'] = config.get('system', 'auth_group', fallback='no-authentication')
    #config['system']['portal_group'] = config.get('system', 'portal_group', fallback='pg0')
    #config['system']['target_config'] = config.get('system', 'target_config', fallback='/etc/ctl.conf')
    #config['system']['dummy_lun_img'] = config.get('system', 'dummy_lun_img', fallback='/root/czs-targercontrol-dummy-lun0.img')
    
    # Sanity check loglevel
    if not re.match('debug|info|warning|error|critical', config['system']['loglevel']):
            raise GeneralError("Invalid loglevel %s in %s - Must be debug, info, warning, error, or critical" % (config['system']['loglevel'], conffile))
    
    # Sanity check device serial to name lookup settings
    if 'lookup' in config:
        config['lookup']['enable'] = config.get('lookup', 'enable', fallback='false')
        config['lookup']['domain'] = config.get('lookup', 'domain')

        # Prime the DNS system.  This uses /etc/resolv.conf.
        DNS.DiscoverNameServers()

    else:
        config['lookup'] = {}
        config['lookup']['enable'] = 'false'

    # Sanity check log settings
    if 'syslog' in config:
        config['syslog']['enable'] = config.get('syslog', 'enable', fallback='false')

        # Check facility for proper code name
        if not re.match('user|daemon|syslog|local[0-7]', config.get('syslog', 'facility', fallback='local0')):
            raise GeneralError("Invalid syslog facility %s in %s - Must be user, daemon, syslog, or local 0-7" % (config.get('syslog', 'facility'), conffile))

        config['syslog']['syslog_server'] = config.get('syslog', 'syslog_server', fallback='/dev/log')

        # Replace with syslog facility
        config['syslog']['facility'] = 'LOG_' + config.get('syslog', 'facility', fallback='daemon').upper()

    else:
        config['syslog'] = {}
        config['syslog']['enable'] = 'false'

    # Mail config
    if ('mail' in config) and config.getboolean('mail', 'enable'):
        # Make sure everything is set.
        req = ['smtp_server', 'sender', 'recipients', 'subject_prefix'] 
        for item in req:
            if not config.has_option('mail', item):
                raise GeneralError("Mail enabled but missing %s value" % item)
            
            # Break out the recipient list
            if item == 'recipients':
                config['mail']['recipients'] = config.get('mail', 'recipients')
    else:
        config['mail'] = {'enable': 'false'}

    return True


def fix_syslog_server (syslog_server):
    """
    Check input string for either a path or a host:port value.  Return a simple string if
    it is a path or return a (host, port) tuple if a remote server is specified.
    """

    syslog_server = syslog_server.strip()

    if syslog_server.startswith('/'):
        # Looks like a path.  Check that it is there.
        if not os.path.exists(syslog_server):
            # Oh, you wanted to log?  Time to die.
            raise GeneralError("Could not find syslog device %s" % syslog_server)

    else:
        # Try to extract a name/address and a port.
        match = re.match(r'^([\da-z\.\-\:\[\]]+)\:(\d+)$', syslog_server)
        if match:
            syslog_server = (match.group(1), int(match.group(2)))

        else:
            raise GeneralError("Could not grok syslog_server value... what the heck is a %s ???" % syslog_server)

    return syslog_server


def fix_device_path_nocheck (device):
    """
    Perform a simple sanity check and cleanup on a device name without
    verifying that it exists.  Use when removing a detached device.
    Returns a cleaned up version of the device path.
    """

    # If it is not fully pathed, assume it is under /dev/
    if not device.startswith('/'):
        device = '/dev/' + device

    # XXX Add further translations here as needed XXX

    return device


def fix_device_path (device):
    """
    Given a short/incomplete device name find the full device path for use
    in ctl.conf.  Returns an empty string upon failure.  Use this when
    checking if a device is present.  If the device is detached already just
    use fix_device_path_nocheck instead
    """

    # Run it though our non-checking fixer first
    device = fix_device_path_nocheck(device)

    # Now check that it is a block device.  Support for file backed LUNs can be added later.
    if not os.path.exists(device):
        # Log warning and return nothing
        logger.warning("Could not find block device %s" % device)
        return ""

    mode = os.stat(device).st_mode
    if not stat.S_ISBLK:
        logger.warning("Device %s is not a block device" % device)
        return ""
    
    return device


def fetch_device_path_and_serial (device, default_serial=""):
    """
    Attempt to fetch the preferred path and serial number for a
    given device. Returns the prefered device path and a precleaned
    serial number string on success.  If default_serial is defined
    it will be returned if the serial number lookup fails, else a 
    munged version of the device name is used.
    """
    
    # Sanity check on the device name
    if not re.match(r'^\/[a-z0-9\:\.\-_\/]+$', device, flags=re.IGNORECASE):
        raise GeneralError("Device name '%s' did not pass safety check.  Will not proceed." % device)
    

    # Look for the device using UDEV
    matched = 0

    context = pyudev.Context()
    for dev in context.list_devices(subsystem='block').match_property('DEVTYPE', 'disk'):
        # Allow for device name to be the main DEVNAME property
        if dev['DEVNAME'] == device:
            matched = 1
            break

        # ...or be included in the list of DEVLINKS
        if 'DEVLINKS' in dev:
            m = re.search(r'(^|\s)(%s)($|\s)' % device, dev['DEVLINKS'])
            if m:
                matched = 1
                break
    
    # If the device is not present in UDEV we should just return
    if not matched:
        return (device, default_serial)

    if config.getboolean('system', 'by_id'):
        # Translate to our prefered path if so configured
        PREFERRED_PATH = r'/dev/disk/by-id/'
        m = re.search(r'(^|\s)(%s.+?)($|\s)' % PREFERRED_PATH, dev['DEVLINKS'])
        if m:
            device = m.group(2)
            # Another sanity check on the device.  (Now the prefered path)
            if not re.match(r'^\/[a-z0-9\:\.\-_\/]+$', device, flags=re.IGNORECASE):
                raise GeneralError("Device name '%s' did not pass safety check.  Will not proceed." % device)

            logger.debug("Using \"%s\" for device path" % device)

        else:
            logger.debug("Could not find device link under %s for requested device \"%s\"" % (PREFERRED_PATH, device))
            
            
    if config['system']['serial_attribute'] in dev:
        # Try to pull the long serial
        serial = dev[config['system']['serial_attribute']]
    elif default_serial != "":
        serial = default_serial
    else:
        # Oh well - Return a sanitized version of the device name
        serial = re.sub(r'[^a-z0-9\-]', r'-', device).strip('-')

    return (device, serial)


def translate_serial_to_name (serial):
    """
    CNAME lookup of device serial numbers to a friendly name. Requires
    "serial-XXXXX" entries in the configured "domain".  The CNAME entries
    should point to the name of the device. For example, if your lookup domain
    is "czs.example.com" and the serial number of the device,
    (as reported by camcontrol inquiry DEVICENAME -S), is "3413ef34", then this
    function will check for the CNAME "serial-3413ef34.czs.example.com".  If
    such a record existed and were named "czs1234.czs.example.com", this method
    would return "czs1234"

    Returns the friendly device name on sucess or the serial back as passed
    on failure.
    """
    
    # Push the serial to lower case
    serial = serial.lower()

    # Cleanup serial number to only include valid DNS text and report any
    # changes in debug.
    nserial = re.sub(r'[^a-z0-9\-]', r'-', serial)
    
    # It must also be no more than 63 chars long, minus "serial-".
    # (So, 56 chars or less).  Truncation is done starting at the front
    # to maintiain the most unique portion in a typical serial.
    nserial = nserial[len(nserial) - 56:]

    if serial != nserial:
        logger.info("Using \"%s\" instead of \"%s\" for CNAME lookup" % (nserial, serial))
        serial = nserial
    
    # The name to resolve
    sname = "serial-" + serial + '.' + config['lookup']['domain']

    # Give it a go
    request = DNS.Request(qtype="CNAME", name=sname)
    response = request.req()

    if response.answers and 'data' in response.answers[0]:
        devname = response.answers[0]['data']
        
        # Verify the result and return with the domain stripped off
        if devname.endswith('.' + config['lookup']['domain']):
            devname = devname[:-len('.' + config['lookup']['domain'])]
            logger.info("Successfully resolved %s to device name %s" % (serial, devname))
            return devname

        else:
            logger.warning("Invalid data in CNAME lookup for %s: %s" % (serial, devname))

    else:
        logger.info("Alias not found in DNS - Using device serial number %s for iSCSI name. (Add a CNAME for %s to correct this)" % (serial, sname))

    # Fell through, so just return the serial
    return serial

    
def fetch_target (targetname):
    """
    Given a target name, return either the rtslib target object or None.
    """

    target = None
    try:
        root = rtslib.RTSRoot()
        
        for t in root.targets:
            if t.wwn == config['system']['target_name']:
                # Matched!
                target = t
                break

    except rtslib.utils.RTSLibError as err:
        raise GeneralError("RTSLib error when trying to fetch target object %s: %s" % (targetname, err))

    return target
        

def enumerate_luns (target):
    """
    Return a dictionary of currently configured LUNs for our target
    """
    
    luns = {}

    if not target:
        raise GeneralError("Target not defined!  You must configure %s using targetcli before using this system!" % config['system']['target_name'])

    # Only target group 1 is supported at this time.  If you want different
    # auth sets/etc then make another whole target/WWN
    tpgs = next(target.tpgs)

    for lun in tpgs.luns:
        lunid = str(lun.lun)

        # Bye LUN 0
        if lunid == '0':
            continue

        name = lun.storage_object.name
        device = lun.storage_object.udev_path
        # If by_id is enabled this will not only give us a serial but will
        # force the device path to our prefered path.
        (device, serial) = fetch_device_path_and_serial(device)
        device_syspath = lun.storage_object.path

        logger.debug("Found LUN section for device name %s (path %s, serial %s) with LUN %s" % (name, device, serial, lunid))
        luns[lunid] = {}
        luns[lunid]['device'] = device
        luns[lunid]['name'] = name
        luns[lunid]['serial'] = serial
        luns[lunid]['device_syspath'] = device_syspath

    return luns


def add_device_to_luns (device, luns, default_serial=""):
    """
    Add a new LUN entry for the provided device path.  Returns an updated LUN
    dict and a status message string.  Checks for same device path already
    being shared and skips making changes.  Changing to check for duplicate
    names/serial numbers instead could be better but there would need to be
    a lot of checking to make sure bad lookups/duplicate serials don't creep
    in and ruin the show.
    """
    
    # Cleanup the device name and make sure it exists
    t = fix_device_path(device)
    if not t:
        msg = "Failed to find device %s - Not adding to LUNs" % device
        logger.warning(msg)
        return (luns, msg)
    device = t

    # Make sure the device is not already in the list
    device_exists = 0
    for lunid in luns:
        if luns[lunid]['device'] == device:
            msg = "Device %s already mapped to LUN %s" % (device, lunid)
            logger.info(msg)
            return (luns, msg)

    # Lookup the device prefered path, serial, and name
    (device, serial) = fetch_device_path_and_serial(device, default_serial="")
    if config.getboolean('lookup', 'enable'):
        name = translate_serial_to_name(serial)
    else:
        name = serial

    # Find the lowest free LUN over 0 and add a new entry
    for i in range(1,255):
        lunid = str(i)
        if not lunid in luns:
            # Found one!
            luns[lunid] = {}
            luns[lunid]['device'] = device
            luns[lunid]['name'] = name
            luns[lunid]['serial'] = serial
            break

    if not lunid:
        # No free LUN IDs found.  Not good.
        msg = "Unable to map device %s (path %s, serial %s) - No free LUNs found" % (name, device, serial)
        logger.warning(msg)

        return (luns, msg)

    # Build the backing device
    try:
        bso = rtslib.BlockStorageObject(name=name,dev=device,wwn=name)

    except rtslib.utils.RTSLibError as err:
        raise GeneralError("RTSLib error when trying to define block device object %s: %s" % (device, err))


    # Get the device control path for the iBlock storage
    luns[lunid]['device_syspath'] = bso.path

    # Write the name into place before mapping
    #write_device_name(device, luns)

    # Map the LUN
    try:
        target = fetch_target(config['system']['target_name'])
        # Only target group 1 is supported at this time.  If you want different
        # auth sets/etc then make another whole target/WWN
        tpgs = next(target.tpgs)

        lun = rtslib.LUN(tpgs, lun=lunid, storage_object=bso, alias=name)

    except rtslib.utils.RTSLibError as err:
        raise GeneralError("RTSLib error when trying to map LUN %s to device object %s: %s" % (lunid, device, err))

    msg = "Mapped device %s (path %s, serial %s) to LUN %s" % (name, device, serial, lunid)
    logger.info(msg)

    return (luns, msg)



def remove_device_from_luns (device, luns):
    """
    Remove an existing LUN entry for the provided device path.  Returns an
    updated LUN dict and message string.
    """

    # Cleanup the device name without checking if it is present. (Because it probably ain't!)
    device = fix_device_path_nocheck(device)
    found = 0
    for lunid in luns:
        if luns[lunid]['device'] == device:
            found = 1
            break
        
    if not found:
        # Device was not mapped.  Note and move along
        msg = "Could not unmap device path %s - Not currently mapped" % device
        return (luns, msg)

    # Unmap the LUN and destroy the backing device.  It's a cruel world.
    try:
        target = fetch_target(config['system']['target_name'])
        # Only target group 1 is supported at this time.  If you want different
        # auth sets/etc then make another whole target/WWN
        tpgs = next(target.tpgs)
        
        lun = tpgs.lun(lunid)
        so = lun.storage_object

        lun.delete()
        so.delete()

    except rtslib.utils.RTSLibError as err:
        raise GeneralError("RTSLib error when trying to unmap LUN %s from device object %s: %s" % (lunid, device, err))
    
    msg = "Unmapped device %s (path %s, serial %s) from LUN %s" % (luns[lunid]['name'], device, luns[lunid]['serial'], lunid)
    logger.info(msg)
    del luns[lunid]
    
    return (luns, msg)


def report_luns_text (luns):
    """
    Make a human readable report of the lun to device mappings.
    """

    report = "CURRENT LUN TO DEVICE MAPPING(S):\n"
    for lunid in sorted(luns):
        report +=  "LUN: %s, NAME: %s, PATH: %s, SERIAL: %s\n" % (lunid, luns[lunid]['name'], luns[lunid]['device'], luns[lunid]['serial'])

    return report



def life_check_ctld (pid):
    """
    Check if a given process is still amongst the living.
    """
    
    try:
        # Errors out if process is not running
        os.kill(pid, 0)
        
    except OSError:
        # Not running
        return False

    return True
    


def main ():
    # Process CLI args (limited now)
    parser = argparse.ArgumentParser(
        description="Manage presentation of raw devices as iSCSI LUNs",
        epilog="The 'attach' and 'detach' actions require a device to be specified.")
    parser.add_argument('action', metavar='ACTION', choices=['attach', 'detach', 'reset', 'list'], help="attach, detach, reset, or list")
    parser.add_argument('device', metavar='DEVICE', nargs="?", default="", help="the device to attach or detach")
    parser.add_argument('--config', metavar='CONFIG', default=CONFFILE, help="alternate config file")
    parser.add_argument('--serial', metavar='SERIAL', default="", help="explicitly define serial number to use for drive")
    args = parser.parse_args()

    # Make sure the device is set if we are attaching or detaching
    if ((args.action=='attach' or args.action=='detach') and not args.device):
        print("FATAL: You must specify a device after the 'attach' and 'detach' actions\n")    
        parser.print_help()
        exit(1)
    
    # Wrap initial config and steps before we have more alerting take hold
    try:
        # Pull in the config
        configure(args.config)
    

        # If "list" is the action stop now and just spit out the current LUN list
        if args.action == 'list':
            print(report_luns_text(enumerate_luns(fetch_target(config['system']['target_name']))))
            exit(0)


        # Finish logger setup
        format = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
        logger.setLevel(config['system']['loglevel'].upper())

        # Simple console logger
        clog = logging.StreamHandler()
        clog.setFormatter(format)
        logger.addHandler(clog)

        # Syslog
        if config.getboolean('syslog', 'enable'):
            syslog_server = fix_syslog_server(config['syslog']['syslog_server'])
            slog = logging.handlers.SysLogHandler(address=syslog_server, facility=getattr(syslog, config['syslog']['facility']))
            # Use a more quiet log format since syslog already adds a date
            syslog_format = logging.Formatter('%(name)s %(levelname)s %(message)s')
            slog.setFormatter(syslog_format)
            logger.addHandler(slog)
            logger.debug("Enabled syslogging using facility %s" % getattr(syslog, config['syslog']['facility']))

        # Email reporting
        if config.getboolean('mail', 'enable'):
            elog = EmailReportHandler(config['mail']['smtp_server'], config['mail']['sender'], config['mail']['recipients'], config['mail']['subject_prefix'])
            elog.setFormatter(format)
            logger.addHandler(elog)

    except GeneralError as detail:
        print("GeneralError: %s" % detail)
        sys.exit(1)


    # Wrap the remainder - We will log this going forward and only allow one
    # instance at a time
    try:
        # Check for other running instances, wait a while, then die out if we
        # can't get a lock
        retries = WAIT_RETRIES
        waittime = WAIT_SECONDS
        while retries:
            retries -= 1
            thisapp = singleInstance(config['system']['czstc_pid'])
            if thisapp.alreadyrunning():
                if retries:
                    logger.error("Previous instance already running! Waiting %s seconds..." % waittime)
                    time.sleep(waittime)
                else:
                    logger.error("Timed out waiting for previous job to complete.  Remove pidfile %s if incorrect" % config['system']['czstc_pid'])
                    raise GeneralError("Timed out waiting for previous instance to complete")
            else:
                break

        # Pull the current LUN list
        luns = enumerate_luns(fetch_target(config['system']['target_name']))

        if args.action=='attach':
            # Add device to LUN list
            (luns, msg) = add_device_to_luns(args.device, luns, default_serial=args.serial)

        elif args.action=='detach':
            # Remove device to LUN list
            (luns, msg) = remove_device_from_luns(args.device, luns)

        elif args.action=='reset':
            # No LUNS, except 0 which is left alone
            for lunid in luns:
                (luns, msg) = remove_device_from_luns(luns[lunid]['device'], luns)

            msg = "Cleared all LUN mappings other than 0"

            
        #logger.info("Configuration updated")
        
    
    except GeneralError as detail:
        logger.error("%s" % detail)
        if config.getboolean('mail', 'enable'):
            if args.action=="reset":
                elog.send("FAIL - Did not complete %s" % args.action, "GeneralError: %s\r\nPlease review the log and investigate as needed" % detail)
            else:
                elog.send("FAIL - Did not complete %s for device %s" % (args.action, args.device), "GeneralError: %s\r\nPlease review the log and investigate as needed" % detail)
        sys.exit(1)
    
    else:
        if args.action=='reset':
            logger.info("Completed reset of LUNs to empty list")
            if config.getboolean('mail', 'enable'):
                elog.send("OK - %s"  % msg, report_luns_text(luns) + "\n\n------ LOG ------\n")
        else:
            logger.info("Completed %s on device %s with status: %s" % (args.action, args.device, msg))
            if config.getboolean('mail', 'enable'):
                elog.send("OK - %s" % msg , report_luns_text(luns) + "\n\n------ LOG ------\n")

    exit(0)

if __name__ == '__main__':
    main()
