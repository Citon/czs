#!/usr/local/bin/python3

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
# This is designed to run on a FreeBSD system with a multitude of USB/other
# ports allowing attachment of seed data drives.  When a drive is attached
# it is automatically shared as a iSCSI LUN.  The LUN is destroyed when the
# drive is detached.
#
# Requires Python 3.2+ because the future is now
##

VERSION = "v0.1 (2014-11-05)"

# General imports
import sys, os, stat, errno, subprocess, traceback, time, re, datetime

# Logging and alerting
import signal, logging, logging.handlers, smtplib, email, syslog

# Configuration handling
import configparser, argparse

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
        self.toaddrs = toaddrs
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

        msg = email.Message.Message()

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
    PID file based single-instance check - Required since we are modifying a single
    config file.  Based on recipe from:
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
    Read configuration file into the global config dictionary and ensure sections are present
    """

    # Perform a quick (but race vulnerable) config file existance and permission
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
        raise GeneralError("No [system] seciton in configuration file %s - EXITING" % conffile)

    # System config
    config['system']['target_name'] = config.get('system', 'target_name', fallback='iqn.1997-03.com.citon:target0')
    config['system']['auth_group'] = config.get('system', 'auth_group', fallback='no-authentication')
    config['system']['portal_group'] = config.get('system', 'portal_group', fallback='pg0')
    config['system']['czstc_pid'] = config.get('system', 'czstc_pid', fallback='/var/run/czs-targetcontrol.pid')
    config['system']['ctld_conf'] = config.get('system', 'ctld_conf', fallback='/etc/ctl.conf')
    config['system']['ctld_pid'] = config.get('system', 'ctld_pid', fallback='/var/run/ctld.pid')
    config['system']['fetch_serial_cmd'] = config.get('system', 'fetch_serial_cmd', fallback='/sbin/camcontrol -S {device}')
    config['system']['loglevel'] = config.get('system', 'loglevel', fallback='info')

    # Sanity check loglevel
    if not re.match('debug|info|warning|error|critical', config['system']['loglevel']):
            raise GeneralError("Invalid loglevel %s in %s - Must be debug, info, warning, error, or critical" % (config['system']['loglevel'], conffile))

    # Sanity check log settings
    if 'syslog' in config:
        config['syslog']['enabled'] = config.get('syslog', 'enabled', fallback='false')

        # Replace facility with the proper code
        if not re.match('user|daemon|syslog|local[0-7]', config.get('syslog', 'facility', fallback='daemon')):
            raise GeneralError("Invalid syslog facility %s in %s - Must be user, daemon, syslog, or local 0-7" % (config.get('syslog', 'facility'), conffile))

        # Replace with syslog facility
        config['syslog']['facility'] = 'LOG_' + config.get('syslog', 'facility', fallback='daemon').upper()

    else:
        logger.debug("No [syslog] section found in %s - Using defaults" % conffile)
        config['syslog'] = {}
        config['syslog']['enabled'] = 'false'
        config['syslog']['level'] = 'info'

    # Mail config
    if ('mail' in config) and config.getboolean('mail', 'enabled'):
        # Make sure everything is set.
        req = ['smtp_server', 'sender', 'recipients', 'subject_prefix'] 
        for item in req:
            if not config.has_option('mail', item):
                raise GeneralError("Mail enabled but missing %s value" % item)
            
            # Break out the recipient list
            if item == 'recipients':
                config['mail']['recipients'] = config.get('mail', 'recipients').split(',')
    else:
        logger.debug("No [mail] section found in %s - Using defaults" % conffile)
        config['mail'] = {'enabled': 'false'}


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
    device = fix_device_patch_nocheck(device)

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


def fetch_device_serial (device):
    """
    Attempt to use camcontrol to fetch the serial number for a given device.
    Returns a string with the trimmed first line of output form the command.
    """
    
    try:
        # Call our serial fetch command replacing {device} with the device path to check
        serial = subprocess.check_output(config['system']['fetch_serial_command'].format(device=device))
    
    except (CalledProcessError, IOError, OSError) as err:
        raise GeneralError("Unable to fetch serial number for %s using the command '%s'.  Error: %s" % (device,config['system']['fetch_serial_command'].format(device=device), err))
    
    # Clean up and ship it
    return serial.splitlines()[0].strip()

    
def split_ctld_config (ctldconfig):
    """
    Given the full text of a ctl.conf file, return a tuple with prefix, target section,
    and postfix text.
    """
    prefix = ""
    postfix = ""

    # Search for the <czs:target> section.  Note - Old Paul would normally build a regex here.
    (prefix, x, target_section) = ctldconfig.partition('# <czs:target>')
    if not x:
        logger.info("No <czs:target> section found in %s" % ctld_conf)
        return (prefix, "", "")
    else:
        (target_section, x, postfix) = target_section.partition('# </czs:target>')
        if not x:
            logger.warning("<czs:target> section missing closing </czs:target> in %s: may be corrupt!" % ctld_conf)
            return (prefix, target_section, "")

    return (prefix, target_section, postfix)


def build_ctld_config (prefix, target_section, postfix):
    """
    Given a prefix, ready built target section, and postfix, return the fill text of
    a new ctl.conf file.
    """
    
    # Fairly simple for now
    return prefix + "# <czs:target>\n" + target_section.strip() + "\n# </czs:target>\n" + postfix

    
def targettext_to_luns (target_section):
    """
    Break a target section into a dictionary of LUN section information.  Uses metadata in the
    file so anything outside of a <czs:lun></czs:lun> section gets ignored.
    """
    
    luns = {}

    # regex to match the XML-like metadata (comments) for a LUN section
    pat = re.compile(r'<czs:lun\s+device=\"([a-z0-9\_\-\/]+)\"\s+id=\"(\d+)\"\s+serial=\"([a-z0-9]*)\"\s+time=\"([0-9 :\-\+a-z]+)\">.+?<\/czs:lun>', re.I | re.S)
    
    for match in pat.finditer(target_section):
        device = match.group(1)
        lunid = match.group(2)
        serial = match.group(3)
        addtime = match.group(4)

        logger.debug("Found LUN section in ctl config for device %s (serial %s) with LUN %s" % (device, serial, lunid))
        luns[lunid] = {}
        luns[lunid]['device'] = device
        luns[lunid]['serial'] = serial
        luns[lunid]['addtime'] = addtime

    return luns


def luns_to_targettext (luns):
    """
    Convert a multidemensional dict of luns into a new target section including lun sections
    for insertion into ctl.conf
    """

    # Build the header.  Note that the "<czs:target>" tags are not added here
    targettemplate = """
# !!! DO NOT MODIFY THE FOLOWING TARGET SECTION !!!
# Automatically generated by {ident}
target {target_name} {
        auth-group {auth_group}
        portal_group {portal_group}

{lunsections}
}
"""

    # Build the template for use with each LUN section
    luntemplate = """
        # <czs:lun device="{device}" id="{lunid}" serial="{serial}" addtime="{addtime}">
        lun {lunid} {
                path {device}
        }
        # </czs:lun>"""

    # Build up our lun sections
    luntext = ""
    for lunid in luns:
        luntext += luntemplate.format(device=luns[lunid]['device'], lunid=lunid, serial=luns[lunid]['serial'], addtime=luns[lunid]['addtime'])

    # Fill out the target section template and send it back
    return targettemplate.format(
        ident=IDENT,
        target_name = config['system']['target_name'],
        auth_group = config['system']['auth_group'],
        portal_group = config['system']['portal_group'],
        lunsections = luntext)


def add_device_to_luns (luns, device):
    """
    Add a new LUN entry for the provided device path.  Returns and updated LUN dict.
    """
    
    # Cleanup the device name and make sure it exists
    t = fix_device_path(device)
    if not t:
        logger.warning("Failed to find device %s - Not adding to LUNs" % device)
        return luns
    device = t

    # Make sure the device is not already in the list
    device_exists = 0
    for lunid in luns:
        if luns[lunid]['device'] == device:
            device_exists = 1
            break

    if device_exists:
        logger.info("Device %s already mapped to LUN %s - Skipping" % (device, lunid))
        return luns

    # Find the lowest free LUN and add a new entry
    for lunid in range(0,255):
        if not lunid in luns:
            # Found one!
            luns[lunid]['device'] = device
            luns[lunid]['serial'] = fetch_device_serial(device)
            luns[lunid]['addtime'] = datetime.datetime.now().isoformat(' ')
            
            return luns

    # No free LUN IDs found.  Not good.
    logger.warning("Unable to map device %s (serial %s) - No free LUNs found" % (device, serial))

    return luns



def remove_device_from_luns (luns, device):
    """
    Remove an existing LUN entry for the provided device path.  Returns an updated LUN dict.
    """

    # Cleanup the device name without checking if it is present. (Because it probably ain't!)
    device = fix_device_path_nocheck(device)

    for lunid in luns:
        if luns[lunid]['device'] == device:
            logger.info("Unmapping device %s (serial %s) from LUN %s" % (device, luns[lunid]['serial'], lunid)) 
            del luns[lunid]

            return luns

    # Device was not mapped.  Note and move along
    logger.info("Could not unmap device %s - Not currently mapped" % device)

    return luns


def ctld_conf_read (ctld_conf):
    """
    Read in current ctld config file, parse, and return a config dict with the following
    keys:
       prefix - Text before the autogenerated target section
       postfix - Text after the autogenerated target section
       luns - Sub-dict with LUN info indexed by LUN ID
    """

    try:
        ctldconfig = open(ctld_conf, 'r').read()

    except (IOError, OSError) as err:
        raise GeneralError("Could not read in %s: %s" % (ctld_conf, err))

    # Parse and return
    logger.debug("Read ctl config file %s" % ctld_conf)

    (prefix, target_section, postfix) = split_ctld_config(ctldconfig)

    luns = targettext_to_luns(target_section)
    
    return (prefix, postfix, luns)
    

def ctld_conf_write (ctld_conf, prefix, postfix, luns):
    """
    Write config file using the provided luns dictionary
    """

    #try:
    #    ctldconfig = open(ctld_conf, 'r').read()
    #
    #except (IOError, OSError) as err:
    #    raise GeneralError("Could not read in %s: %s" % (ctld_conf, err))

    # Parse and return
    #logger.debug("Read ctl config file %s" % ctld_conf)

    #(prefix, target_section, postfix) = ctld_conf_split(ctldconfig)

    #luns = ctld_conf_parse_luns(target_section)
    
    #return (prefix, postfix, luns)
    


def main ():
    # Process CLI args (limited now)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', metavar='ACTION', choices=['attach', 'detach'])
    parser.add_argument('device', metavar='DEVICE')
    parser.add_argument('--config', metavar='CONFIG', default=CONFFILE)
    args = parser.parse_args()

    # Pull in the config
    configure(args.config)

    # Finish logger setup
    format = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
    logger.setLevel(config['system']['level'].upper())

    # Simple console logger
    clog = logging.StreamHandler()
    clog.setFormatter(format)
    logger.addHandler(clog)

    # Syslog
    if config.getboolean('syslog', 'enabled'):
        logger.addHandler(logging.handlers.SysLogHandler(facility=getattr(syslog, config['syslog']['facility'])))
    
    # Email reporting
    if config.getboolean('mail', 'enabled'):
        elog = EmailReportHandler(config['mail']['smtp_server'], config['mail']['sender'], config['mail']['recipients'], config['mail']['subject_prefix'])
        elog.setFormatter(format)
        logger.addHandler(elog)

    # Wrap the remainder - We will log this going forward
    try:
        # Check for other running instances, wait a while, then die out if we can't get a lock
        retries = 6
        waittime = 10
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
    
        # Read in ctl.conf
        print(ctld_conf_read(config['system']['ctld_conf']))

    except GeneralError as detail:
        logger.warning("GeneralError: %s" % detail)
        if config.getboolean('mail', 'enabled'):
            elog.send("FAIL", "GeneralError: %s\r\nPlease review the log and investigate as needed" % detail)
        sys.exit(1)
    
    else:
        logger.info("Completed action \"%s\" on %s" % (args.action, args.device))
        if config.getboolean('mail', 'enabled'):
            elog.send("OK", "")

    exit(0)

if __name__ == '__main__':
    main()
