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
# Requires Python 3
##

VERSION = "v0.1 (2014-11-05)"

# General imports
import sys, os, errno, traceback, time, re, datetime

# Logging and alerting
import signal, logging, logging.handlers, smtplib, email, syslog

# Configuration handling
import configparser, argparse

# Default location of config
CONFFILE = "/etc/czs-targetcontrol.conf"

# Create our global config dict
config = configparser.ConfigParser()


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
    config file.
    Based on recipe from http://code.activestate.com/recipes/546512-creating-a-single-
instance-application-linux-versi/
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

        if not self.lasterror:
            # Write out new pid file
            fp = open(pidPath, 'w')
            fp.write(str(os.getpid()))
            fp.close()

    def alreadyrunning(self):
        return self.lasterror

    def __del__(self):
        if not self.lasterror:
            os.unlink(self.pidPath)


def configure (conffile):
    """
    Read configuration file into the global config dictionary
    """

    # Read in the config and perish if nothing is read
    conffiles_read = config.read(conffile)
    
    if not len(conffiles_read):
        raise GeneralError("No configuration read from %s - EXITING" % conffile)


    # Sanity check log settings
    if 'log' in config:
        
        # Replace facility with the proper code
        if not re.match('user|daemon|syslog|local[0-7]', config.get('log', 'facility', fallback='daemon')):
            raise GeneralError("Invalid log facility %s in %s - Must be user, daemon, syslog, or local 0-7" % (config.get('log', 'facility'), conffile))

        # Replace with syslog facility
        config['log']['facility'] = 'LOG_' + config.get('log', 'facility', fallback='daemon').upper()

        if not re.match('debug|info|warning|error|critical', config.get('log', 'level', fallback='info')):
            raise GeneralError("Invalid log level %s in %s - Must be debug, info, warning, error, or critical" % (config.get('log', 'level'), conffile))
        config['log']['level'] = config.get('log', 'level', fallback='info')
    else:
        config['log'] = {}
        config['log']['enabled'] = 'false'
        config['log']['level'] = 'LOG_INFO'
        config['log']['ident'] = 'czs-targetcontrol'


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
        config['mail'] = {'enabled': 'false'}

    if 'system' in config:
        config['system']['czstc_pid'] = config.get('system', 'czstc_pid', fallback='/var/run/czs-targetcontrol.pid')
        config['system']['ctld_conf'] = config.get('system', 'ctld_conf', fallback='/etc/ctl.conf')
        config['system']['ctld_pid'] = config.get('system', 'ctld_pid', fallback='/var/run/ctld.pid')
    else:
        config['system'] = {}
        config['system']['czstc_pid'] = '/var/run/czs-targetcontrol.pid'
        config['system']['ctld_conf'] = '/etc/ctl.conf'
        config['system']['ctld_pid'] = '/var/run/ctld.pid'


def ctld_conf_read (ctld_conf):
    """
    Read in current ctld config file
    """

    try:
        ctldconfig = open(ctld_conf, 'r').read()

    except (IOError, OSError) as err:
        raise GeneralError("Could not read in %s: %s" % (ctld_conf, err))

    return ctldconfig


def main ():
    # Process CLI args (limited now)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', metavar='ACTION', choices=['attach', 'detach'])
    parser.add_argument('device', metavar='DEVICE')
    parser.add_argument('--config', metavar='CONFIG', default=CONFFILE)
    args = parser.parse_args()

    # Pull in the config
    configure(args.config)

    # Setup logging
    format = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')

    logger_level = config['log']['level']
    logger_ident = config['log']['ident']

    # Simple console logger
    logger = logging.getLogger(config['log']['ident'])
    clog = logging.StreamHandler()
    clog.setFormatter(format)
    logger.addHandler(clog)

    # Syslog
    if config.getboolean('log', 'enabled'):
        logger.addHandler(logging.handlers.SysLogHandler(facility=getattr(syslog, config['log']['facility'])))
    
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
    
    except GeneralError as detail:
        logger.warning("GeneralError: %s" % detail)
        if config.getboolean('mail', 'enabled'):
            elog.send("FAIL", "GeneralError: %s\r\nPlease review the log and investigate as needed" % detail)
        sys.exit(1)
    
    else:
        logger.info("Completed action %s on %s" % (args.action, args.device))
        if config.getboolean('mail', 'enabled'):
            elog.send("OK", "")

    exit(0)

if __name__ == '__main__':
    main()
