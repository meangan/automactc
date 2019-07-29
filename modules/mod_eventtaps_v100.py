#!/usr/bin/env python

'''
@ author: Megan Andersen
@ email: mego888@gmail.com, megan.andersen@crowdstrike.com

@ purpose:

A module intended to parse event taps.

'''
from __main__ import data_writer

import Quartz
import csv
import logging
import os
from collections import OrderedDict

_modName = __name__.split('_')[-2]
_modVers = '.'.join(list(__name__.split('_')[-1][1:]))
log = logging.getLogger(_modName)

def module():
	headers = ['tapID', 'tap_point', 'options', 'event_interest',
               'tapping_process', 'process_tapped', 'enabled']
	output = data_writer(_modName, headers)

	try:
		temp = Quartz.CGGetEventTapList(10,None,None)
		taps = str(temp[1]).split(',')[1:]
		log.debug("Success. Captured event tap list.")
	except IOError:
		log.error("Couldn't grab event taps.")
		taps = []

	log.debug("Parsing event taps.")
	for i in range(len(taps)):
		events = taps[i].split(' ')
		record = OrderedDict((h, '') for h in headers)

		record['tapID'] = events[2].rsplit('=',1)[1]
		record['tap_point'] = events[3].rsplit('=',1)[1]
		record['options'] = events[4].rsplit('=',1)[1]
		record['event_interest'] = events[5].rsplit('=',1)[1]
		record['tapping_process'] = events[6].rsplit('=',1)[1]
		record['process_tapped'] = events[7].rsplit('=',1)[1]
		record['enabled'] = events[8].rsplit('=',1)[1]

		output.write_entry(record.values())

	log.debug("Done.")




if __name__ == "__main__":
    print "This is an AutoMacTC module, and is not meant to be run stand-alone."
    print "Exiting."
    sys.exit(0)
else:
    module()