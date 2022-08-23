#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Generate DNS queries based on input file
    Add timing and sequence randomisation

 Requirements:
   Python3 with dnspython

 Author: Chris Marrison

 Date Last Updated: 20220823

 Todo:

 Copyright (c) 2022 Chris Marrison / Infoblox

 Redistribution and use in source and binary forms,
 with or without modification, are permitted provided
 that the following conditions are met:

 1. Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright
 notice, this list of conditions and the following disclaimer in the
 documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

'''
import argparse
import logging
import sys
import os
import dns.resolver
import random
import time
import yaml
import datetime
import tqdm

__version__ = '0.1.1'
__copyright__ = "Chris Marrison"
__author__ = 'Chris Marrison'
__author_email__ = 'chris@infoblox.com'
__license__ = 'BSD-2-Clause'

_logger = logging.getLogger(__name__)


def parse_args(args):
    """Parse command line parameters

    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--help"]``).

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(description="Generate suedo DNS traffic")
    parser.add_argument(
        "--version",
        action="version",
        version="dns_traffic_generator {ver}".format(ver=__version__),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="loglevel",
        help="set loglevel to INFO",
        action="store_const",
        const=logging.INFO,
    )
    parser.add_argument(
        "-vv",
        "--very-verbose",
        dest="loglevel",
        help="set loglevel to DEBUG",
        action="store_const",
        const=logging.DEBUG,
    )

    parser.add_argument('-c', '--config', type=str, default='config.yml',
                        help="Overide Config file")
    parser.add_argument('-q', '--queryfile', type=str, default='sample_queries',
                        help="Query input file")
    parser.add_argument('-f', '--queryformat', type=str, default='queryperf',
                        choices=['queryperf', 'bind'],
                        help="Query input file format")
    parser.add_argument('-r', '--runonce', action='store_true',
                        help="Run query set once, ignoring schedule")

    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(
        level=loglevel, stream=sys.stdout, format=logformat, datefmt="%Y-%m-%d %H:%M:%S"
    )
    return


def get_config(cfg):
    '''
    '''
    config = {}

    if os.path.isfile(cfg):
        # Attempt to open yaml config file 
        try:
            config = yaml.safe_load(open(cfg, 'r'))
        except yaml.YAMLError as err:
            _logger.error(err)
            raise
    else:
        _logger.error('No such file {}'.format(cfg))
        raise FileNotFoundError(f'Config file "{cfg}" not found.')

    return config


def open_file(filename):
    '''
    Attempt to open output file

    Parameters:
        filename (str): desired filename

    Returns file handler
        handler (file): File handler object
    '''
    if os.path.isfile(filename):
        try:
            handler = open(filename, mode='r')
            _logger.info("Successfully opened input file {}.".format(filename))
        except IOError as err:
            _logger.error("{}".format(err))
            handler = False
    else:
        _logger.error(f'Queryfile: {filename} does not exist')
        handler = False

    return handler


def build_queries(filename='', format='queryperf'):
    '''
    Read the query file and return list of dict

    Args:
      filename (str): Query filename
      plain (str): File format [ 'queryperf', ['bind']]

    Returns:
      list: list of dict [{"query": "fqdn", "qtype": "query type"}]
    '''
    count = 0
    formats = [ 'queryperf', 'bind' ]
    queries = []
    query = {}
    if filename and format in formats:
        if format == 'queryperf':
            qfile = open_file(filename)
            for line in qfile:
                count += 1
                line = line.rstrip()
                q = line.split()
                if len(q) == 2:
                    query = { "query": q[0], "qtype": q[1]}
                    _logger.debug(f'{query}')
                    queries.append(query)
                else:
                    _logger.debug(f'Error line {count}: {line}')
        elif format == 'bind':
            qfile = open_file(filename)
            for line in qfile:
                count += 1
                line = line.rstrip()
                if 'query:' in line:
                    q = line.split()
                    try:
                        qindex = q.index('query:')
                        query = { "query": q[qindex+1], 
                                  "qtype": q[qindex+2]}
                        _logger.debug(f'{query}')
                        queries.append(query)
                    except ValueError:
                        _logger.debug(f'Error line {count}: {line}')
        else:
            _logger.debug(f'Log file format error')
                
    else:
        # Gen Test query
        queries = [ { "query": "www.google.com", "qtype": "a" },
                    { "query": "www.infoblox.com", "qtype": "a" },
                    { "query": "failme.infoblox.com", "qtype": "a" },
                    { "query": "csp.infoblox.com", "qtype": "a" } ]

    return queries


def generate_queries(qlist, rtime=11):
    '''
    '''
    successful = 0
    failed = 0

    random.shuffle(qlist)
    _logger.info(f'Generating {len(qlist)} queries')

    with tqdm.tqdm(total=len(qlist)) as pbar:
        for query in qlist:
            # Update progress bar
            pbar.update(1)
            # Wait random time and generate query
            time.sleep(random.uniform(0,rtime))
            if dns_query(query['query'], query['qtype']):
                _logger.debug(f'query: {query["query"]}, successful')
                successful += 1
            else:
                _logger.debug(f'query: {query["query"]}, failed')
                failed += 1

    return successful, failed


def dns_query(query, qtype='A'):
    '''
    '''
    status = False
    try: 
        answers = dns.resolver.resolve(query, qtype)
        status = True
        for rdata in answers:
            _logger.debug(f'{rdata}')
    except:
        _logger.debug(f'Resolution failed')
        status = False

    return status


def scheduled(config):
    '''
    '''
    scheduled = False
    days_of_week = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ]

    if 'schedule' in config.keys():
        if config['schedule'].get('continuous'):
            _logger.debug('Continuous schedule')
            scheduled = True
        else:
            now = datetime.datetime.now()
            # Check weekday
            week_day = days_of_week[now.weekday()]
            if week_day in config['schedule'].get('days_of_week'):
                _logger.debug(f'{week_day} in schedule')
                # Get start and end times
                if config['schedule'].get('start_time'):
                    start_time = convert_to_delta(config['schedule'].get('start_time'))
                else:
                    # Set to midnight
                    start_time = convert_to_delta('0000')
                if config['schedule'].get('end_time'):
                    end_time = convert_to_delta(config['schedule'].get('end_time'))
                else:
                    end_time = convert_to_delta('2359')

                # Check time schedule
                current_time = convert_to_delta(now.strftime('%H%M'))
                if start_time < current_time < end_time:
                    _logger.debug(f'{now.strftime("%H:%M")} within time window')
                    scheduled = True
                else:
                    _logger.debug(f'{now.strftime("%H:%M")} outside time window')
                    scheduled = False
            else:
                _logger.debug(f'Not scheduled for today in schedule')
                scheduled = False
    else:
        _logger.warning("No schedule defined")
        
    return scheduled


def wait_for_schedule(config):
    '''
    '''
    status = False 
    wait = 0
    days_of_week = [ 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' ]

    if 'schedule' in config.keys():
        now = datetime.datetime.now()
        now_time = now.time()   
        # Check weekday
        week_day = days_of_week[now.weekday()]
        # Get start and end times
        if config['schedule'].get('start_time'):
            start_delta = convert_to_delta(config['schedule'].get('start_time'))
        else:
            # Set to midnight
            start_delta = convert_to_delta('0000')
        if config['schedule'].get('end_time'):
            end_delta = convert_to_delta(config['schedule'].get('end_time'))
        else:
            end_delta = convert_to_delta('2359')
        
        now_delta = datetime.timedelta(hours=now_time.hour,
                                        minutes=now_time.minute,
                                        seconds=now_time.second )
        wait = calc_wait(now_delta, start_delta, end_delta)

        if week_day in config['schedule'].get('days_of_week'):
            _logger.debug(f'{week_day} in schedule')
        else:
            _logger.debug(f'{week_day} not in schedule - try tomorrow')

        # Sleep time
        _logger.info(f'Waiting for next schedule: {wait} until next attemp.')
        time.sleep(wait.total_seconds())
        status = True

    else:
        _logger.warning("No schedule defined - exiting")

    return status


def convert_to_delta(stime):
    '''
    Convert basic string time 'HHMM' to datetime.timedelta()

    Parameters:
        st (str): Simple time in 24h 'HHMM' format
    
    Returns:
        datetime.time() object
    '''
    stime = str(stime)
    hours = int(stime[:-2])
    minutes = int(stime[2:])
    t = datetime.time(hours, minutes)
    return datetime.timedelta(hours=t.hour, minutes=t.minute, seconds=t.second)


def calc_wait(ntime, stime, etime):
    '''
    '''
    wait = 0

    day = datetime.timedelta(days=1)
    if ntime < stime:
        wait = stime - ntime
    elif ntime > etime:
        # Wait until st tomorrow
        wait = day - ntime + stime
    else:
        wait = datetime.timedelta(seconds=0)
    
    _logger.debug(f'Wait time: {wait}')
    
    return wait


def main(args):
    '''
    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--verbose", "42"]``).
    '''
    run = True
    sucess = 0
    failed = 0
    config = {}

    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.info("Reading configuration")
    config = get_config(args.config)
    rtime = config.get('rtime') if config.get('rtime') else 11
    _logger.debug(f'Random time interval set to {rtime} seconds')

    _logger.info("Reading query file")
    qlist = build_queries(args.queryfile, format=args.queryformat)

    if not args.runonce:
        while run:
            if scheduled(config):
                _logger.info("Executing queries")
                sucess, failed = generate_queries(qlist, rtime=rtime)
                _logger.info(f'Successful queries: {sucess}, Failed queries: {failed}')
            else:
                _logger.info("Not currently scheduled")
                run = wait_for_schedule(config)
            
            if run:
                # Wait for random period before continuing
                wait = random.randint(1,21)
                _logger.debug(f'Waiting {wait} seconds...')
                time.sleep(wait)
    else:
        _logger.info("Ignoring schedule: Executing queries")
        sucess, failed = generate_queries(qlist, rtime=rtime)
        _logger.info(f'Successful queries: {sucess}, Failed queries: {failed}')

    return


def run():
    """Calls :func:`main` passing the CLI arguments extracted from :obj:`sys.argv`

    This function can be used as entry point to create console scripts with setuptools.
    """
    main(sys.argv[1:])

# *** Main ***
if __name__ == "__main__":
    # ^  This is a guard statement that will prevent the following code from
    #    being executed in the case someone imports this file instead of
    #    executing it as a script.
    #    https://docs.python.org/3/library/__main__.html

    # After installing your project with pip, users can also run your Python
    # modules as scripts via the ``-m`` flag, as defined in PEP 338::
    #
    #     python -m dns_traffic_generator.skeleton 42
    #
    run()
