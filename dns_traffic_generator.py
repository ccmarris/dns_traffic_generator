#!/usr/bin/env python3
#vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
'''

 Description:

    Generate DNS queries based on input file
    Add timing and sequence randomisation

 Requirements:
   Python3 with dnspython

 Author: Chris Marrison

 Date Last Updated: 20220723

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

__version__ = '0.0.2'
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


def build_queries(filename=''):
    '''
    Read the query file and return list of dict

    Args:
      filename (str): Query filename

    Returns:
      list: list of dict [{"query": "fqdn", "qtype": "query type"}]
    '''
    queries = []
    query = {}
    if filename:
        qfile = open_file(filename)
        for line in qfile:
            line = line.rstrip()
            q = line.split()
            query = { "query": q[0], "qtype": q[1]}
            _logger.debug(f'{query}')
            queries.append(query)
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
    for query in qlist:
        time.sleep(random.uniform(0,rtime))
        if dns_query(query['query'], query['qtype']):
            _logger.debug(f'query: {query["query"]}, successful')
            successful += 1
        else:
            _logger.debug(f'query: query["query"], failed')
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


def main(args):
    '''
    Args:
      args (List[str]): command line parameters as list of strings
          (for example  ``["--verbose", "42"]``).
    '''
    sucess = 0
    failed = 0
    config = {}

    args = parse_args(args)
    setup_logging(args.loglevel)
    config = get_config(args.config)

    _logger.info("Reading query file")
    qlist = build_queries(args.queryfile)
    sucess, failed = generate_queries(qlist)
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