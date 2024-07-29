#!/usr/bin/env python3

import argparse
import os
import signal
import sys
# import multiprocessing
import threading
from typing import Any, Dict, List, NoReturn
import boto3

# Inner
from lib.metadata import AwsMetadata
from lib.constants import *
from lib.handler import Handler
from lib.utils import start_trail, stop_trail
global region

stop_flag = threading.Event()



def show_version():
    print("extcap {version=%s}{help=https://www.wireshark.org}{display=TrailShark}" % EXTCAP_VERSION)


def show_interfaces():
    print("extcap {version=%s}{help=https://www.wireshark.org}{display=TrailShark}" % EXTCAP_VERSION)
    print("interface {value=cloudtrail}{display=TrailShark}")


def show_dlts():
    print("dlt {number=%d}{name=USER0}{display=TrailShark event}" % DLT_USER1)


class ConfigArg:
    next_id: int = 0
    id_map: Dict[str, int] = {}

    def __init__(self, call: str, display: str, type: str, **kwargs):
        self.number = ConfigArg.next_id
        ConfigArg.next_id += 1
        self.call = call
        ConfigArg.id_map[self.call] = self.number
        self.display = display
        self.type = type
        self.kwargs = kwargs
    
    @classmethod
    def id_from_call(cls, call: str) -> int:
        return cls.id_map[call]
    
    def __str__(self) -> str:
        string = 'arg {number=%d}{call=%s}{display=%s}{type=%s}' % (self.number, self.call, self.display, self.type)
        for arg, val in self.kwargs.items():
            string += '{%s=%s}' % (arg, str(val))
        
        return string


def show_config():
    args: List[ConfigArg] = [
        ConfigArg(call='--profile', display='Profile AWS credentials', type='string', default='default'),
        ConfigArg(call='--region', display='AWS region (Where you deployed trailshark)', type='string', default=DEFAULT_REGION),
        ConfigArg(call='--method', display='Log pulling method (s3 or cloudwatch)', type='string', default=DEFAULT_METHOD),
        ConfigArg(call='--interval', display='Interval between log pulling', type='integer', default=DEFAULT_INTERVAL),
    ]


    for arg in args:
        print(str(arg))


def stop_capture(is_error: bool = False):
    global region
    if STOP_TRAIL:
        stop_trail(region)
    stop_flag.set()
    os._exit(1)

def exit_cb(_signum, _frame):
    stop_capture(is_error=False)

def cloudtrail_capture(args: argparse.Namespace):
    global region
    if args.profile != 'defualt':
        boto3.setup_default_session(profile_name=args.profile)

    # Setup metadata and handler (omitted for brevity)
    region = args.region
    start_trail(region)
    metadata = AwsMetadata()
    handler = Handler(args=args, metadata=metadata,stop_flag=stop_flag, fetcher=args.method, interval=args.interval)

    if not args.fifo:
        raise('no output pipe provided')
    
    signal.signal(signal.SIGINT, exit_cb)
    signal.signal(signal.SIGTERM, exit_cb)

    # Start the process
    thread = threading.Thread(target=handler.main_loop)
    thread.start()

def main():
    parser = argparse.ArgumentParser(prog=os.path.basename(__file__), description='Capture CloudTrail events')

    # extcap arguments
    parser.add_argument('--extcap-interfaces', help='Provide a list of interfaces to capture from', action='store_true')
    parser.add_argument('--extcap-version', help='Shows the version of this utility', nargs='?', default='')
    parser.add_argument('--extcap-config', help='Provide a list of configurations for the given interface', action='store_true')
    parser.add_argument('--extcap-interface', help='Provide the interface to capture from')
    parser.add_argument('--extcap-dlts', help='Provide a list of dlts for the given interface', action='store_true')
    parser.add_argument('--capture', help='Start the capture routine', action='store_true')
    parser.add_argument('--fifo', help='Use together with capture to provide the fifo to dump data to')

    # custom arguments
    parser.add_argument('--profile',default='default', type=str)
    parser.add_argument('--region',default='eu-south-1', type=str)
    parser.add_argument('--method',default='cloudwatch', type=str)
    parser.add_argument('--interval',default=30, type=int)

    args = parser.parse_args()

    if args.extcap_version and not args.extcap_interfaces:
        show_version()
        sys.exit(0)
    
    if args.extcap_interfaces or args.extcap_interface is None:
        show_interfaces()
        sys.exit(0)
    
    if not args.extcap_interfaces and args.extcap_interface is None:
        parser.exit('An interface must be provided or the selection must be displayed')
    
    if args.extcap_config:
        show_config()
    elif args.extcap_dlts:
        show_dlts()
    elif args.capture:
        cloudtrail_capture(args)

    sys.exit(0)


if __name__ == '__main__':
    try:
        main()    
    # any exception needs to be raised
    except Exception as e:
        sys.stderr.write(e)
        sys.stderr.write("Please re-enter a valid profile or validate your AWS credentials, and ensure that you have the necessary policy in place.\n")
        stop_capture(is_error=True)
