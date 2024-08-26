from datetime import datetime, timezone
import struct
from typing import Any, BinaryIO, Dict, List, NoReturn
from botocore.exceptions import ClientError
from lib.constants import *
import boto3 
def get_fake_pcap_header() -> bytearray:
    header = bytearray()
    header += struct.pack('<L', int('a1b2c3d4', 16))
    header += struct.pack('<H', 2)  # Pcap Major Version
    header += struct.pack('<H', 4)  # Pcap Minor Version
    header += struct.pack('<I', 0)  # Timezone
    header += struct.pack('<I', 0)  # Accuracy of timestamps
    header += struct.pack('<L', 0xffffffff)  # Max Length of capture frame
    header += struct.pack('<L', DLT_USER1)  
    return header


def parse_ts(log_parsed: str) -> int:
    # Parse the timestamp and explicitly set it as UTC
    utc_time = datetime.strptime(log_parsed['eventTime'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    # Convert the UTC datetime to a timestamp
    timestamp = int(utc_time.timestamp())
    return timestamp


def write_event(ts: int, event: bytes, extcap_pipe: BinaryIO):
    packet = bytearray()

    caplen = len(event)
    timestamp_secs = ts#int(ts / 1000000000)
    timestamp_usecs = int((ts % 1000000000) / 1000)

    packet += struct.pack('<L', timestamp_secs) # timestamp seconds
    packet += struct.pack('<L', timestamp_usecs)  # timestamp microseconds
    packet += struct.pack('<L', caplen)  # length captured
    packet += struct.pack('<L', caplen)  # length in frame

    packet += event

    extcap_pipe.write(packet)

def get_ssm_parameter(parameter_name, region, decrypt=False):
    """
    Fetches the value of a parameter from AWS SSM Parameter Store.

    Args:
    parameter_name (str): The name of the SSM parameter.
    decrypt (bool): Set to True if the parameter is encrypted and needs to be decrypted.

    Returns:
    str: The value of the parameter.

    Raises:
    Exception: If the parameter cannot be retrieved.
    """
    # Create a session and an SSM client
    ssm_client = boto3.client('ssm', region_name=region)
    
    try:
        # Get the parameter
        parameter = ssm_client.get_parameter(
            Name=parameter_name,
            WithDecryption=decrypt
        )
        return parameter['Parameter']['Value']
    except ClientError as e:
        raise Exception(f"Failed to retrieve SSM parameter {parameter_name}: {e}")


def start_trail(region):
    trail_name = get_ssm_parameter('/trail-shark/trail/name', region=region)

    """Starts the specified AWS CloudTrail trail."""
    client = boto3.client('cloudtrail', region_name=region)
    try:
        response = client.start_logging(Name=trail_name)
    except Exception as e:
        raise Exception(f"Failed to start trail {trail_name}: {str(e)}")

def stop_trail(region):
    trail_name = get_ssm_parameter('/trail-shark/trail/name', region=region)
    
    """Stops the specified AWS CloudTrail trail."""
    client = boto3.client('cloudtrail', region_name=region)
    try:
        response = client.stop_logging(Name=trail_name)
    except Exception as e:
        raise Exception(f"Failed to stop trail {trail_name}: {str(e)}")