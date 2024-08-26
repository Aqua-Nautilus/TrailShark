import json
import sys
from datetime import datetime, timezone
import time
from lib.fetch import CloudWatchFetcher, S3Fetcher
import json
import sys
from lib.utils import get_ssm_parameter, write_event, parse_ts, get_fake_pcap_header

class Handler:
    def __init__(self, args, metadata,stop_flag, fetcher = 'cloudwatch', interval=30):
        self.interval = interval
        self.stop_flag = stop_flag
        self.args = args
        self.metadata = metadata
        self.bucket_name = get_ssm_parameter('/trail-shark/bucket/name', region=args.region)


        # CONST
        if fetcher == 'cloudwatch':
            log_group_name = get_ssm_parameter('/trail-shark/loggroup/name', region=args.region)
            self.fetcher = CloudWatchFetcher(account_id=metadata.account_id, region_name=args.region, log_group=log_group_name)
        elif fetcher == 's3':
            self.fetcher = S3Fetcher(account_id=metadata.account_id, region_name=args.region, bucket_name=self.bucket_name)
        else:
            raise "Wrong Fetcher"
        self.extcap_pipe_f = open(args.fifo, 'wb')
        self.init_timestamp = self.write_initial_event()


    def write_event(self, timestamp, data):
        try:
            write_event(timestamp, data, self.extcap_pipe_f)
            self.extcap_pipe_f.flush()
        except Exception as e:
            sys.stderr.write(str(e))
            self.stop_flag.set()

    def write_initial_event(self):
        self.extcap_pipe_f.write(get_fake_pcap_header())
        current_user = self.metadata.username
        init_log = {
            'eventName': 'Initial Event',
            'eventTime': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'userIdentity': {
                'arn': current_user,
                'name': current_user.split('/')[-1]
            },
        }
        init_timestamp = parse_ts(init_log)
        self.write_event(init_timestamp, json.dumps(init_log).encode())
        return init_timestamp

    def main_loop(self):
        end_time = int(datetime.now().timestamp() * 1000)  # Current time in milliseconds
        while not self.stop_flag.is_set():
            start_time, end_time = end_time, int(datetime.now().timestamp() * 1000)
            logs = self.fetcher.fetch_logs(start_time, end_time)

            for log in logs:
                log_parsed = (log)
                log_timestamp = parse_ts(log_parsed)
                if log_timestamp < self.init_timestamp:
                    continue
                if log_parsed.get('eventName') in ['ListStacks', 'DescribeLogStreams', 'GetLogEvents']:
                    continue
                parameters = log_parsed.get('requestParameters')
                if parameters and parameters.get("bucketName") and parameters["bucketName"] == self.bucket_name:
                    continue
                self.enrich(log_parsed=log_parsed)
                self.write_event(log_timestamp, json.dumps(log_parsed).encode())
                self.handle_custom_events(log_parsed=log_parsed, log_timestamp=log_timestamp)
            time.sleep(self.interval)

    def enrich(self, log_parsed):
        if log_parsed.get('userIdentity', {}).get('arn') == self.metadata.username:
            log_parsed['madeByRecorder'] = 1
        else:
            log_parsed['madeByRecorder'] = 0
        if (log_parsed['madeByRecorder'] and 
            (log_parsed['userAgent'].endswith('com') or log_parsed['userAgent'] == 'AWS Internal')) or \
        (log_parsed['eventSource'].endswith('com') and 
            log_parsed['sourceIPAddress'].endswith('com') and 
            log_parsed['sourceIPAddress'] != log_parsed['eventSource']):
            log_parsed['derivativeEvent'] = 1
        else:
            log_parsed['derivativeEvent'] = 0




    def handle_custom_events(self, log_parsed, log_timestamp):

        parameters = log_parsed.get('requestParameters')
        if parameters and parameters.get("bucketName") and parameters["bucketName"] not in self.metadata.buckets:
            self.metadata.buckets.append(parameters["bucketName"])
            unknown_bucket_event = json.dumps({
                'eventName': "UnknownBucket(Rule)",
                'requestParameters': parameters["bucketName"],
                'madeByRecorder': log_parsed['madeByRecorder']
            }).encode()
            self.write_event(log_timestamp, unknown_bucket_event)

