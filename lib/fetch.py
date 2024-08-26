import json
import boto3
from datetime import datetime, timedelta, timezone
from io import BytesIO
import gzip

class AWSLogFetcher:
    def __init__(self, region_name):
        self.region_name = region_name

    def fetch_logs(self, start_time, end_time):
        raise NotImplementedError("Subclasses should implement this method")
    
    def sort_logs(self, logs, sort_key):
        """
        Sort logs based on the specified sort_key.
        """
        return sorted(logs, key=lambda log: log.get(sort_key, 0))
    
class CloudWatchFetcher(AWSLogFetcher):
    def __init__(self,account_id, region_name, log_group):
        super().__init__(region_name)
        self.client = boto3.client('logs', region_name=region_name)
        self.log_group = log_group

    def fetch_logs(self, start_time, end_time):
        logs = []
        streams = self.client.describe_log_streams(logGroupName=self.log_group)

        def fetch_log_events(stream_name):
            events = self.client.get_log_events(
                logGroupName=self.log_group,
                logStreamName=stream_name,
                startTime=start_time,
                endTime=end_time
            )
            for event in events['events']:
                logs.append(event)

        for stream in streams['logStreams']:
            fetch_log_events(stream['logStreamName'])

        return self.sort_logs([json.loads(log['message']) for log in logs], 'eventTime')

class S3Fetcher(AWSLogFetcher):
    def __init__(self, account_id, region_name, bucket_name):
        super().__init__(region_name)
        self.bucket_name = bucket_name
        self.base_prefix = "AWSLogs/{}/CloudTrail".format(account_id)
        self.regions = self.get_regions()


    def get_regions(self):
        # Fetch all available regions for the EC2 service
        ec2_client = boto3.client('ec2',region_name='us-east-1')
        regions = ec2_client.describe_regions()
        return [region['RegionName'] for region in regions['Regions']]

    def fetch_logs(self, start_time, end_time):
        # Convert Unix timestamp milliseconds to UTC datetime
        start_time = datetime.fromtimestamp(start_time / 1000.0, tz=timezone.utc)
        end_time = datetime.fromtimestamp(end_time / 1000.0, tz=timezone.utc)

        logs = []
        for region in self.regions:
            s3_client = boto3.client('s3', self.region_name)
            start_date = start_time
            while start_date <= end_time:
                date_prefix = start_date.strftime('%Y/%m/%d')
                full_prefix = f"{self.base_prefix}/{region}/{date_prefix}/"

                paginator = s3_client.get_paginator('list_objects_v2')
                pages = paginator.paginate(Bucket=self.bucket_name, Prefix=full_prefix)

                for page in pages:
                    if "Contents" in page:
                        for obj in page['Contents']:
                            if start_time <= obj['LastModified'] <= end_time:
                                response = s3_client.get_object(Bucket=self.bucket_name, Key=obj['Key'])
                                with gzip.GzipFile(fileobj=BytesIO(response['Body'].read())) as gzipfile:
                                    log_content = gzipfile.read().decode('utf-8')
                                    parsed = json.loads(log_content)
                                    if 'Records' in parsed: 
                                        logs.extend(parsed['Records'])
                start_date += timedelta(days=1)
        return self.sort_logs(logs, 'eventTime')

