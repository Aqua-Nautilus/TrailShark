import boto3

class AwsMetadata:
    def __init__(self):
        self.s3_client = boto3.client('s3')
        self.sts_client = boto3.client('sts')
        self.buckets = self.get_buckets()
        self.username = self.get_username()
        self.account_id = self.get_account_id()

    def get_buckets(self):
        """Retrieve and return a list of bucket names."""
        response = self.s3_client.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        return buckets

    def get_username(self):
        """Retrieve and return the AWS user ARN."""
        try:
            identity = self.sts_client.get_caller_identity()
            return identity['Arn']
        except Exception as e:
            print(f"Error fetching user ARN: {e}")
            exit()

    def get_account_id(self):
        """Retrieve and return the AWS account ID."""
        try:
            identity = self.sts_client.get_caller_identity()
            return identity['Account']
        except Exception as e:
            print(f"Error fetching account ID: {e}")
            exit()