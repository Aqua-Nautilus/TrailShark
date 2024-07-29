# TrailShark

## Overview
The TrailShark Capture Utility seamlessly integrates with Wireshark, facilitating the capture of AWS CloudTrail logs directly into Wireshark for near-real-time analysis. This tool can be used for debugging AWS API calls and played a pivotal role in our "Bucket Monopoly Research" project. By leveraging this utility, we were able to understand the internal API calls made by AWS, leading to the discovery of critical vulnerabilities across different services. This insight is invaluable for enhancing security measures and understanding AWS service interactions more deeply.


## Features
- CloudTrail Log Capture: Enables capturing of CloudTrail logs directly from AWS S3 or CloudWatch for comprehensive monitoring. (Tool has the capability )
- Advanced Filtering: Offers custom filters, fields, and color-coding options to highlight interesting or significant events, making analysis more intuitive and efficient.
- Custom Event: Supports the creation of custom events derived from existing ones, allowing for more detailed and targeted analysis of event chains and their impacts.

## Prerequisites
Note: The plugin has been tested on Linux and macOS, but it should work on Windows as well. 

- Wireshark
- Python 3.x
- boto3 library

## Installation
First, deploy the CloudFormation template to create the CloudTrail trail and configure S3 to store logs.

```bash
aws cloudformation create-stack --stack-name TrailShark --template-body aws/template.yaml  --region {REGION}
```

Run the following script to install the wireshark plugin
```bash
./install-plugin.sh
```

## Usage
[Usage Guide](docs/usage.md)

## Contributing
Contributions to this project are welcome. Please ensure to follow the existing code style and add unit tests for any new or changed functionality.


## Known Issues
- Sorting of Events: Events are not automatically sorted due to the inherent delays associated with how CloudTrail logs events. These delays vary depending on the region and the specific AWS service involved. Users can manually sort events using the GUI.
- 1-2 minute delay in event sending due to CloudTrail capabilities (that's why it's near-real-time).
- The tool offers two options for pulling data: S3, which is slower, and CloudWatch, which may experience event losses under stress. Choose the best option for your research.

## External Resources
- [Logray Tool by Sysdig](https://blog.wireshark.org/tag/cloudtrail/) - A heartfelt appreciation to the creators of Logray, a tool developed by Sysdig based on Falco. Their work offers a similar functionality to ours and provides valuable insights into the use of CloudTrail logging. We recognize and commend their innovative approach and contributions to the community.
- [Wireshark](https://github.com/wireshark/wireshark)

## Disclaimer
We created this tool for internal research purposes and decided to share it with the community to provide more options for working with CloudTrail.

## License
[LICENSE](LICENSE)