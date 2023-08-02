## Stale Security group Rule Analysis with Serverless Architecture

### Architecture

The solution assumes that VPC Flow Logs are enabled and created with Amazon S3 as the destination type. This is based on a serverless architecture that leverages AWS Step Functions to run four Glue Jobs at a scheduled cron interval. The first Glue job parses all of the security groups present in an account and stores them in an Amazon DynamoDB table. The second Glue Job runs Amazon Athena queries to parse the VPC Flow Logs stored in an S3 bucket. The third Glue job computes the usage metrics of rules in security group and stores the results in another DynamoDB table. The parsed data is visualized in QuickSight to generate heat maps to identify which ports/protocols are frequently used.

Finally, the fourth Glue job is used to send an email notification using Amazon Simple Email Service (Amazon SES) client with usage metrics of the security group rule. You can remove these un-used security group rules to meet compliance requirements. This architecture is shown in the following figure.

![image1](https://github.com/aws-samples/stale-securitygroup-rule-analysis-with-serverless-architecture/blob/main/stale-rule.png)

Two DynamoDB tables are created. The first table (sg-analysis-rules-data) stores existing Security Groups and rules information (Security Group ID, Name, Port, Protocol). The second table (sg-analysis-rules-usage) stores the usage counts. It contains information about the Security Group rule ID, Security Group ID, protocol, flow direction, last usage, and the count on the number of times that a rule got used.

The following figure shows the visualization of security group rules in QuickSight. In this example, we’ve filtered the flow log data for the duration of a month. The screenshot shows the heat map representation of security group rules based on flow direction or usage count. The color density increases based on usage count. In the following example, we observe the ingress rule ID (sgr-0a2c6a2a1b919ed46) with usage count of 244 has a color density that differentiates it from other security group rules, such as sgr-04759165217dbcc3b (Ingress) and sgr-01e3d80c29348220d (Egress).

![image2](https://github.com/aws-samples/stale-securitygroup-rule-analysis-with-serverless-architecture/blob/main/visualization-rule-density.png)

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

## Git Submodules
This repoistory contains submodules linking to the aws_network code. Use the commands below to configure:
``git submodule init``
``git submodule update``

You can also checkout to different branches within the aws_network folder for Development purposes

