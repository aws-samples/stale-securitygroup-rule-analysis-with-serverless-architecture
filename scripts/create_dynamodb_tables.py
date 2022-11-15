import boto3
import pandas as pd
import datetime
import uuid

region = 'us-west-2'
ec2 = boto3.client("ec2", region)
dynamodb = boto3.client('dynamodb', region)
autoscaling_client = boto3.client('application-autoscaling', region)

sgrules_tbl_name="sg-analysis-rules-data"
ports_usage_tbl_name="sg-analysis-rules-usage"

def create_sg_rules_table():
    response = dynamodb.create_table(
        AttributeDefinitions=[
            {
                'AttributeName': 'sg_rule_id',
                'AttributeType': 'S',
            },
            {
                'AttributeName': 'security_group_id',
                'AttributeType': 'S',
            }
        ],
        KeySchema=[
            {
                'AttributeName': 'sg_rule_id',
                'KeyType': 'HASH',
            },
            {
                'AttributeName': 'security_group_id',
                'KeyType': 'RANGE',
            }
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 5,
            'WriteCapacityUnits': 5,
        },
        TableName=sgrules_tbl_name,
    )
    dynamodb.get_waiter('table_exists').wait(TableName=sgrules_tbl_name)
    print("Security Groups Rules table created")

def create_sg_rules_count_table():
    response = dynamodb.create_table(
        AttributeDefinitions=[
            {
                'AttributeName': 'sg_rule_id',
                'AttributeType': 'S',
            },
            {
                'AttributeName': 'sg_id',
                'AttributeType': 'S',
            },
            {
                'AttributeName': 'protocol',
                'AttributeType': 'S',
            }
        ],
        KeySchema=[
            {
                'AttributeName': 'sg_rule_id',
                'KeyType': 'HASH',
            }
        ],
        GlobalSecondaryIndexes=[
            {
                'IndexName': 'protocol',
                'KeySchema': [
                    {
                        'AttributeName': 'sg_id',
                        'KeyType': 'HASH',
                    },
                    {
                        'AttributeName': 'protocol',
                        'KeyType': 'RANGE',
                    }
                ],
                'Projection': {
                    'ProjectionType': 'ALL'
                },
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 50,
                    'WriteCapacityUnits': 50
                }
            },
        ],

        ProvisionedThroughput={
            'ReadCapacityUnits': 50,
            'WriteCapacityUnits': 50,
        },
        TableName=ports_usage_tbl_name,
    )
    dynamodb.get_waiter('table_exists').wait(TableName=ports_usage_tbl_name)
    
    
    #Read capacity
    autoscaling_client.register_scalable_target(ServiceNamespace='dynamodb',
                                                ResourceId="table/{}".format(ports_usage_tbl_name),
                                                ScalableDimension='dynamodb:table:ReadCapacityUnits',
                                                MinCapacity=50,
                                                MaxCapacity=2000)
    #Write capacity
    autoscaling_client.register_scalable_target(ServiceNamespace='dynamodb',
                                                ResourceId="table/{}".format(ports_usage_tbl_name),
                                                ScalableDimension='dynamodb:table:WriteCapacityUnits',
                                                MinCapacity=50,
                                                MaxCapacity=2000)

    percent_of_use_to_aim_for = 50.0
    scale_out_cooldown_in_seconds = 60
    scale_in_cooldown_in_seconds = 60
    autoscaling_client.put_scaling_policy(ServiceNamespace='dynamodb',
                                        ResourceId="table/{}".format(ports_usage_tbl_name),
                                        PolicyType='TargetTrackingScaling',
                                        PolicyName='ScaleDynamoDBReadCapacityUtilization',
                                        ScalableDimension='dynamodb:table:ReadCapacityUnits',
                                        TargetTrackingScalingPolicyConfiguration={
                                          'TargetValue': percent_of_use_to_aim_for,
                                          'PredefinedMetricSpecification': {
                                            'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'
                                          },
                                          'ScaleOutCooldown': scale_out_cooldown_in_seconds,
                                          'ScaleInCooldown': scale_in_cooldown_in_seconds
                                        })
    autoscaling_client.put_scaling_policy(ServiceNamespace='dynamodb',
                                        ResourceId="table/{}".format(ports_usage_tbl_name),
                                        PolicyType='TargetTrackingScaling',
                                        PolicyName='ScaleDynamoDBWriteCapacityUtilization',
                                        ScalableDimension='dynamodb:table:WriteCapacityUnits',
                                        TargetTrackingScalingPolicyConfiguration={
                                          'TargetValue': percent_of_use_to_aim_for,
                                          'PredefinedMetricSpecification': {
                                            'PredefinedMetricType': 'DynamoDBWriteCapacityUtilization'
                                          },
                                          'ScaleOutCooldown': scale_out_cooldown_in_seconds,
                                          'ScaleInCooldown': scale_in_cooldown_in_seconds
                                        })
                                                
    indexes = ["protocol"]
    for index_name in indexes:
        autoscaling_client.register_scalable_target(ServiceNamespace = "dynamodb",
                                                 ResourceId = "table/sg-analysis-rules-usage/index/{index_name}".format(table_name = ports_usage_tbl_name, index_name = index_name),
                                                 ScalableDimension = "dynamodb:index:ReadCapacityUnits",
                                                 MinCapacity = 50,
                                                 MaxCapacity = 2000)
        autoscaling_client.register_scalable_target(ServiceNamespace = "dynamodb",
                                                 ResourceId = "table/sg-analysis-rules-usage/index/{index_name}".format(table_name = ports_usage_tbl_name, index_name = index_name),
                                                 ScalableDimension = "dynamodb:index:WriteCapacityUnits",
                                                 MinCapacity = 50,
                                                 MaxCapacity = 2000)
        autoscaling_client.put_scaling_policy(ServiceNamespace='dynamodb',
                                        ResourceId = "table/sg-analysis-rules-usage/index/{index_name}".format(table_name = ports_usage_tbl_name, index_name = index_name),
                                        PolicyType='TargetTrackingScaling',
                                        PolicyName='ScaleDynamoDBReadCapacityUtilization',
                                        ScalableDimension='dynamodb:index:ReadCapacityUnits',
                                        TargetTrackingScalingPolicyConfiguration={
                                          'TargetValue': percent_of_use_to_aim_for,
                                          'PredefinedMetricSpecification': {
                                            'PredefinedMetricType': 'DynamoDBReadCapacityUtilization'
                                          },
                                          'ScaleOutCooldown': scale_out_cooldown_in_seconds,
                                          'ScaleInCooldown': scale_in_cooldown_in_seconds
                                        })
        autoscaling_client.put_scaling_policy(ServiceNamespace='dynamodb',
                                        ResourceId = "table/sg-analysis-rules-usage/index/{index_name}".format(table_name = ports_usage_tbl_name, index_name = index_name),
                                        PolicyType='TargetTrackingScaling',
                                        PolicyName='ScaleDynamoDBWriteCapacityUtilization',
                                        ScalableDimension='dynamodb:index:WriteCapacityUnits',
                                        TargetTrackingScalingPolicyConfiguration={
                                          'TargetValue': percent_of_use_to_aim_for,
                                          'PredefinedMetricSpecification': {
                                            'PredefinedMetricType': 'DynamoDBWriteCapacityUtilization'
                                          },
                                          'ScaleOutCooldown': scale_out_cooldown_in_seconds,
                                          'ScaleInCooldown': scale_in_cooldown_in_seconds
                                        })

    print("Security Groups Ports Usage table created")
    
def main():
    try:
        rulesTable = dynamodb.describe_table(TableName=sgrules_tbl_name)
        print("Security Groups Rules table already exists...")
    except dynamodb.exceptions.ResourceNotFoundException:
        create_sg_rules_table()
    
    try:
        usageTable = dynamodb.describe_table(TableName=ports_usage_tbl_name)
        print("Security Groups Ports Usage table already exists...")
    except dynamodb.exceptions.ResourceNotFoundException:
        create_sg_rules_count_table()
    

if __name__ == "__main__":
    main()