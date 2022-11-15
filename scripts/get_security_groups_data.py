import sys
sys.path.insert(0, '/glue/lib/installation')
keys = [k for k in sys.modules.keys() if 'boto' in k]
for k in keys:
    if 'boto' in k:
       del sys.modules[k]

import boto3
print('boto3 version')
print(boto3.__version__)
import pandas as pd
import datetime
import uuid

ec2 = boto3.client("ec2", "us-west-2")
dynamodb = boto3.client('dynamodb', "us-west-2")

regions = ['us-west-2']
dynamodb_tbl_name="sg-analysis-rules-data"

# Get rules from SG
def get_rules(sg, region):
    ec2r = boto3.client("ec2", region)
    sgs = ec2r.describe_security_group_rules(
        Filters= [ {
            'Name': 'group-id',
            'Values': [
                    sg,
                ]
            }
        ]
    )
    return sgs["SecurityGroupRules"]

# Get available SGs
def get_sgs(instance):
    sgs = instance.security_groups
    return sgs


# Get instance name
def get_name(instance):
    if instance.tags:
        for tag in instance.tags:
            if tag["Key"] == "Name":
                return tag["Value"]
    else:
        return "None"

# Insert rule into DynamoDB
def insert_into_dynamodb(region, sg_name, sg_id, rule_id, direction, from_cidr, protocol, ports):
    print("Processing rule: "+region +"-"+ sg_name+"-"+ sg_id+"-"+rule_id+"-"+ direction+"-"+ str(from_cidr)+"-"+ protocol+"-"+ str(ports))
    response = dynamodb.put_item(
    TableName=dynamodb_tbl_name,
    Item={
        'sg_rule_id': {'S':str(rule_id)},
        'security_group_id': {'S':sg_id},
        'sg_rule_ports': {'S':str(ports)},
        'sg_rule_protocol': {'S':protocol},
        'sg_rule_direction': {'S':direction},
        'security_group_region': {'S':region},
        'security_group_name': {'S':sg_name},
        'security_group_src': {'S':str(from_cidr)}
    }
    )
    return response
        

def delete_sg_rules_table():
    dynamodb.delete_table(TableName=dynamodb_tbl_name)
    dynamodb.get_waiter('table_not_exists').wait(TableName=dynamodb_tbl_name)
    print ("Security Groups Rules table deleted")

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
            },
            {
                'AttributeName': 'security_group_name',
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
                'IndexName': 'sgrule',
                'KeySchema': [
                    {
                        'AttributeName': 'security_group_id',
                        'KeyType': 'HASH',
                    },
                    {
                        'AttributeName': 'security_group_name',
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
        TableName=dynamodb_tbl_name,
    )
    dynamodb.get_waiter('table_exists').wait(TableName=dynamodb_tbl_name)
    print("Security Groups Rules table created")
    
def main():
    try:
        response = dynamodb.describe_table(TableName=dynamodb_tbl_name)
        delete_sg_rules_table()
        create_sg_rules_table()
    except dynamodb.exceptions.ResourceNotFoundException:
        create_sg_rules_table()
   
    table = []
    columns = [
        "Region",
        "SG-Name",
        "SG-ID",
        "Rule-ID",
        "Direction",
        "Source",
        "Destination",
        "Protocol",
        "Ports",
    ]
    df = pd.DataFrame(table, columns=columns)
    print("Collecting Security Groups information from every region....")
    
    for region in regions:
        ec2r = boto3.resource("ec2", region)
        ec2=boto3.client('ec2', region)
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            # print(sg)
            sg_id = sg["GroupId"]
            sg_name = sg["GroupName"]
            # rule_destination = inst_id
            rules = get_rules(sg_id, region)
            # print(rules)
            for rule in rules:
                # print(rule["SecurityGroupRuleId"])
                rule_id = rule["SecurityGroupRuleId"]
                direction = "egress" if rule["IsEgress"] else "ingress"
                from_port_range = rule["FromPort"]
                to_port_range = rule["ToPort"]
                if from_port_range == to_port_range:
                    ports = from_port_range
                else:
                    ports = str(from_port_range) + " - " + str(to_port_range)
                if from_port_range == -1:
                    ports = "any"
                protocol = rule["IpProtocol"]
                if protocol == "-1":
                    protocol = "any"
                
                from_cidr = []
                if 'CidrIpv4' in rule:
                    from_cidr.append(rule["CidrIpv4"])
                if 'CidrIpv6' in rule:
                    from_cidr.append(rule["CidrIpv6"])
                if 'PrefixListId' in rule:
                    from_cidr.append(rule["PrefixListId"])
                if 'ReferencedGroupInfo' in rule:
                    from_cidr.append(rule["ReferencedGroupInfo"]["GroupId"])
            
                insert_into_dynamodb(region, sg_name, sg_id, rule_id, direction, from_cidr, protocol, ports)
                

    print("Security Group rules check run completed at:"+datetime.datetime.now().strftime("%H-%M-%S_%d-%m-%Y"))
    return "Success"


if __name__ == "__main__":
    main()