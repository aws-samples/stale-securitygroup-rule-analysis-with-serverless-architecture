import boto3
import awswrangler as wr
import pandas as pd
import re
import time
import json
import uuid
from datetime import datetime, timedelta, date
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from ipaddress import IPv4Address, IPv4Network
from hashlib import sha1

s3 = boto3.resource('s3',"eu-west-2")
dynamodb = boto3.client('dynamodb',"eu-west-2")
ec2 = boto3.client('ec2',"eu-west-2")

regions = ['eu-west-2']

flow_logs_athena_results_bucket="security-group-monitoring-test-bucket-athena"
sg_rules_tbl_name="security-groups"
sg_rules_group_idx = "group_id-index"
nic_interface_tbl="sg-analysis-interface-details"
dynamodb_tbl_name="sg-analysis-rules-usage"
sg_analysis_rules_use_idx='addr-id-index'
athena_s3_prefix = "vpcflowlogs"
date_yst = (date.today() - timedelta(4))

my_bucket = s3.Bucket(flow_logs_athena_results_bucket)

def network_test(rule_block,flow_addr):
    net = IPv4Network(rule_block)
    addr = IPv4Address(flow_addr)
    result = addr in net
    return result


def get_sg_rule_id(sg_id, protocol, flow_dir, srcaddr, srcport, dstaddr, dstport):
    deserializer = TypeDeserializer()
    try:
        protocol_dict = {'6': 'tcp', '27': 'udp', '1': 'icmp', 'any': 'any'}
        key_list = list(protocol_dict.keys())
        val_list = list(protocol_dict.values())
        
        response=dynamodb.query(
            TableName=sg_rules_tbl_name,
            IndexName=sg_rules_group_idx,
            KeyConditions={
                "group_id":{
                    'ComparisonOperator': 'EQ',
                    'AttributeValueList': [ {"S": sg_id} ]
                }
            }
        )
        if flow_dir == 'egress':
            resp_list = [{k: deserializer.deserialize(v) for k, v in r.items()} for r in response['Items'] if r['properties']['M']['IsEgress']['BOOL'] == True]
        else:
            resp_list = [{k: deserializer.deserialize(v) for k, v in r.items()} for r in response['Items'] if r['properties']['M']['IsEgress']['BOOL'] == False]

        for respItem in resp_list:
            try:
                if dstport in range(int(respItem['properties']['FromPort']), int(respItem['properties']['ToPort'])+1) and protocol == respItem['properties']['IpProtocol']:
                    if flow_dir == 'egress':
                        if network_test(rule_block=respItem['properties']['CidrIpv4'],flow_addr=dstaddr):
                            print(f"Security Group rule id is: {respItem['id']}")
                            insert_usage_data(sg_rule_id=respItem['id'],sg_id=sg_id, flow_dir=flow_dir,protocol=respItem['properties']['IpProtocol'],addr=dstaddr,dstport=dstport)
                    elif flow_dir == 'ingress':
                        if network_test(rule_block=respItem['properties']['CidrIpv4'],flow_addr=srcaddr):
                            insert_usage_data(sg_rule_id=respItem['id'],sg_id=sg_id, flow_dir=flow_dir,protocol=respItem['properties']['IpProtocol'],addr=srcaddr,dstport=dstport)
                else:
                    print(f'no rule found for flow')
            except Exception as e:
                print(str(e))
                raise e
        return resp_list
    except Exception as e: 
        print("There was an error while trying to perform DynamoDB get operation on Rules table: "+str(e))
    
def insert_usage_data(sg_rule_id, sg_id, flow_dir, protocol, addr, dstport):
    addr_rule_hash = [sg_rule_id,addr,dstport]
    hash_digest = sha1(str(addr_rule_hash).encode()).hexdigest()
    try:
        checkRuleIdExists=dynamodb.query(
            TableName=dynamodb_tbl_name,
            KeyConditionExpression="sg_rule_id = :sg_rule_id",
            ExpressionAttributeValues={':sg_rule_id':{'S':hash_digest}}
        )
        if checkRuleIdExists['Count'] == 0:
            insertItemResponse = dynamodb.put_item(
              TableName=dynamodb_tbl_name,
              Item={
                    'sg_rule_id': {'S':str(hash_digest)},
                    'rule_id': {'S':sg_rule_id},
                    'sg_id': {'S':str(sg_id)},
                    'flow_direction': {'S':str(flow_dir)},
                    'protocol': {'S':str(protocol)},
                    'addr': {'S':str(addr)},
                    'dstport': {'N':str(dstport)},
                    'used_times': {'N':str(1)},
                    'sg_rule_last_used': {'S':date_yst.strftime('%Y-%m-%d')},
                }
            )
        else:
            updateItemResponse = dynamodb.update_item(
                TableName=dynamodb_tbl_name,
                Key={
                  'sg_rule_id': {'S': str(hash_digest)},
                },
                UpdateExpression='SET used_times = used_times + :val, sg_rule_last_used = :newlastused',
                ExpressionAttributeValues={
                    ':val': {'N':str(1)},
                    ':newlastused': {'S':date_yst.strftime('%Y-%m-%d')}
                },
                ReturnValues="UPDATED_NEW"
            )
    except Exception as e: 
        print("There was an error while trying to perform DynamoDB insert operation on Usage table: "+str(e))

def get_interface_ddb(id:str) -> dict:
    deserialize = TypeDeserializer()
    response = dynamodb.get_item(
        TableName=nic_interface_tbl,
        Key={'id':{'S':id}}
    )
    if 'Item' in response:
        nic_dict = {k: deserialize.deserialize(v) for k, v in response['Item'].items()}
        return nic_dict
    else:
        raise ValueError(f'nic id: {id} not found!')


def main():
    s3_folder_path = f's3://{flow_logs_athena_results_bucket}/{athena_s3_prefix}/{date_yst.isoformat().replace("-","/")}/'
    start = time.time()
    print("Writing rules data to DynamoDB table- started at: "+str(datetime.now()))
    dfs = wr.s3.read_csv(path=s3_folder_path, chunksize=1000, encoding = 'ISO-8859-1')
    for df in dfs:
        try:
            df['protocol'] = df['protocol'].map({6: 'tcp', 17: 'udp', 1: 'icmp'})
            for index, row in df.iterrows():
                if row is not None and 'dstport' in row:
                    nw_int_info = get_interface_ddb(id=row['interface_id'])
                
                    for grp in nw_int_info['security_group_ids']:
                        print(grp, row['protocol'],row['flow_direction'],row['srcaddr'],row['srcport'],row['dstaddr'],row['dstport'])
                        get_sg_rule_id(grp, row['protocol'],row['flow_direction'],row['srcaddr'],row['srcport'],row['dstaddr'],row['dstport'])
        except KeyError:
            pass
        except Exception as e:
            raise e
    
    print("Writing rules data to DynamoDB table- completed at: "+str(datetime.now()))
    end = time.time()
    print("Total time taken in minutes: "+str((end - start)/60))


if __name__ == "__main__":
    main()