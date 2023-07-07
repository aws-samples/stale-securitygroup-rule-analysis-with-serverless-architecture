import boto3
import awswrangler as wr
import pandas as pd
import re
import time
import json
import uuid
from datetime import datetime, timedelta
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer

s3 = boto3.resource('s3',"eu-west-2")
dynamodb = boto3.client('dynamodb',"eu-west-2")
ec2 = boto3.client('ec2',"eu-west-2")

regions = ['eu-west-2']

flow_logs_athena_results_bucket="INSERT_ATHENA_QUERY_RESULTS_S3_BUCKET_NAME_HERE"
sg_rules_tbl_name="sg-analysis-rules-data"
dynamodb_tbl_name="sg-analysis-rules-usage"

my_bucket = s3.Bucket(flow_logs_athena_results_bucket)


def get_sg_rule_id(sg_id, sg_name, flow_dir, protocol, dstport, dstport_used_times):
    try:
        protocol_dict = {'6': 'tcp', '27': 'udp', '1': 'icmp', 'any': 'any'}
        key_list = list(protocol_dict.keys())
        val_list = list(protocol_dict.values())
        
        getItemResponse=dynamodb.query(
            TableName=sg_rules_tbl_name,
            IndexName='sgrule',
            KeyConditions={
                "security_group_id":{
                    'ComparisonOperator': 'EQ',
                    'AttributeValueList': [ {"S": str(sg_id)} ]
                }
            },
            FilterExpression='sg_rule_direction = :flow_dir',
            ExpressionAttributeValues= {
                ":flow_dir": {'S':str(flow_dir)}
            }
        )
                
        for respItem in getItemResponse['Items']:
            deserializer = TypeDeserializer()
            deserialized_document = {k: deserializer.deserialize(v) for k, v in respItem.items()}
            if getItemResponse['Count'] == 1:
                print("Security Group rule id is:"+str(deserialized_document['sg_rule_id']))
                insert_usage_data(str(deserialized_document['sg_rule_id']), sg_id, flow_dir, str(deserialized_document['sg_rule_protocol']), dstport_used_times)
            else:
                incProtocol=protocol
                incPort=dstport
                exisProtocol=""
                exisPort=""
                exisSgrId=""
                for k,v in deserialized_document.items():
                    if k == "sg_rule_id":
                        exisSgrId=v
                    if k == "sg_rule_protocol":
                        exisProtocol=v
                    if k == "sg_rule_ports":
                        exisPort=v
                print("Security Group rule id is:"+exisSgrId)
                if '-' in exisPort:
                    startPort,endPort = exisPort.split('-')
                if ((str(incProtocol) == str(key_list[val_list.index(exisProtocol)]) or exisProtocol == "any") and (incPort == exisPort or exisPort == "any" or int(str(startPort).strip()) <= int(incPort) <= int(str(endPort).strip()))):
                    insert_usage_data(exisSgrId, sg_id, flow_dir, exisProtocol, dstport_used_times)
        return getItemResponse
    except Exception as e: 
        print("There was an error while trying to perform DynamoDB get operation on Rules table: "+str(e))
    
def insert_usage_data(sg_rule_id, sg_id, flow_dir, protocol, dstport_used_times):
    try:
        checkRuleIdExists=dynamodb.query(
            TableName=dynamodb_tbl_name,
            KeyConditions={
                "sg_rule_id":{
                    'ComparisonOperator': 'EQ',
                    'AttributeValueList': [ {"S": str(sg_rule_id)} ]
                }
            }
        )
        if checkRuleIdExists['Count'] == 0:
            insertItemResponse = dynamodb.put_item(
              TableName=dynamodb_tbl_name,
              Item={
                    'sg_rule_id': {'S':str(sg_rule_id)},
                    'sg_id': {'S':str(sg_id)},
                    'protocol': {'S':str(protocol)},
                    'used_times': {'N':str(dstport_used_times)},
                    'sg_rule_last_used': {'S':datetime.strftime(datetime.now() - timedelta(1), '%Y-%m-%d')},
                    'flow_direction': {'S':str(flow_dir)}
                }
            )
        else:
            updateItemResponse = dynamodb.update_item(
                TableName=dynamodb_tbl_name,
                Key={
                  'sg_rule_id': {'S': str(sg_rule_id)},
                },
                UpdateExpression='SET used_times = used_times + :newusedtimes, sg_rule_last_used = :newlastused',
                ExpressionAttributeValues={
                    ':newusedtimes': {'N':str(dstport_used_times)},
                    ':newlastused': {'S':datetime.strftime(datetime.now() - timedelta(1), '%Y-%m-%d')}
                },
                ReturnValues="UPDATED_NEW"
            )
    except Exception as e: 
        print("There was an error while trying to perform DynamoDB insert operation on Usage table: "+str(e))

def main():
    for object_summary in my_bucket.objects.filter(Prefix='vpcflowlogs/athena/output/'+datetime.strftime(datetime.now() - timedelta(1), '%Y-%m-%d')+'/'):
         if object_summary.key.endswith('.csv'): 
            # print(object_summary.key)
            file_name = "s3://"+flow_logs_athena_results_bucket+"/"+object_summary.key
            s3_folder_path = "s3://"+flow_logs_athena_results_bucket+"/vpcflowlogs/athena/output/"+datetime.strftime(datetime.now() - timedelta(1), '%Y-%m-%d')+"/"
            start = time.time()
            print("Writing rules data to DynamoDB table- started at: "+str(datetime.now()))
            dfs = wr.s3.read_csv(path=s3_folder_path, chunksize=1000, encoding = 'ISO-8859-1')
            for df in dfs:
                for index, row in df.iterrows():
                    if row is not None and 'dstport' in row:
                        nw_int_info = ec2.describe_network_interfaces(
                            Filters=[
                                {
                                    'Name': 'network-interface-id',
                                    'Values': [
                                        row['interface_id'],
                                    ]
                                },
                            ]
                        )
                    
                        for nwint in nw_int_info['NetworkInterfaces']:
                                for grp in nwint['Groups']:
                                    sg_id=grp['GroupId']
                                    sg_name=grp['GroupName']
                                    
                        print(sg_id, sg_name, row['dstport'],row['port_used_times'],row['protocol'],row['flow_direction'],row['srcaddr'],row['dstaddr'])
                        get_sg_rule_id(sg_id, sg_name, row['flow_direction'],row['protocol'],row['dstport'],row['port_used_times'])
                        # insert_into_dynamodb(sg_id, row['dstport'],row['port_used_times'],row['protocol'],row['flow_direction'],row['srcaddr'],row['dstaddr'])

    
    print("Writing rules data to DynamoDB table- completed at: "+str(datetime.now()))
    end = time.time()
    print("Total time taken in minutes: "+str((end - start)/60))        


if __name__ == "__main__":
    main()