import json
import boto3
import os
from modules.aws_network.securitygroup import SecurityGroup
from modules.aws_network.export import ExportNetwork

sg_client = SecurityGroup()
export_client = ExportNetwork()

def lambda_handler(event, context):
    
    sg_client.list_security_groups()
    
    # print(sg_client.security_groups)
    
    security_group_list = sg_client.list_security_group_rules()
    
    if os.environ.get('DB_TABLE'):
        try:
            response = export_client.write_ddb(os.environ['DB_TABLE'], security_group_list)
            return response
        except Exception as e:
            error_msg = {
                "message": e.response
            }
            print(error_msg)
            return {
                "message": e.response
            }
    else:
        print("Please set the DB_TABLE Enviroment Variable!")
        return {
            "message": "Please set the DB_TABLE Enviroment Variable!"
        }