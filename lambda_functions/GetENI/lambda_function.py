import json
import os
from modules.aws_network.interface import NetworkInterface
from modules.aws_network.export import ExportNetwork
from datetime import datetime
import time
import calendar

exp = ExportNetwork()
nic = NetworkInterface()


def lambda_handler(event, context):
    if os.environ.get('DB_TABLE'):
        
        nic.list_interfaces()
        
        interface_details_list = []
    
        for n in nic.iface_ids:
            interface_details_list.append(nic.get_interface(nic_id=[n]))
        
        for i in interface_details_list:
            try:
                i.attachment_properties['AttachTime']=calendar.timegm(i.attachment_properties['AttachTime'].utctimetuple())
            except:
                pass
    
        # print(interface_details_list)
    
        try:
            response = exp.write_ddb(ddb_table=os.environ['DB_TABLE'],input_list=interface_details_list)
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
    