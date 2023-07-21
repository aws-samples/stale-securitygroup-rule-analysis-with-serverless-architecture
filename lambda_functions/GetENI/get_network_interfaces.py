from aws_network.interface import NetworkInterface
from aws_network.export import ExportNetwork
from datetime import datetime
import time
import calendar

exp = ExportNetwork()
nic = NetworkInterface('mb_aws','eu-west-2')

nic.list_interfaces()

interface_details_list = []

for n in nic.iface_ids:
    interface_details_list.append(nic.get_interface(nic_id=[n]))

for i in interface_details_list:
    try:
        i.attachment_properties['AttachTime']=calendar.timegm(i.attachment_properties['AttachTime'].utctimetuple())
    except:
        pass

exp.write_ddb(aws_profile='mb_aws',aws_region='eu-west-2',ddb_table='sg-analysis-interface-details',input_list=interface_details_list)