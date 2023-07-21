import csv
from typing import NamedTuple
import boto3
import json
from boto3.dynamodb.types import TypeSerializer

class ExportNetwork:
    """
    A class to export aws_network resources to a file.

    Methods
    -------
    export_csv(self,out_file:str,input_list:list[NamedTuple],mode:str)
        method to export resources to a csv

    write_ddb(self,aws_profile:str,aws_region:str,ddb_table:str,input_list:list[NamedTuple])
        method to write resource to dynamodb table ddb_table
    """


    def __init__(self) -> None:
        pass

    def export_csv(self,out_file:str,input_list:list[NamedTuple],mode:str='a') -> dict:
        """
        exports resources in "input_list" resources to csv file "out_file"

        Parameters
        ----------
        out_file: str
            file path and file name to export resources to
        input_list: list[NamedTuple]
            list of resources in namedtuple format as returned by modules
            in this package
        mode: str
            the write mode to use. defaults to 'a' for append to file 
        
        Returns
        -------
        message
            returns dict formated status message on successful write
        exception
            returns error message if unable to write to file
        """
        self.out_file = out_file
        dict_list = [i._asdict() for i in input_list]
        try:
            with open(self.out_file,mode) as f:
                writer = csv.DictWriter(f,dict_list[0].keys())
                writer.writeheader()
                writer.writerows(dict_list)
            return {'state':f'wrote to file: {self.out_file}'}
        except Exception as e:
            return e
    
    def write_ddb(self,ddb_table:str,input_list:list[NamedTuple],aws_profile:str=None,aws_region:str=None) -> dict:
        """
        writes resources in "input_list" to DynamoDB table "ddb_table"

        Parameters
        ------
            aws_profile: str
                aws profile to authenticate with, must have permissions to r/w to DynamoDB table
            aws_region: str
                the aws region the DynamoDB table is in
            ddb_table: str
                the name of the DynamoDB table to write to
            input_list: list[NamedTuple]
                list of resources in namedtuple format as returned by modules
                in this package

        Returns
        ------
        response
            response from DynamoDB api
        exception
            returns exception if failed at any stage
        """
        self.aws_profile = aws_profile
        self.aws_region = aws_region
        self._session = boto3.session.Session(
            profile_name=self.aws_profile,region_name=self.aws_region)
        self._client = self._session.client('dynamodb')
        self.ddb_table = ddb_table
        seraliser = TypeSerializer()

        dict_list = [i._asdict() for i in input_list]

        try:
            for i in dict_list:
                ddb_dict = {k: seraliser.serialize(v) for k,v in i.items()}
                response = self._client.put_item(
                    TableName=self.ddb_table,
                    Item=ddb_dict
                )
            return response
        except Exception as e:
            raise e