import boto3
import boto3.session
from collections import namedtuple

class SecurityGroup:
    """
    A class used to return details on security groups.

    Attributes
    ----------
    aws_profile: str
        The AWS profile to use - as saved in credential file.
    aws_region: str
        The AWS region to make API calls against
    
    Methods
    -------
    list_security_groups(self, **kwargs)
        Returns a list of namedtuples of security groups in the region
    get_security_group(self, sg_id:list, **kwargs)
        Returns details about the security group specified in sg_id
    list_security_group_rules(self, **kwargs)
        Returns a list of security_group_rules namedtuples
    """

    def __init__(self,aws_profile=None,aws_region=None) -> None:
        if 'aws_profile':
            self.aws_profile = aws_profile
            self.aws_region = aws_region
            self._session = boto3.session.Session(
                profile_name=self.aws_profile,region_name=self.aws_region
            )
        self._client = self._session.client('ec2')

    def list_security_groups(self,**kwargs) -> list:
        """
        Lists security groups in the region.

        Parameters
        ----------
        **kwargs: see boto3 docs
            allows the use of boto3 keyword args for filtering results.
        
        Returns
        -------
        List of security_group namedtuples
        """
        self._security_group = namedtuple('security_group',['name','id','vpc_id'])
        response = self._client.describe_security_groups(**kwargs)
        sg_list = response['SecurityGroups']
        while response.get('NextToken'):
            response = self._client.describe_security_groups(NextToken=response['NextToken'],**kwargs)
            if len(response['SecurityGroups']) > 0:
                sg_list.extend(response['SecurityGroups'])
        self.sg_names = [i['GroupName'] for i in sg_list]
        self.sg_ids = [i['GroupId'] for i in sg_list]
        self.sg_vpc_id = [i['VpcId'] for i in sg_list]
        self.security_groups = [
            self._security_group(
                name=self.sg_names[i],
                id=self.sg_ids[i],
                vpc_id=self.sg_vpc_id[i]
                )
            for i in range(len(self.sg_vpc_id))
        ]

        return self.security_groups

    def get_security_group(self,sg_id:list,**kwargs) -> namedtuple:
        """
        Returns details of a single security group.

        Parameters
        ----------
        sg_id: list
            A single item list containing the group-id of the security group to return details on.
        **kwargs: see boto3 docs
            allows the use of boto3 keyword args for filtering results.
        
        Returns
        -------
        security_group_details namedtuple containing details of the security group provided in sg_id
        """
        self._security_group_details = namedtuple('security_group_details',
            [
                'name',
                'id',
                'vpc_id',
                'ingress_permissions',
                'egress_permissions'
            ],
        )
        self.security_group_id=sg_id
        response = self._client.describe_security_groups(GroupIds=self.security_group_id,**kwargs)['SecurityGroups'][0]
        self.security_group_details = self._security_group_details(
            name=response['GroupName'],
            id=response['GroupId'],
            vpc_id=response['VpcId'],
            ingress_permissions=response['IpPermissions'],
            egress_permissions=response['IpPermissionsEgress']
        )
        
        return self.security_group_details

    def list_security_group_rules(self,**kwargs) -> list:
        """
        Returns list of security group rules.

        Parameters
        ----------
        **kwargs: see boto3 docs
            allows the use of boto3 keyword args for filtering results.
        
        Returns
        -------
        List of security_group_rules containing the security group rules in the region.
        """
        self._security_group_rules = namedtuple('security_group_rules',['id','group_id','properties'])
        response = self._client.describe_security_group_rules(**kwargs)
        sgr_list = response['SecurityGroupRules']
        while response.get('NextToken'):
            response = self._client.describe_security_group_rules(NextToken=response['NextToken'],**kwargs)
            if len(response['SecurityGroupRules']) > 0:
                sgr_list.extend(response['SecurityGroupRules'])
        self.sgr_rule_id = [i['SecurityGroupRuleId'] for i in sgr_list]
        self.sgr_group_id = [i['GroupId'] for i in sgr_list]
        self.security_group_rules = [
            self._security_group_rules(
                id=self.sgr_rule_id[i],
                group_id=self.sgr_group_id[i],
                properties=_sgr_property_parser(sgr_list[i])
            )
            for i in range(len(self.sgr_group_id))
        ]

        return self.security_group_rules

def _sgr_property_parser(sgr_dict):
    for k,v in sgr_dict.items():
        if k == 'SecurityGroupRuleId' or k == 'GroupId':
            pass
        else:
            try:
                props.update({k:v})
            except NameError:
                props = {k:v}
    return props