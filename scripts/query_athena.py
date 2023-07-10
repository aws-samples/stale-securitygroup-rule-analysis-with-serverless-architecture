import boto3
import pandas as pd
import io
import re
import time
from datetime import datetime, timedelta, date
# Follow this article to create Athena table (to be used in query) that can analyze Amazon VPC Flow Logs - https://aws.amazon.com/premiumsupport/knowledge-center/athena-analyze-vpc-flow-logs/
params = {
    # AWS region to use
    'region': 'eu-west-2',
    # Name of database in glue
    'database': 'glue_db_name',
    # Name of table in glue
    'table': 'athena_table_name',
    # Name of S3 bucket Athena queries go into
    'bucket': 'athena_s3_bucket',
    # Path to use in bucket - no leading or trailing slash
    # e.g. vpcflowlogs/athena
    'path': 'path_to_flow_logs'
}

date_yst = (date.today() - timedelta(1))
params['query'] = f"select interface_id, dstport, count(dstport) port_used_times, protocol, flow_direction, srcaddr, dstaddr FROM {params['database']}.{params['table']} WHERE dstport is not null and day='{date_yst.day}' group by interface_id, dstport, protocol, flow_direction, srcaddr, dstaddr order by port_used_times desc"

session = boto3.Session()
outputLocation='s3://' + params['bucket'] + '/' + params['path'] + '/' + date_yst.isoformat().replace('-','/')

def athena_query(client, params):
    
    print("Starting query execution....")
    print(params["query"])
    response = client.start_query_execution(
        QueryString=params["query"],
        QueryExecutionContext={
            'Database': params['database']
        },
        ResultConfiguration={
            'OutputLocation': outputLocation
        }
    )
    return response


def athena_to_s3(session, params, max_execution = 5):
    client = session.client('athena', region_name=params["region"])
    execution = athena_query(client, params)
    execution_id = execution['QueryExecutionId']
    state = 'RUNNING'

    while (max_execution > 0 and state in ['RUNNING', 'QUEUED']):
        max_execution = max_execution - 1
        response = client.get_query_execution(QueryExecutionId = execution_id)

        if 'QueryExecution' in response and \
                'Status' in response['QueryExecution'] and \
                'State' in response['QueryExecution']['Status']:
            state = response['QueryExecution']['Status']['State']
            if state == 'FAILED':
                return False
            elif state == 'SUCCEEDED':
                s3_path = response['QueryExecution']['ResultConfiguration']['OutputLocation']
                filename = re.findall('.*\/(.*)', s3_path)[0]
                print("Query execution succeeded. Results written to the file "+filename+ " and is stored on "+params["bucket"]+ " bucket and the path "+outputLocation)
                return filename
        time.sleep(1)
    
    return False


def main():
    print("Executing the query to fetch ports and used information from Athena table....")
    # Query Athena and get the Ports information
    ports_count_info = athena_to_s3(session, params)


if __name__ == "__main__":
    main()