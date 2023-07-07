import boto3
import pandas as pd
import io
import re
import time
from datetime import datetime, timedelta
# Follow this article to create Athena table (to be used in query) that can analyze Amazon VPC Flow Logs - https://aws.amazon.com/premiumsupport/knowledge-center/athena-analyze-vpc-flow-logs/
params = {
    'region': 'eu-west-2',
    'database': 'default',
    'bucket': 'INSERT_ATHENA_QUERY_RESULTS_BUCKET_NAME',
    'path': 'INSERT_ATHENA_QUERY_RESULTS_OUTPUT_PATH- Ex: vpcflowlogs/athena/output',
    'query': 'select interface_id, dstport, count(dstport) port_used_times, protocol, flow_direction, srcaddr, dstaddr FROM "default"."INSERT_ATHENA_VPC_FLOW_LOGS_TABLE" WHERE dstport is not null and day=\'{}\' group by interface_id, dstport, protocol, flow_direction, srcaddr, dstaddr order by port_used_times desc'.format(datetime.strftime(datetime.now()-timedelta(1),"%Y/%m/%d"))
}

session = boto3.Session()
outputLocation='s3://' + params['bucket'] + '/' + params['path'] + '/' + datetime.strftime(datetime.now()-timedelta(1),"%Y-%m-%d")

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