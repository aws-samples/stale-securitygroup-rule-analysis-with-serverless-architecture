import csv
import boto3
import json
import pandas as pd
import email
from boto3.dynamodb.conditions import Key, Attr, And
from datetime import datetime, date, timedelta
from dateutil.relativedelta import relativedelta
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

region="us-west-2"
ses_client = boto3.client('ses', region)
s3_resource = boto3.resource('s3', region)
s3 = boto3.client("s3")

dynamodb = boto3.resource('dynamodb',"us-west-2")
dynamodb_tbl_name = dynamodb.Table('ports-usage-dummy')

s3_bucket = "INSERT_S3_BUCKET_NAME_HERE"
s3_analysis_file_key="sg-analysis/email-reports/"

def emailFile():
    SENDER = "INSERT_SENDER_EMAIL-sender@sender.com"
    RECIPIENT = "INSERT_RECEIVER_EMAIL-receiver@receiver.com"
    
    last_month = datetime.now() - relativedelta(months=1)
    month_year = format(last_month, '%B_%Y')
    usage_analysis_file = 'Security_Group_Rules_Analysis_{}'.format(month_year)
    csvFileName = '{}.csv'.format(usage_analysis_file)
    
    SUBJECT = "Security Group Analysis report for "+format(last_month, '%B %Y')
    TMP_FILE_NAME = '/tmp/' +csvFileName
    
    # Download the file/s from the event (extracted above) to the tmp location
    s3.download_file(s3_bucket, s3_analysis_file_key+csvFileName, TMP_FILE_NAME)

    ATTACHMENT = csvFileName

    BODY_TEXT = "Security Groups Analysis Report,\r\nPlease see the attached file related to Security Groups Analysis for last month ."+month_year

    BODY_HTML = """\
    <html>
    <head></head>
    <body>
    <h1>Security Groups Analysis Report</h1>
    <p>Please see the attached file related to Security Groups Analysis for last month.</p>
    </body>
    </html>
    """

    CHARSET = "utf-8"
    msg = MIMEMultipart('mixed')
    msg['Subject'] = SUBJECT 
    msg['From'] = SENDER 
    msg['To'] = RECIPIENT

    msg_body = MIMEMultipart('alternative')
    textpart = MIMEText(BODY_TEXT.encode(CHARSET), 'plain', CHARSET)
    htmlpart = MIMEText(BODY_HTML.encode(CHARSET), 'html', CHARSET)
    msg_body.attach(textpart)
    msg_body.attach(htmlpart)
    att = MIMEApplication(open(ATTACHMENT, 'rb').read())
    att.add_header('Content-Disposition','attachment',filename=csvFileName)
    msg.attach(msg_body)
    msg.attach(att)
    print(msg)
    try:
        response = ses_client.send_raw_email(
            Source=SENDER,
            Destinations=[
                RECIPIENT
            ],
            RawMessage={
                'Data':msg.as_string(),
            },
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])
    
def main():
    today = datetime.now()
    if today.day == 1:
        last_month = datetime.now() - relativedelta(months=1)
        month_year = format(last_month, '%B_%Y')
        
        usage_analysis_file = 'Security_Group_Rules_Analysis_{}'.format(month_year)
        csvFileName = '{}.csv'.format(usage_analysis_file)
        
        minimum_usage_count=5
        last_day_of_prev_month = date.today().replace(day=1) - timedelta(days=1)
        start_day_of_prev_month = date.today().replace(day=1) - timedelta(days=last_day_of_prev_month.day)
        
        try:
            response = dynamodb_tbl_name.scan(
                FilterExpression=Key("used_times").lt(minimum_usage_count) & Key("sg_rule_last_used").lt(str(last_day_of_prev_month)) & Key("sg_rule_last_used").gt(str(start_day_of_prev_month))
            )
        except Exception as e: 
            print("There was an error while trying to perform DynamoDB scan operations: "+str(e))
        
        if len(response['Items']) != 0:
            print('Rules available for review...')
            df = pd.DataFrame(response['Items'])
            df.to_csv(csvFileName, index=False, header=True)
        
        s3Object = s3_resource.Object(s3_bucket, s3_analysis_file_key+csvFileName)
        s3Response = s3Object.put(Body=open(csvFileName, 'rb'))
        
        if s3Response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print('File uploaded to S3. Emailing contents...')
            emailFile()
            return {
                "status": True,
                "file_name": str(csvFileName)
            }
        else:
            return {
                "status": False
        }
    else:
        print("This job will run only on 1st of every month...")

if __name__ == '__main__':
    main()