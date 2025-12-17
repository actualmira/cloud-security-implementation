import json
import boto3

def lambda_handler(event, context):
    print("Event received:", json.dumps(event))
    
    # Initialize S3 control client for account-level operations
    s3control = boto3.client('s3control')
    
    # Get account ID
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']
    
    try:
        print(f"Enabling account-level Block Public Access for account: {account_id}")
        
        # Enable all 4 Block Public Access settings at account level
        response = s3control.put_public_access_block(
            AccountId=account_id,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        print(f"Successfully enabled account-level Block Public Access")
        
        return {
            'statusCode': 200,
            'body': json.dumps(f'Account-level Block Public Access enabled for account {account_id}')
        }
        
    except Exception as e:
        print(f"Error enabling Block Public Access: {str(e)}")
        raise e
