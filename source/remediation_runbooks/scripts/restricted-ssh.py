import boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')

    # Get all security groups
    security_groups = ec2.describe_security_groups()['SecurityGroups']

    # Ports to check for ingress rules containing "0.0.0.0/0"
    ports_to_check = [22]

    # Find security groups with ingress rule containing "0.0.0.0/0" and port in the specified list
    changed_rules = []

    for security_group in security_groups:
        group_id = security_group['GroupId']
        group_name = security_group['GroupName']

        for permission in security_group['IpPermissions']:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')

            for ip_range in permission['IpRanges']:
                if ip_range['CidrIp'] == '0.0.0.0/0' and (from_port in ports_to_check or to_port in ports_to_check):
                    print(f"Updating rule for Security Group: {group_name} ({group_id})")

                    # Revoke the ingress rule
                    ec2.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[{
                            'FromPort': from_port,
                            'ToPort': to_port,
                            'IpProtocol': permission['IpProtocol'],
                            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                        }]
                    )

                    # Create a new permission without "0.0.0.0/0" IP range
                    new_permission = {
                        'FromPort': from_port,
                        'ToPort': to_port,
                        'IpProtocol': permission['IpProtocol'],
                        'UserIdGroupPairs': [{'GroupId': group_id}]
                    }

                    # Authorize the new ingress rule
                    ec2.authorize_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[new_permission]
                    )

                    # Add the changed rule details to the list
                    changed_rules.append((group_id, group_name, f"{from_port}-{to_port}" if from_port != to_port else f"{from_port}"))
                    
                    break

                    

    # Print the changed rules
    print("\nChanged rules:")
    for group_id, group_name, changed_port in changed_rules:
        print(f"Security Group: {group_name} ({group_id}), Changed Port: {changed_port}")

    # Add tags to the security group
    ec2.create_tags(
        Resources=[group_id],
        Tags=[
            {
                'Key': 'ComplianceStatus',
                'Value': 'NonCompliant'
            },
            {
                'Key': 'IngressRule',
                'Value': 'LocalLoopBack'
            }
        ]
    )
