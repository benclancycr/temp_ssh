#! /usr/bin/env python

"""
Python command line tool for updating security groups within AWS
"""

import argparse
import boto3
import json
import time
import sys
from botocore.exceptions import ClientError
from urllib2 import urlopen

sys.tracebacklimit = 0

parser = argparse.ArgumentParser()
parser.add_argument('--sg', help='Provide the security group to be updated')
parser.add_argument('--sg-clean-up', help='Provide an security group to be cleaned up')
parser.add_argument('--env', help='Provide an enviroment file')
parser.add_argument('--env-clean-up', help='Provide an environment to be cleaned up')
args = parser.parse_args()


def get_public_ip_address():
    public_ip_address = str(json.load(urlopen('http://jsonip.com'))['ip'])
    public_ip_address_cidr = public_ip_address + '/32'
    return public_ip_address_cidr


def update_security_group(security_group_id, ip_address_to_add_to_sg):
    ec2 = boto3.resource('ec2')
    if security_group_id[:3] != 'sg-':
        raise ValueError('Security group does not start with "sg-" ')
    try:
        security_group = ec2.SecurityGroup(security_group_id)
        response = security_group.authorize_ingress(
                IpProtocol='tcp',
                FromPort=22,
                ToPort=22,
                CidrIp=ip_address_to_add_to_sg
                )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print(security_group_id + ' has been updated to allow ' + ip_address_to_add_to_sg + ' in via SSH')
    except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.Duplicate':
                print(security_group_id + ' Already contains ' + ip_address_to_add_to_sg)
            else:
                print "Unexpected error: %s" % e


def update_security_group_tags(security_group_id):
    ec2 = boto3.resource('ec2')
    if security_group_id[:3] != 'sg-':
        raise ValueError('Security group does not start with "sg-" ')
    else:
        security_group = ec2.SecurityGroup(security_group_id)
        epoch_time = str(int(time.time()))
        tag = security_group.create_tags(
                Tags=[
                    {
                        'Key': 'updated_by_temp_ssh_at',
                        'Value': epoch_time
                    },
                ]
        )
        return tag


def get_env_details(config_file, env):
    with open(config_file) as env_file:
        data = json.load(env_file)
    environments = data['Environments']
    if env not in environments:
        print('Environment provided not in config file')
        raise SystemExit()
    else:
        return data['Environments'][env]


def remove_ssh_rule(security_group_id):
    ec2 = boto3.client('ec2')
    if security_group_id[:3] != 'sg-':
        raise ValueError('Security group does not start with "sg-" ')
    else:
        try:
            response = ec2.revoke_security_group_ingress(
                    GroupId=security_group_id,
                    CidrIp=get_public_ip_address(),
                    IpProtocol='TCP',
                    FromPort=22,
                    ToPort=22
                    )
            if response['ResponseMetadata']['HTTPStatusCode'] == 200:
                print('Entry has been removed from ' + security_group_id)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidPermission.NotFound':
                print('Entry not found in ' + security_group_id)
            else:
                print "Unexpected error: %s" % e
        return True


def remove_security_group_tags(security_group_id):
    ec2 = boto3.client('ec2')
    if security_group_id[:3] != 'sg-':
        raise ValueError('Security group does not start with "sg-" ')
    else:
        response = ec2.delete_tags(
                Resources=[
                    security_group_id
                ],
                Tags=[
                    {
                        'Key': 'updated_by_temp_ssh_at'
                    }
                ]
        )
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            print('Tags have been removed from ' + security_group_id)
            return True
        else:
            return False


def clean_up_env(config_file, env):
    with open(config_file) as env_file:
        data = json.load(env_file)
    environments = data['Environments']
    if env not in environments:
        print('Environment provided not in config file')
        raise SystemExit()
    if env == 'ALL':
        for environment in data['Environments']:
            security_group = data['Environments'][environment]['Security Group']
            if security_group[:3] != 'sg-':
                raise ValueError('Security group does not start with "sg-" ')
            else:
                remove_ssh_rule(security_group)
                remove_security_group_tags(security_group)
    else:
        security_group = data['Environments'][env]['Security Group']
        if security_group[:3] != 'sg-':
            raise ValueError('Security group does not start with "sg-" ')
        else:
            remove_ssh_rule(security_group)
            remove_security_group_tags(security_group)
            print(env + ' is now clean')
            return True


def clean_up_security_group(security_group_id):
    remove_ssh_rule(security_group_id)
    remove_security_group_tags(security_group_id)
    print(security_group_id + ' is now clean')
    return True


def main():
    if not len(sys.argv) > 1:
        print('You need to provide an arguement. Example usage: main.py --sg "sg-123456"')
        raise SystemExit()
    client_public_ip = get_public_ip_address()
    if args.sg is not None:
        update_security_group(args.sg, client_public_ip)
        update_security_group_tags(args.sg)
    if args.sg_clean_up is not None:
        clean_up_security_group(args.sg_clean_up)
    if args.env is not None:
        env_details = get_env_details('config.json', args.env)
        update_security_group(env_details['Security Group'], client_public_ip)
        update_security_group_tags(env_details['Security Group'])
    if args.env_clean_up is not None:
        clean_up_env('config.json', args.env_clean_up)


if __name__ == "__main__":
    main()
