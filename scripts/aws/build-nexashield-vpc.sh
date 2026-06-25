#!/bin/bash
# NexaShield VPC build script
# Builds the full 3-tier VPC in AWS us-east-2
# Run from CloudShell or any machine with AWS CLI configured
# Replace placeholders with your actual values before running

set -e

REGION="us-east-2"
VPC_CIDR="172.16.0.0/16"
PUBLIC_CIDR="172.16.1.0/24"
PRIVATE_CIDR="172.16.2.0/24"
DB_CIDR="172.16.3.0/24"

echo "Creating NexaShield VPC in $REGION..."

# Create VPC
VPC_ID=$(aws ec2 create-vpc \
  --cidr-block $VPC_CIDR \
  --region $REGION \
  --query 'Vpc.VpcId' \
  --output text)

aws ec2 create-tags --resources $VPC_ID \
  --tags Key=Name,Value=nexashield-vpc \
  --region $REGION

echo "VPC created: $VPC_ID"

# Enable DNS hostnames
aws ec2 modify-vpc-attribute \
  --vpc-id $VPC_ID \
  --enable-dns-hostnames \
  --region $REGION

# Create subnets
PUBLIC_SUBNET=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block $PUBLIC_CIDR \
  --availability-zone ${REGION}a \
  --query 'Subnet.SubnetId' \
  --output text \
  --region $REGION)

aws ec2 create-tags --resources $PUBLIC_SUBNET \
  --tags Key=Name,Value=nexashield-public-dmz \
  --region $REGION

PRIVATE_SUBNET=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block $PRIVATE_CIDR \
  --availability-zone ${REGION}a \
  --query 'Subnet.SubnetId' \
  --output text \
  --region $REGION)

aws ec2 create-tags --resources $PRIVATE_SUBNET \
  --tags Key=Name,Value=nexashield-private-app \
  --region $REGION

DB_SUBNET=$(aws ec2 create-subnet \
  --vpc-id $VPC_ID \
  --cidr-block $DB_CIDR \
  --availability-zone ${REGION}a \
  --query 'Subnet.SubnetId' \
  --output text \
  --region $REGION)

aws ec2 create-tags --resources $DB_SUBNET \
  --tags Key=Name,Value=nexashield-database-isolated \
  --region $REGION

echo "Subnets created: $PUBLIC_SUBNET $PRIVATE_SUBNET $DB_SUBNET"

# Internet Gateway
IGW_ID=$(aws ec2 create-internet-gateway \
  --query 'InternetGateway.InternetGatewayId' \
  --output text \
  --region $REGION)

aws ec2 attach-internet-gateway \
  --internet-gateway-id $IGW_ID \
  --vpc-id $VPC_ID \
  --region $REGION

aws ec2 create-tags --resources $IGW_ID \
  --tags Key=Name,Value=nexashield-igw \
  --region $REGION

echo "IGW created and attached: $IGW_ID"

# Public route table
PUBLIC_RT=$(aws ec2 create-route-table \
  --vpc-id $VPC_ID \
  --query 'RouteTable.RouteTableId' \
  --output text \
  --region $REGION)

aws ec2 create-route \
  --route-table-id $PUBLIC_RT \
  --destination-cidr-block 0.0.0.0/0 \
  --gateway-id $IGW_ID \
  --region $REGION

aws ec2 associate-route-table \
  --route-table-id $PUBLIC_RT \
  --subnet-id $PUBLIC_SUBNET \
  --region $REGION

aws ec2 create-tags --resources $PUBLIC_RT \
  --tags Key=Name,Value=nexashield-public-rt \
  --region $REGION

echo "VPC build complete"
echo "VPC ID:             $VPC_ID"
echo "Public subnet:      $PUBLIC_SUBNET"
echo "Private subnet:     $PRIVATE_SUBNET"
echo "Database subnet:    $DB_SUBNET"
echo "Internet Gateway:   $IGW_ID"
echo ""
echo "Next: create Virtual Private Gateway and add VPN route 10.0.0.0/8"
