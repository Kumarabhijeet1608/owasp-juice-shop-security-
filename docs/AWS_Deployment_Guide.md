# ☁️ AWS Deployment Guide - Secure Infrastructure Setup

> **Enterprise-Grade Cloud Security & Infrastructure Deployment**  
> *Version: 1.0*  
> *Cloud Security Architect: [Your Name]*  
> *Project: OWASP Juice Shop Production Deployment*

## 📋 Executive Summary

This guide provides a comprehensive approach to deploying the hardened OWASP Juice Shop application on AWS with enterprise-grade security controls. Our infrastructure follows AWS Well-Architected Framework security best practices and implements defense-in-depth security architecture.

### 🎯 Deployment Objectives

- **Secure Infrastructure**: Production-ready security posture
- **Scalability**: Auto-scaling and load balancing capabilities
- **Monitoring**: Comprehensive security monitoring and alerting
- **Compliance**: Industry security standards compliance
- **Cost Optimization**: Efficient resource utilization

### 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AWS Cloud Infrastructure                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  Internet Gateway → Route 53 → CloudFront → Application Load Balancer     │
│                                    ↓                                       │
│  WAF → VPC → Public Subnet (Bastion) → Private Subnet (App) → DB Subnet   │
│                                    ↓                                       │
│  CloudWatch → CloudTrail → GuardDuty → Security Hub → S3 (Logs)           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Phase 1: Network Security Foundation

### 1.1 Virtual Private Cloud (VPC) Configuration

#### VPC Architecture Design
```yaml
# infrastructure/vpc.yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Secure VPC for OWASP Juice Shop'

Parameters:
  Environment:
    Type: String
    Default: 'production'
    AllowedValues: ['development', 'staging', 'production']
  
  VpcCidr:
    Type: String
    Default: '10.0.0.0/16'
    Description: 'CIDR block for VPC'

Resources:
  # Main VPC
  VPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: !Ref VpcCidr
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-vpc'
        - Key: Environment
          Value: !Ref Environment
        - Key: Project
          Value: 'juice-shop-security'

  # Internet Gateway
  InternetGateway:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-igw'

  # Attach Internet Gateway to VPC
  InternetGatewayAttachment:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      InternetGatewayId: !Ref InternetGateway
      VpcId: !Ref VPC

  # Public Subnet (Bastion Host, Load Balancer)
  PublicSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: '10.0.1.0/24'
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-public-1'

  PublicSubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: '10.0.2.0/24'
      AvailabilityZone: !Select [1, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-public-2'

  # Private Subnet (Application Servers)
  PrivateSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: '10.0.3.0/24'
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-private-1'

  PrivateSubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: '10.0.4.0/24'
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-private-2'

  # Database Subnet
  DatabaseSubnet1:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: '10.0.5.0/24'
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-db-1'

  DatabaseSubnet2:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref VPC
      CidrBlock: '10.0.6.0/24'
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-db-2'
```

#### Route Tables & Network ACLs
```yaml
  # Public Route Table
  PublicRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref VPC
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-public-rt'

  # Public Route
  PublicRoute:
    Type: AWS::EC2::Route
    DependsOn: InternetGatewayAttachment
    Properties:
      RouteTableId: !Ref PublicRouteTable
      DestinationCidrBlock: '0.0.0.0/0'
      GatewayId: !Ref InternetGateway

  # Private Route Table
  PrivateRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref VPC
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-private-rt'

  # Network ACLs
  PublicNetworkAcl:
    Type: AWS::EC2::NetworkAcl
    Properties:
      VpcId: !Ref VPC
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-public-nacl'

  # Restrictive Public NACL Rules
  PublicNaclEntry1:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId: !Ref PublicNetworkAcl
      RuleNumber: 100
      Protocol: -1
      RuleAction: allow
      Egress: false
      CidrBlock: '0.0.0.0/0'

  PublicNaclEntry2:
    Type: AWS::EC2::NetworkAclEntry
    Properties:
      NetworkAclId: !Ref PublicNetworkAcl
      RuleNumber: 100
      Protocol: -1
      RuleAction: allow
      Egress: true
      CidrBlock: '0.0.0.0/0'
```

### 1.2 Security Groups Configuration

#### Application Security Group
```yaml
  # Application Security Group
  ApplicationSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub '${Environment}-juice-shop-app-sg'
      GroupDescription: 'Security group for Juice Shop application servers'
      VpcId: !Ref VPC
      SecurityGroupIngress:
        # Allow HTTP from Load Balancer
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          SourceSecurityGroupId: !Ref LoadBalancerSecurityGroup
        # Allow HTTPS from Load Balancer
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          SourceSecurityGroupId: !Ref LoadBalancerSecurityGroup
        # Allow SSH from Bastion Host
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          SourceSecurityGroupId: !Ref BastionSecurityGroup
      SecurityGroupEgress:
        # Allow outbound to database
        - IpProtocol: tcp
          FromPort: 3306
          ToPort: 3306
          DestinationSecurityGroupId: !Ref DatabaseSecurityGroup
        # Allow outbound to Redis
        - IpProtocol: tcp
          FromPort: 6379
          ToPort: 6379
          DestinationSecurityGroupId: !Ref RedisSecurityGroup
        # Allow HTTPS outbound for updates
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: '0.0.0.0/0'
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-app-sg'

  # Load Balancer Security Group
  LoadBalancerSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub '${Environment}-juice-shop-lb-sg'
      GroupDescription: 'Security group for Application Load Balancer'
      VpcId: !Ref VPC
      SecurityGroupIngress:
        # Allow HTTP from internet
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: '0.0.0.0/0'
        # Allow HTTPS from internet
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: '0.0.0.0/0'
      SecurityGroupEgress:
        # Allow outbound to application servers
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          DestinationSecurityGroupId: !Ref ApplicationSecurityGroup
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          DestinationSecurityGroupId: !Ref ApplicationSecurityGroup
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-lb-sg'

  # Database Security Group
  DatabaseSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub '${Environment}-juice-shop-db-sg'
      GroupDescription: 'Security group for RDS database'
      VpcId: !Ref VPC
      SecurityGroupIngress:
        # Allow MySQL from application servers only
        - IpProtocol: tcp
          FromPort: 3306
          ToPort: 3306
          SourceSecurityGroupId: !Ref ApplicationSecurityGroup
      SecurityGroupEgress:
        - IpProtocol: -1
          CidrIp: '0.0.0.0/0'
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-db-sg'
```

---

## 🛡️ Phase 2: Web Application Firewall (WAF)

### 2.1 WAF Configuration

#### WAF Web ACL
```yaml
  # WAF Web ACL
  WafWebAcl:
    Type: AWS::WAFv2::WebACL
    Properties:
      Name: !Sub '${Environment}-juice-shop-waf'
      Description: 'WAF for OWASP Juice Shop application'
      Scope: REGIONAL
      DefaultAction:
        Allow: {}
      Rules:
        # SQL Injection Protection
        - Name: SQLInjectionRule
          Priority: 1
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesSQLiRuleSet
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: SQLInjectionRule

        # XSS Protection
        - Name: XSSRule
          Priority: 2
          Statement:
            ManagedRuleGroupStatement:
              VendorName: AWS
              Name: AWSManagedRulesKnownBadInputsRuleSet
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: XSSRule

        # Rate Limiting
        - Name: RateLimitRule
          Priority: 3
          Statement:
            RateBasedStatement:
              Limit: 2000
              AggregateKeyType: IP
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: RateLimitRule

        # Geo-blocking (optional)
        - Name: GeoBlockRule
          Priority: 4
          Statement:
            GeoMatchStatement:
              CountryCodes: ['CN', 'RU', 'KP']  # Block specific countries
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: GeoBlockRule

        # Custom Rule for Juice Shop specific attacks
        - Name: JuiceShopCustomRule
          Priority: 5
          Statement:
            AndStatement:
              Statements:
                - ByteMatchStatement:
                    SearchString: 'admin'
                    FieldToMatch:
                      UriPath: {}
                    TextTransformations:
                      - Priority: 1
                        Type: LOWERCASE
                - ByteMatchStatement:
                    SearchString: 'admin'
                    FieldToMatch:
                      QueryString: {}
                    TextTransformations:
                      - Priority: 1
                        Type: LOWERCASE
          Action:
            Block: {}
          VisibilityConfig:
            SampledRequestsEnabled: true
            CloudWatchMetricsEnabled: true
            MetricName: JuiceShopCustomRule

      VisibilityConfig:
        SampledRequestsEnabled: true
        CloudWatchMetricsEnabled: true
        MetricName: JuiceShopWafWebAcl
```

#### WAF Association
```yaml
  # Associate WAF with Application Load Balancer
  WafWebAclAssociation:
    Type: AWS::WAFv2::WebACLAssociation
    Properties:
      ResourceArn: !GetAtt ApplicationLoadBalancer.LoadBalancerArn
      WebACLArn: !GetAtt WafWebAcl.Arn
```

---

## 🔐 Phase 3: Identity & Access Management (IAM)

### 3.1 IAM Roles & Policies

#### Application Role
```yaml
  # Application IAM Role
  ApplicationRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub '${Environment}-juice-shop-app-role'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
      Policies:
        - PolicyName: JuiceShopAppPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              # S3 access for logs and assets
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:DeleteObject
                Resource: 
                  - !Sub '${LoggingBucket}/*'
                  - !Sub '${AssetsBucket}/*'
              
              # Secrets Manager access
              - Effect: Allow
                Action:
                  - secretsmanager:GetSecretValue
                Resource: !Sub '${DatabaseSecret}'
              
              # CloudWatch Logs
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - logs:DescribeLogGroups
                  - logs:DescribeLogStreams
                Resource: '*'

  # Application Instance Profile
  ApplicationInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      InstanceProfileName: !Sub '${Environment}-juice-shop-app-profile'
      Roles:
        - !Ref ApplicationRole
```

#### Database Role
```yaml
  # Database IAM Role
  DatabaseRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub '${Environment}-juice-shop-db-role'
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonRDSEnhancedMonitoringRole
      Policies:
        - PolicyName: JuiceShopDatabasePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              # CloudWatch monitoring
              - Effect: Allow
                Action:
                  - cloudwatch:PutMetricData
                Resource: '*'
```

### 3.2 Secrets Management

#### Database Secret
```yaml
  # Database Secret
  DatabaseSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Sub '${Environment}/juice-shop/database'
      Description: 'Database credentials for Juice Shop application'
      SecretString: !Sub |
        {
          "username": "juice_shop_user",
          "password": "{{resolve:secretsmanager:${Environment}/juice-shop/database:SecretString:password}}",
          "engine": "mysql",
          "host": "${DatabaseEndpoint}",
          "port": 3306,
          "dbname": "juice_shop"
        }
      Tags:
        - Key: Environment
          Value: !Ref Environment
        - Key: Project
          Value: 'juice-shop-security'
```

---

## 🚀 Phase 4: Application Infrastructure

### 4.1 Application Load Balancer

#### ALB Configuration
```yaml
  # Application Load Balancer
  ApplicationLoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Name: !Sub '${Environment}-juice-shop-alb'
      Scheme: internet-facing
      Type: application
      IpAddressType: ipv4
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2
      SecurityGroups:
        - !Ref LoadBalancerSecurityGroup
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-alb'
        - Key: Environment
          Value: !Ref Environment

  # Target Group
  ApplicationTargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      Name: !Sub '${Environment}-juice-shop-tg'
      Port: 80
      Protocol: HTTP
      TargetType: instance
      VpcId: !Ref VPC
      HealthCheckPath: '/health'
      HealthCheckIntervalSeconds: 30
      HealthCheckTimeoutSeconds: 5
      HealthyThresholdCount: 2
      UnhealthyThresholdCount: 3
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-tg'

  # HTTP Listener
  HttpListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref ApplicationLoadBalancer
      Port: 80
      Protocol: HTTP
      DefaultActions:
        - Type: redirect
          RedirectConfig:
            Protocol: HTTPS
            Port: '443'
            StatusCode: HTTP_301

  # HTTPS Listener
  HttpsListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref ApplicationLoadBalancer
      Port: 443
      Protocol: HTTPS
      SslPolicy: ELBSecurityPolicy-TLS-1-2-2017-01
      Certificates:
        - CertificateArn: !Ref SSLCertificate
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref ApplicationTargetGroup
```

### 4.2 Auto Scaling Group

#### ASG Configuration
```yaml
  # Launch Template
  ApplicationLaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateName: !Sub '${Environment}-juice-shop-lt'
      LaunchTemplateData:
        ImageId: !Ref AmiId
        InstanceType: !Ref InstanceType
        KeyName: !Ref KeyPairName
        SecurityGroupIds:
          - !Ref ApplicationSecurityGroup
        IamInstanceProfile:
          Name: !Ref ApplicationInstanceProfile
        UserData:
          Fn::Base64: !Sub |
            #!/bin/bash
            yum update -y
            yum install -y docker
            systemctl start docker
            systemctl enable docker
            
            # Install CloudWatch agent
            yum install -y amazon-cloudwatch-agent
            
            # Start application
            docker run -d \
              --name juice-shop \
              -p 80:3000 \
              -e NODE_ENV=production \
              -e DATABASE_URL=${DatabaseEndpoint} \
              -e REDIS_URL=${RedisEndpoint} \
              ${ECRRepository}:latest
        BlockDeviceMappings:
          - DeviceName: /dev/xvda
            Ebs:
              VolumeSize: 20
              VolumeType: gp3
              Encrypted: true
              DeleteOnTermination: true
        TagSpecifications:
          - ResourceType: instance
            Tags:
              - Key: Name
                Value: !Sub '${Environment}-juice-shop-app'
              - Key: Environment
                Value: !Ref Environment

  # Auto Scaling Group
  ApplicationAutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: !Sub '${Environment}-juice-shop-asg'
      LaunchTemplate:
        LaunchTemplateId: !Ref ApplicationLaunchTemplate
        Version: !GetAtt ApplicationLaunchTemplate.LatestVersionNumber
      MinSize: 2
      MaxSize: 10
      DesiredCapacity: 2
      VPCZoneIdentifier:
        - !Ref PrivateSubnet1
        - !Ref PrivateSubnet2
      TargetGroupARNs:
        - !Ref ApplicationTargetGroup
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-app'
          PropagateAtLaunch: true
        - Key: Environment
          Value: !Ref Environment
          PropagateAtLaunch: true

  # Scale Up Policy
  ScaleUpPolicy:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      AutoScalingGroupName: !Ref ApplicationAutoScalingGroup
      PolicyName: !Sub '${Environment}-juice-shop-scaleup'
      PolicyType: TargetTrackingScaling
      TargetTrackingConfiguration:
        PredefinedMetricSpecification:
          PredefinedMetricType: ASGAverageCPUUtilization
        TargetValue: 70.0
        ScaleOutCooldown: 300
        ScaleInCooldown: 300
```

---

## 🗄️ Phase 5: Database & Storage

### 5.1 RDS Database

#### RDS Configuration
```yaml
  # RDS Subnet Group
  DatabaseSubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupName: !Sub '${Environment}-juice-shop-db-subnet'
      DBSubnetGroupDescription: 'Subnet group for Juice Shop database'
      SubnetIds:
        - !Ref DatabaseSubnet1
        - !Ref DatabaseSubnet2
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-db-subnet'

  # RDS Parameter Group
  DatabaseParameterGroup:
    Type: AWS::RDS::DBParameterGroup
    Properties:
      DBParameterGroupName: !Sub '${Environment}-juice-shop-db-params'
      Description: 'Parameter group for Juice Shop database'
      Family: mysql8.0
      Parameters:
        # Security parameters
        sql_mode: 'STRICT_TRANS_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO'
        max_connections: '1000'
        wait_timeout: '28800'
        interactive_timeout: '28800'

  # RDS Database
  Database:
    Type: AWS::RDS::DBInstance
    Properties:
      DBInstanceIdentifier: !Sub '${Environment}-juice-shop-db'
      DBInstanceClass: !Ref DatabaseInstanceType
      Engine: mysql
      EngineVersion: '8.0.28'
      AllocatedStorage: !Ref DatabaseAllocatedStorage
      StorageType: gp3
      StorageEncrypted: true
      KmsKeyId: !Ref KmsKeyId
      DBName: juice_shop
      MasterUsername: !Sub '{{resolve:secretsmanager:${Environment}/juice-shop/database:SecretString:username}}'
      MasterUserPassword: !Sub '{{resolve:secretsmanager:${Environment}/juice-shop/database:SecretString:password}}'
      VPCSecurityGroups:
        - !Ref DatabaseSecurityGroup
      DBSubnetGroupName: !Ref DatabaseSubnetGroup
      DBParameterGroupName: !Ref DatabaseParameterGroup
      BackupRetentionPeriod: 7
      PreferredBackupWindow: '03:00-04:00'
      PreferredMaintenanceWindow: 'sun:04:00-sun:05:00'
      MultiAZ: true
      DeletionProtection: true
      EnablePerformanceInsights: true
      PerformanceInsightsRetentionPeriod: 7
      MonitoringInterval: 60
      MonitoringRoleArn: !GetAtt DatabaseRole.Arn
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-db'
        - Key: Environment
          Value: !Ref Environment
```

### 5.2 ElastiCache Redis

#### Redis Configuration
```yaml
  # Redis Subnet Group
  RedisSubnetGroup:
    Type: AWS::ElastiCache::SubnetGroup
    Properties:
      Description: 'Subnet group for Redis cluster'
      SubnetIds:
        - !Ref PrivateSubnet1
        - !Ref PrivateSubnet2

  # Redis Security Group
  RedisSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupName: !Sub '${Environment}-juice-shop-redis-sg'
      GroupDescription: 'Security group for Redis cluster'
      VpcId: !Ref VPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 6379
          ToPort: 6379
          SourceSecurityGroupId: !Ref ApplicationSecurityGroup
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-redis-sg'

  # Redis Cluster
  RedisCluster:
    Type: AWS::ElastiCache::ReplicationGroup
    Properties:
      ReplicationGroupId: !Sub '${Environment}-juice-shop-redis'
      Description: 'Redis cluster for Juice Shop application'
      NodeType: !Ref RedisNodeType
      NumCacheClusters: 2
      AutomaticFailoverEnabled: true
      MultiAZEnabled: true
      CacheSubnetGroupName: !Ref RedisSubnetGroup
      SecurityGroupIds:
        - !Ref RedisSecurityGroup
      AtRestEncryptionEnabled: true
      TransitEncryptionEnabled: true
      AuthToken: !Ref RedisAuthToken
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-redis'
        - Key: Environment
          Value: !Ref Environment
```

---

## 📊 Phase 6: Monitoring & Logging

### 6.1 CloudWatch Monitoring

#### CloudWatch Dashboard
```yaml
  # CloudWatch Dashboard
  SecurityDashboard:
    Type: AWS::CloudWatch::Dashboard
    Properties:
      DashboardName: !Sub '${Environment}-juice-shop-security'
      DashboardBody: !Sub |
        {
          "widgets": [
            {
              "type": "metric",
              "x": 0,
              "y": 0,
              "width": 12,
              "height": 6,
              "properties": {
                "metrics": [
                  ["AWS/WAFV2", "BlockedRequests", "WebACL", "${Environment}-juice-shop-waf"],
                  [".", "AllowedRequests", ".", "."]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${AWS::Region}",
                "title": "WAF Requests"
              }
            },
            {
              "type": "metric",
              "x": 12,
              "y": 0,
              "width": 12,
              "height": 6,
              "properties": {
                "metrics": [
                  ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", "${ApplicationLoadBalancer}"],
                  [".", "TargetResponseTime", ".", "."]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${AWS::Region}",
                "title": "Application Load Balancer"
              }
            },
            {
              "type": "metric",
              "x": 0,
              "y": 6,
              "width": 12,
              "height": 6,
              "properties": {
                "metrics": [
                  ["AWS/RDS", "CPUUtilization", "DBInstanceIdentifier", "${Environment}-juice-shop-db"],
                  [".", "DatabaseConnections", ".", "."]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${AWS::Region}",
                "title": "Database Performance"
              }
            },
            {
              "type": "metric",
              "x": 12,
              "y": 6,
              "width": 12,
              "height": 6,
              "properties": {
                "metrics": [
                  ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "${Environment}-juice-shop-asg"],
                  [".", "NetworkIn", ".", "."],
                  [".", "NetworkOut", ".", "."]
                ],
                "view": "timeSeries",
                "stacked": false,
                "region": "${AWS::Region}",
                "title": "Application Server Performance"
              }
            }
          ]
        }
```

#### CloudWatch Alarms
```yaml
  # Security Alarms
  SecurityScoreAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${Environment}-juice-shop-security-score'
      MetricName: SecurityScore
      Namespace: JuiceShop/Security
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 7.0
      ComparisonOperator: LessThanThreshold
      AlarmActions:
        - !Ref SecurityTopic
      AlarmDescription: 'Security score below acceptable threshold'

  # WAF Alarms
  WafBlockedRequestsAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${Environment}-juice-shop-waf-blocks'
      MetricName: BlockedRequests
      Namespace: AWS/WAFV2
      Statistic: Sum
      Period: 300
      EvaluationPeriods: 1
      Threshold: 100
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: WebACL
          Value: !Sub '${Environment}-juice-shop-waf'
      AlarmActions:
        - !Ref SecurityTopic
      AlarmDescription: 'High number of WAF blocked requests'

  # Performance Alarms
  HighCPUAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub '${Environment}-juice-shop-high-cpu'
      MetricName: CPUUtilization
      Namespace: AWS/EC2
      Statistic: Average
      Period: 300
      EvaluationPeriods: 2
      Threshold: 80
      ComparisonOperator: GreaterThanThreshold
      Dimensions:
        - Name: AutoScalingGroupName
          Value: !Sub '${Environment}-juice-shop-asg'
      AlarmActions:
        - !Ref SecurityTopic
      AlarmDescription: 'High CPU utilization detected'
```

### 6.2 S3 Logging

#### S3 Bucket for Logs
```yaml
  # Logging S3 Bucket
  LoggingBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub '${Environment}-juice-shop-logs-${AWS::AccountId}'
      VersioningConfiguration:
        Status: Enabled
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
      LifecycleConfiguration:
        Rules:
          - Id: LogRetention
            Status: Enabled
            ExpirationInDays: 2555  # 7 years
            Transitions:
              - StorageClass: INTELLIGENT_TIERING
                TransitionInDays: 30
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-logs'
        - Key: Environment
          Value: !Ref Environment

  # S3 Bucket Policy
  LoggingBucketPolicy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref LoggingBucket
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Sid: DenyUnencryptedObjectUploads
            Effect: Deny
            Principal: '*'
            Action: s3:PutObject
            Resource: !Sub '${LoggingBucket}/*'
            Condition:
              StringNotEquals:
                s3:x-amz-server-side-encryption: AES256
          - Sid: DenyIncorrectEncryptionHeader
            Effect: Deny
            Principal: '*'
            Action: s3:PutObject
            Resource: !Sub '${LoggingBucket}/*'
            Condition:
              StringNotEquals:
                s3:x-amz-server-side-encryption: AES256
```

---

## 🔍 Phase 7: Security Monitoring & Response

### 7.1 GuardDuty & Security Hub

#### GuardDuty Configuration
```yaml
  # GuardDuty Detector
  GuardDutyDetector:
    Type: AWS::GuardDuty::Detector
    Properties:
      Enable: true
      FindingPublishingFrequency: FIFTEEN_MINUTES

  # GuardDuty Master Account (if using organization)
  GuardDutyMasterAccount:
    Type: AWS::GuardDuty::Master
    Properties:
      AccountId: !Ref MasterAccountId
      DetectorId: !Ref GuardDutyDetector
```

### 7.2 CloudTrail Logging

#### CloudTrail Configuration
```yaml
  # CloudTrail
  CloudTrail:
    Type: AWS::CloudTrail::Trail
    Properties:
      TrailName: !Sub '${Environment}-juice-shop-trail'
      S3BucketName: !Ref LoggingBucket
      S3KeyPrefix: 'cloudtrail/'
      IncludeGlobalServiceEvents: true
      IsMultiRegionTrail: true
      EnableLogFileValidation: true
      EventSelectors:
        - ReadWriteType: All
          IncludeManagementEvents: true
          DataResources:
            - Type: 'AWS::S3::Object'
              Values:
                - !Sub '${LoggingBucket}/'
      Tags:
        - Key: Name
          Value: !Sub '${Environment}-juice-shop-trail'
        - Key: Environment
          Value: !Ref Environment
```

---

## 🚀 Phase 8: Deployment & CI/CD

### 8.1 Deployment Scripts

#### Deployment Script
```bash
#!/bin/bash
# deploy.sh - AWS Infrastructure Deployment Script

set -e

# Configuration
ENVIRONMENT=${1:-production}
REGION=${2:-us-east-1}
STACK_NAME="${ENVIRONMENT}-juice-shop-security"

echo "🚀 Deploying ${STACK_NAME} to ${REGION}..."

# Validate template
echo "📋 Validating CloudFormation template..."
aws cloudformation validate-template \
  --template-body file://infrastructure/main.yaml \
  --region ${REGION}

# Deploy infrastructure
echo "🏗️ Deploying infrastructure stack..."
aws cloudformation deploy \
  --template-file infrastructure/main.yaml \
  --stack-name ${STACK_NAME} \
  --parameter-overrides \
    Environment=${ENVIRONMENT} \
    InstanceType=t3.medium \
    DatabaseInstanceType=db.t3.micro \
    RedisNodeType=cache.t3.micro \
  --capabilities CAPABILITY_NAMED_IAM \
  --region ${REGION}

# Wait for stack completion
echo "⏳ Waiting for stack completion..."
aws cloudformation wait stack-create-complete \
  --stack-name ${STACK_NAME} \
  --region ${REGION}

# Get outputs
echo "📊 Getting stack outputs..."
aws cloudformation describe-stacks \
  --stack-name ${STACK_NAME} \
  --region ${REGION} \
  --query 'Stacks[0].Outputs'

echo "✅ Deployment completed successfully!"
```

#### Environment Configuration
```bash
#!/bin/bash
# setup-env.sh - Environment Setup Script

# Set environment variables
export ENVIRONMENT="production"
export AWS_REGION="us-east-1"
export STACK_NAME="${ENVIRONMENT}-juice-shop-security"

# Create .env file for application
cat > .env << EOF
# Application Configuration
NODE_ENV=production
PORT=3000

# Database Configuration
DATABASE_HOST=\$(aws cloudformation describe-stacks \
  --stack-name ${STACK_NAME} \
  --query 'Stacks[0].Outputs[?OutputKey==`DatabaseEndpoint`].OutputValue' \
  --output text)

# Redis Configuration
REDIS_HOST=\$(aws cloudformation describe-stacks \
  --stack-name ${STACK_NAME} \
  --query 'Stacks[0].Outputs[?OutputKey==`RedisEndpoint`].OutputValue' \
  --output text)

# Security Configuration
JWT_SECRET=\$(openssl rand -base64 32)
SESSION_SECRET=\$(openssl rand -base64 32)

# AWS Configuration
AWS_REGION=${AWS_REGION}
S3_BUCKET=\$(aws cloudformation describe-stacks \
  --stack-name ${STACK_NAME} \
  --query 'Stacks[0].Outputs[?OutputKey==`LoggingBucket`].OutputValue' \
  --output text)
EOF

echo "✅ Environment configuration completed!"
```

---

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] **AWS Account Setup**: Configure AWS CLI and permissions
- [ ] **Domain & SSL**: Purchase domain and SSL certificate
- [ ] **Security Review**: Review security configurations
- [ ] **Cost Estimation**: Estimate monthly AWS costs
- [ ] **Backup Strategy**: Plan data backup and recovery

### Infrastructure Deployment
- [ ] **VPC & Networking**: Deploy secure network infrastructure
- [ ] **Security Groups**: Configure firewall rules
- [ ] **WAF**: Deploy Web Application Firewall
- [ ] **IAM**: Set up roles and policies
- [ ] **Database**: Deploy RDS with encryption
- [ ] **Cache**: Deploy ElastiCache Redis
- [ ] **Load Balancer**: Configure ALB with SSL
- [ ] **Auto Scaling**: Set up application scaling

### Application Deployment
- [ ] **Container Registry**: Push application to ECR
- [ ] **Launch Template**: Configure EC2 launch template
- [ ] **Auto Scaling Group**: Deploy application instances
- [ ] **Health Checks**: Verify application health
- [ ] **SSL Certificate**: Install and configure SSL
- [ ] **DNS**: Configure Route 53 routing

### Security & Monitoring
- [ ] **CloudWatch**: Set up monitoring and alerting
- [ ] **CloudTrail**: Enable audit logging
- [ ] **GuardDuty**: Enable threat detection
- [ ] **WAF Rules**: Test and tune WAF rules
- [ ] **Security Testing**: Run security tests
- [ ] **Documentation**: Update deployment docs

### Post-Deployment
- [ ] **Performance Testing**: Load test application
- [ ] **Security Validation**: Verify security controls
- [ ] **Backup Testing**: Test backup and recovery
- [ ] **Team Training**: Train operations team
- [ ] **Monitoring**: Verify monitoring is working

---

## 💰 Cost Optimization

### Resource Sizing
- **Development**: t3.micro instances, minimal resources
- **Staging**: t3.small instances, moderate resources
- **Production**: t3.medium instances, adequate resources

### Cost Monitoring
```yaml
  # Cost Budget
  MonthlyBudget:
    Type: AWS::Budgets::Budget
    Properties:
      Budget:
        BudgetName: !Sub '${Environment}-juice-shop-monthly'
        BudgetLimit:
          Amount: !Ref MonthlyBudgetAmount
          Unit: USD
        TimeUnit: MONTHLY
        BudgetType: COST
        CostFilters:
          TagKeyValue: 'Environment$${Environment}'
      NotificationsWithSubscribers:
        - Notification:
            ComparisonOperator: GREATER_THAN
            NotificationType: ACTUAL
            Threshold: 80
            ThresholdType: PERCENTAGE
          Subscribers:
            - Address: !Ref BudgetNotificationEmail
              SubscriptionType: EMAIL
```

---

## 🔗 Additional Resources

### AWS Documentation
- [AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
- [AWS CloudFormation User Guide](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/)

### Security Resources
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)
- [AWS Security Blog](https://aws.amazon.com/blogs/security/)
- [Cloud Security Alliance](https://cloudsecurityalliance.org/)

---

## 📞 Support & Contact

**Cloud Security Team**: [Your Name]  
**Email**: [your.email@domain.com]  
**Phone**: [Your Phone]  
**Emergency**: [Emergency Contact]

**AWS Support**:
- **Basic**: Community forums and documentation
- **Developer**: Email support
- **Business**: Phone and email support
- **Enterprise**: 24/7 phone and email support

---

*This guide is part of the OWASP Juice Shop Security Hardening project. All infrastructure configurations follow AWS security best practices and industry standards.*
