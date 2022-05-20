provider "aws" {}

#Variables for Production Environment
variable vpcCIDRPRD{}
variable PublicSubnet1PRD{}
variable PublicSubnet2PRD{}
variable PublicSubnet3PRD{}
variable PrivateSubnet1PRD{}
variable PrivateSubnet2PRD{}
variable PrivateSubnet3PRD{}
variable NATSubnetPRD{}

#Variables for Test Environment
variable vpcCIDRTST{}
variable PublicSubnet1TST{}
variable PublicSubnet2TST{}
variable PublicSubnet3TST{}
variable PrivateSubnet1TST{}
variable PrivateSubnet2TST{}
variable PrivateSubnet3TST{}
variable NATSubnetTST{}
variable dns_name{}

data "aws_availability_zones" "AZs" {
  state = "available"
}

#PRD Environment

#####################   VPC  #####################
resource "aws_vpc" "VPCPRD" {
  cidr_block = var.vpcCIDRPRD
  tags = {
    Name = "VPC-prd"
  }
}
#####################   Subnets  #####################
resource "aws_subnet" "PublicSubnet1PRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.PublicSubnet1PRD
  map_public_ip_on_launch = "true"
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "prd-Public-Subnet1"
  }  
}
  resource "aws_subnet" "PublicSubnet2PRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.PublicSubnet2PRD
  availability_zone = data.aws_availability_zones.AZs.names[2]
  tags = {
    Name = "prd-Public-Subnet2"
  }    
}
  resource "aws_subnet" "PublicSubnet3PRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.PublicSubnet3PRD
  availability_zone = data.aws_availability_zones.AZs.names[3]
  tags = {
    Name = "prd-Public-Subnet3"
  }  
}
resource "aws_subnet" "PrivateSubnet1PRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.PrivateSubnet1PRD
  map_public_ip_on_launch = "false"  
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "prd-Private-Subnet1"
  }  
}
  resource "aws_subnet" "PrivateSubnet2PRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.PrivateSubnet2PRD
  map_public_ip_on_launch = "false"   
  availability_zone = data.aws_availability_zones.AZs.names[2]
  tags = {
    Name = "prd-Private-Subnet2"
  }
}
  resource "aws_subnet" "PrivateSubnet3PRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.PrivateSubnet3PRD
  map_public_ip_on_launch = "false"   
  availability_zone = data.aws_availability_zones.AZs.names[3]
  tags = {
    Name = "prd-Private-Subnet3"
  }
}
  resource "aws_subnet" "NATSubnetPRD" {
  vpc_id     = aws_vpc.VPCPRD.id
  cidr_block = var.NATSubnetPRD
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "prd-NATGW-Subnet"
  }
}
#####################   Internet Gateway  #####################
resource "aws_internet_gateway" "IGWPRD" {
  vpc_id = aws_vpc.VPCPRD.id
  tags = {
    Name = "prd-VPC-IGW"
  }  
}
#####################   NAT Gateway  #####################
resource "aws_eip" "NATEIPPRD" {
  tags = {
    Name = "prd-NATGW-EIP"
  }
}

resource "aws_nat_gateway" "NATGWPRD" {
  allocation_id = aws_eip.NATEIPPRD.id
  subnet_id     = aws_subnet.NATSubnetPRD.id
  tags = {
    Name = "prd-NATGW"
  }
}
#####################   Route Tables  #####################
resource "aws_route_table" "RTPrivatePRD" {
  vpc_id = aws_vpc.VPCPRD.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.NATGWPRD.id
  }
  route {
    cidr_block = var.PublicSubnetDMZ
    gateway_id = aws_vpc_peering_connection.PeerVPC1.id
  }

  tags = {
    Name = "prd-RT-Private"
  }    
}
resource "aws_route_table" "RTPublicPRD" {
  vpc_id = aws_vpc.VPCPRD.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGWPRD.id
  }
  tags = {
    Name = "prd-RT-Public"
  }     
}

#####################   Subnet Association  #####################
resource "aws_route_table_association" "RouteTable1AssociationSubnet1PRD" {
  subnet_id      = aws_subnet.PublicSubnet1PRD.id
  route_table_id = aws_route_table.RTPublicPRD.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet2PRD" {
  subnet_id      = aws_subnet.PublicSubnet2PRD.id
  route_table_id = aws_route_table.RTPublicPRD.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet3PRD" {
  subnet_id      = aws_subnet.PublicSubnet3PRD.id
  route_table_id = aws_route_table.RTPublicPRD.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet4PRD" {
  subnet_id      = aws_subnet.PrivateSubnet1PRD.id
  route_table_id = aws_route_table.RTPrivatePRD.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet5PRD" {
  subnet_id      = aws_subnet.PrivateSubnet2PRD.id
  route_table_id = aws_route_table.RTPrivatePRD.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet6PRD" {
  subnet_id      = aws_subnet.PrivateSubnet3PRD.id
  route_table_id = aws_route_table.RTPrivatePRD.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet7PRD" {
  subnet_id      = aws_subnet.NATSubnetPRD.id
  route_table_id = aws_route_table.RTPublicPRD.id
}
#####################   ACL  #####################
resource "aws_network_acl" "ACLPublicPRD" {
  vpc_id = aws_vpc.VPCPRD.id
  subnet_ids = [aws_subnet.PublicSubnet1PRD.id, aws_subnet.PublicSubnet2PRD.id, aws_subnet.PublicSubnet3PRD.id]
  egress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0
    }

  ingress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0      
    }
  tags = {
    Name = "prd-ACL-Public"    
  }
}
resource "aws_network_acl" "ACLPrivatePRD" {
  vpc_id = aws_vpc.VPCPRD.id
  subnet_ids = [aws_subnet.PrivateSubnet1PRD.id, aws_subnet.PrivateSubnet2PRD.id, aws_subnet.PrivateSubnet3PRD.id]
  egress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0
    }

  ingress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0      
    }
  tags = {
    Name = "prd-ACL-Private"    
  }
}
#####################   Security Group  #####################
#Allow http, https from 0.0.0.0/0
resource "aws_security_group" "SGALBPRD" {
  name        = "prd-SG-ALB"
  vpc_id       = aws_vpc.VPCPRD.id
  description  = "ALB Security Group"
  ingress {
    description = "Allow https traffic"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }
  ingress {
    description = "Allow http traffic"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }  
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }
  tags = {
    Name = "prd-SG-ALB"
   }
}

#Allow http, https from SGALB and ssh from SG DMZ
resource "aws_security_group" "SGEC2PRD" {
  name        = "prd-SG-EC2"
  vpc_id       = aws_vpc.VPCPRD.id
  description  = "VPC Security Group"
  ingress {
    description = "Allow ssh traffic"
    security_groups = [aws_security_group.SGDMZ.id]
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }
  ingress {
    description = "Allow http traffic"
    security_groups = [aws_security_group.SGALBPRD.id]
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }
  tags = {
    Name = "prd-SG-EC2"
   }
}
#################### DNS Route 53 ############################
data "aws_route53_zone" "dns_name" {
  name  = var.dns_name
}

#Create record in hosted zone for ACM Certificate Domain verification
resource "aws_route53_record" "acm_validation" {
  for_each = {
    for val in aws_acm_certificate.cert.domain_validation_options : val.domain_name => {
      name   = val.resource_record_name
      record = val.resource_record_value
      type   = val.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.dns_name.zone_id
}

#Create entry on DNS for ALB
resource "aws_route53_record" "alb_ebPRD" {
  zone_id = data.aws_route53_zone.dns_name.zone_id
  name    = join(".", ["django-prd", data.aws_route53_zone.dns_name.name])
  type    = "A"
  alias {
    name                   = aws_lb.ALBPRD.dns_name
    zone_id                = aws_lb.ALBPRD.zone_id
    evaluate_target_health = true
  }
}

#################### AWS Certificate Manager #######################
resource "aws_acm_certificate" "cert" {
  domain_name       = join(".", ["django-prd", data.aws_route53_zone.dns_name.name])
  validation_method = "DNS"

  tags = {
    Environment = "EB-prd-ALB-cert"
  }
}

resource "aws_acm_certificate_validation" "cert_validation" {
  certificate_arn         = aws_acm_certificate.cert.arn
  validation_record_fqdns = [for record in aws_route53_record.acm_validation : record.fqdn]
}
#################### Application Loadbalancer ######################
resource "aws_lb" "ALBPRD" {
  name               = "ALB-prd"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.SGALBPRD.id]
  subnets            = [aws_subnet.PublicSubnet1PRD.id, aws_subnet.PublicSubnet2PRD.id,aws_subnet.PublicSubnet3PRD.id] 
  enable_deletion_protection = false
  tags = {
    Name = "ALB-prd-"
  }
}
#Listener HTTP
resource "aws_lb_listener" "alb_listener_httpPRD" {
  load_balancer_arn = aws_lb.ALBPRD.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener_rule" "redirect"{
    listener_arn = aws_lb_listener.alb_listener_httpsPRD.arn
    priority     = 2
    action {
        type = "redirect"
        redirect {
           port = "443"
           protocol = "HTTPS"
           status_code = "HTTP_301"
            host = "${aws_elastic_beanstalk_environment.EBEnvPRD.cname}"
        }
    }
    condition {
      path_pattern {
        values = ["/*"]
      }
    }
}

#Listener HTTPS
resource "aws_lb_listener" "alb_listener_httpsPRD" {
  load_balancer_arn = aws_lb.ALBPRD.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.cert.arn
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_targetgroupPRD.arn
 }
}
#target Group
resource "aws_lb_target_group" "alb_targetgroupPRD" {
  name     = "EB-prd-env-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.VPCPRD.id
  health_check {
    enabled  = true
    interval = 15
    path     = "/"
    protocol = "HTTP"
    matcher  = "200"
  }
  tags = {
    Name = "EB-prd-env-target-group"
  }
}

############ Key Pair #############
resource "tls_private_key" "key_pair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2key" {
  key_name   = "ec2-key"
  public_key = tls_private_key.key_pair.public_key_openssh
}

#save the key-pair locally from where terraform had run
resource "local_file" "ssh_key" {
  filename = "${aws_key_pair.ec2key.key_name}.pem"
  content  = tls_private_key.key_pair.private_key_pem
}

############ Role ################
resource "aws_iam_role" "EC2Role" {
  name = "aws-elasticbeanstalk-ec2-role"
  managed_policy_arns = ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier","arn:aws:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker","arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier"]
  assume_role_policy = jsonencode({
    Version = "2008-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "aws-elasticbeanstalk-ec2-role"
  }
}

resource "aws_iam_instance_profile" "EC2InstanceProfile" {
  name = "ElasticbeanstalkEC2InstanceProfile"
  role = aws_iam_role.EC2Role.name
}

resource "aws_iam_role" "EBserviceRole" {
  name = "aws-elasticbeanstalk-service-role"
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth","arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"]
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "elasticbeanstalk.amazonaws.com"
        }
        Condition = {
            StringEquals = {
                "sts:ExternalId" = "elasticbeanstalk"
            }
        }      
      },
    ]
  })

  tags = {
    tag-key = "aws-elasticbeanstalk-service-role"
  }
}
############################# Elastic Beanstalk ######################################
resource "aws_elastic_beanstalk_application" "EBApp" {
  name        = "django-app"
}

resource "aws_elastic_beanstalk_environment" "EBEnvPRD" {
  name                = "django-env-prd"
  application         = aws_elastic_beanstalk_application.EBApp.name
  solution_stack_name = "64bit Amazon Linux 2 v3.3.13 running Python 3.8"

  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "ServiceRole"
    value = "${aws_iam_role.EBserviceRole.arn}"
  }  
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     =  "${aws_iam_instance_profile.EC2InstanceProfile.arn}"
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.VPCPRD.id
  }  
  setting {
    namespace = "aws:ec2:vpc"
    name      = "AssociatePublicIpAddress"
    value     =  "false"
  }
 setting {
   namespace = "aws:ec2:vpc"
   name      = "Subnets"
   value     = "${join(",",[aws_subnet.PrivateSubnet1PRD.id,aws_subnet.PrivateSubnet2PRD.id,aws_subnet.PrivateSubnet3PRD.id])}"
 }
 setting {
   namespace = "aws:ec2:vpc"
   name      = "ELBSubnets"
   value     = "${join(",",[aws_subnet.PublicSubnet1PRD.id,aws_subnet.PublicSubnet2PRD.id,aws_subnet.PublicSubnet3PRD.id])}"
 } 
   setting {
    namespace = "aws:ec2:vpc"
    name      = "ELBScheme"
    value     = "public"
  } 
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "InstanceType"
    value     = "t2.micro"
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "EC2KeyName"
    value     = "${aws_key_pair.ec2key.key_name}"
  }  
 setting {
   namespace = "aws:autoscaling:launchconfiguration"
   name      = "SSHSourceRestriction"
   value     = "tcp, 22, 22, ${aws_security_group.SGDMZ.id}"
 }
 setting {
   namespace = "aws:autoscaling:asg"
   name      = "MinSize"
   value     = 2
 }
 setting {
   namespace = "aws:autoscaling:asg"
   name      = "MaxSize"
   value     = 4
 }
 setting {
   namespace = "aws:autoscaling:trigger"
   name      = "MeasureName"
   value     = "NetworkIn"
 }

  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "SecurityGroups"
    value     = "${aws_security_group.SGEC2PRD.id}"
  }
   setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "LoadBalancerIsShared"
    value = "true"
  } 
  setting {
    namespace = "aws:elbv2:loadbalancer"
    name = "SharedLoadBalancer"
    value = "${aws_lb.ALBPRD.arn}"
  }
  setting {
    namespace = "aws:elbv2:loadbalancer"
    name = "SecurityGroups"
    value = "${aws_security_group.SGALBPRD.id}"
  }
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "LoadBalancerType"
    value     = "application"
  }  
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "StickinessEnabled"
    value     = "true"
  }
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "Port"
    value     = "80"
  }  
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "Protocol"
    value     = "HTTP"
  }   
  setting {
    namespace = "aws:elbv2:listener:443"
    name      = "Rules"
    value     = "default"
  }    
  setting {
    namespace = "aws:elbv2:listener:443"
    name      = "Protocol"
    value     = "HTTPS"
  }    
  setting {
    namespace = "aws:elbv2:listener:443"
    name      = "SSLCertificateArns"
    value     = "${aws_acm_certificate.cert.arn}"
  }
  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name = "SystemType"
    value = "enhanced"
  }
  setting {
    namespace = "aws:elbv2:listener:default"
    name = "ListenerEnabled"
    value = "False"
  }
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "EnvironmentType"
    value = "LoadBalanced"
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name = "DisableIMDSv1"
    value = "true"
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions:platformupdate"
    name = "UpdateLevel"
    value = "minor"
  }                    
}

#Create S3 bucket
resource "aws_s3_bucket" "S3" {
}

#upload django app to S3
resource "aws_s3_object" "S3file" {
  bucket = aws_s3_bucket.S3.id
  key    = "mysite.zip"
  source = "mysite.zip"
}

#create Elastic Beanstalk App Version
resource "aws_elastic_beanstalk_application_version" "EBAppVersionPRD" {
  name        = "django-app-prd-v1"
  application = aws_elastic_beanstalk_application.EBApp.name
  bucket      = aws_s3_bucket.S3.id
  key         = aws_s3_object.S3file.id
}

#TST Environment
#####################   VPC  #####################
resource "aws_vpc" "VPCTST" {
  cidr_block = var.vpcCIDRTST
  tags = {
    Name = "VPC-tst"
  }
}
#####################   Subnets  #####################
resource "aws_subnet" "PublicSubnet1TST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.PublicSubnet1TST
  map_public_ip_on_launch = "true"
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "tst-Public-Subnet1"
  }  
}
  resource "aws_subnet" "PublicSubnet2TST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.PublicSubnet2TST
  availability_zone = data.aws_availability_zones.AZs.names[2]
  tags = {
    Name = "tst-Public-Subnet2"
  }    
}
  resource "aws_subnet" "PublicSubnet3TST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.PublicSubnet3TST
  availability_zone = data.aws_availability_zones.AZs.names[3]
  tags = {
    Name = "tst-Public-Subnet3"
  }  
}
resource "aws_subnet" "PrivateSubnet1TST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.PrivateSubnet1TST
  map_public_ip_on_launch = "false"  
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "tst-Private-Subnet1"
  }  
}
  resource "aws_subnet" "PrivateSubnet2TST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.PrivateSubnet2TST
  map_public_ip_on_launch = "false"   
  availability_zone = data.aws_availability_zones.AZs.names[2]
  tags = {
    Name = "tst-Private-Subnet2"
  }
}
  resource "aws_subnet" "PrivateSubnet3TST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.PrivateSubnet3TST
  map_public_ip_on_launch = "false"   
  availability_zone = data.aws_availability_zones.AZs.names[3]
  tags = {
    Name = "tst-Private-Subnet3"
  }
}
  resource "aws_subnet" "NATSubnetTST" {
  vpc_id     = aws_vpc.VPCTST.id
  cidr_block = var.NATSubnetTST
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "tst-NATGW-Subnet"
  }
}
#####################   Internet Gateway  #####################
resource "aws_internet_gateway" "IGWTST" {
  vpc_id = aws_vpc.VPCTST.id
  tags = {
    Name = "tst-VPC-IGW"
  }  
}
#####################   NAT Gateway  #####################
resource "aws_eip" "NATEIPTST" {
  tags = {
    Name = "tst-NATGW-EIP"
  }
}

resource "aws_nat_gateway" "NATGWTST" {
  allocation_id = aws_eip.NATEIPTST.id
  subnet_id     = aws_subnet.NATSubnetTST.id
  tags = {
    Name = "tst-NATGW"
  }
}
#####################   Route Tables  #####################
resource "aws_route_table" "RTPrivateTST" {
  vpc_id = aws_vpc.VPCTST.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.NATGWTST.id
  }
  route {
    cidr_block = var.PublicSubnetDMZ
    gateway_id = aws_vpc_peering_connection.PeerVPC2.id
  }
  tags = {
    Name = "tst-RT-Private"
  }    
}
resource "aws_route_table" "RTPublicTST" {
  vpc_id = aws_vpc.VPCTST.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGWTST.id
  }
  tags = {
    Name = "tst-RT-Public"
  }     
}

#####################   Subnet Association  #####################
resource "aws_route_table_association" "RouteTable1AssociationSubnet1" {
  subnet_id      = aws_subnet.PublicSubnet1TST.id
  route_table_id = aws_route_table.RTPublicTST.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet2" {
  subnet_id      = aws_subnet.PublicSubnet2TST.id
  route_table_id = aws_route_table.RTPublicTST.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet3" {
  subnet_id      = aws_subnet.PublicSubnet3TST.id
  route_table_id = aws_route_table.RTPublicTST.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet4" {
  subnet_id      = aws_subnet.PrivateSubnet1TST.id
  route_table_id = aws_route_table.RTPrivateTST.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet5" {
  subnet_id      = aws_subnet.PrivateSubnet2TST.id
  route_table_id = aws_route_table.RTPrivateTST.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet6" {
  subnet_id      = aws_subnet.PrivateSubnet3TST.id
  route_table_id = aws_route_table.RTPrivateTST.id
}
resource "aws_route_table_association" "RouteTable1AssociationSubnet7" {
  subnet_id      = aws_subnet.NATSubnetTST.id
  route_table_id = aws_route_table.RTPublicTST.id
}
#####################   ACL  #####################
resource "aws_network_acl" "ACLPublicTST" {
  vpc_id = aws_vpc.VPCTST.id
  subnet_ids = [aws_subnet.PublicSubnet1TST.id, aws_subnet.PublicSubnet2TST.id, aws_subnet.PublicSubnet3TST.id]
  egress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0
    }

  ingress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0      
    }
  tags = {
    Name = "tst-ACL-Public"    
  }
}
resource "aws_network_acl" "ACLPrivateTST" {
  vpc_id = aws_vpc.VPCTST.id
  subnet_ids = [aws_subnet.PrivateSubnet1TST.id, aws_subnet.PrivateSubnet2TST.id, aws_subnet.PrivateSubnet3TST.id]
  egress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0
    }

  ingress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0      
    }
  tags = {
    Name = "tst-ACL-Private"    
  }
}
#####################   Security Group  #####################
#Allow http, https from 0.0.0.0/0
resource "aws_security_group" "SGALBTST" {
  name        = "tst-SG-ALB"
  vpc_id       = aws_vpc.VPCTST.id
  description  = "ALB Security Group"
  ingress {
    description = "Allow https traffic"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }
  ingress {
    description = "Allow http traffic"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }  
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }
  tags = {
    Name = "tst-SG-ALB"
   }
}

#Allow http, https from SGALB and ssh from 0.0.0.0/0
resource "aws_security_group" "SGEC2TST" {
  name        = "tst-SG-EC2"
  vpc_id       = aws_vpc.VPCTST.id
  description  = "VPC Security Group"
  ingress {
    description = "Allow ssh traffic"
    security_groups = [aws_security_group.SGDMZ.id]
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }
  ingress {
    description = "Allow http traffic"
    security_groups = [aws_security_group.SGALBTST.id]
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }

  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }
  tags = {
    Name = "tst-SG-EC2"
   }
}
#################### DNS Route 53 ############################

#Create record in hosted zone for ACM Certificate Domain verification
resource "aws_route53_record" "acm_validationTST" {
  for_each = {
    for val in aws_acm_certificate.certTST.domain_validation_options : val.domain_name => {
      name   = val.resource_record_name
      record = val.resource_record_value
      type   = val.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.dns_name.zone_id
}
#Create entry on DNS for ALB
resource "aws_route53_record" "alb_ebTST" {
  zone_id = data.aws_route53_zone.dns_name.zone_id
  name    = join(".", ["django-tst", data.aws_route53_zone.dns_name.name])
  type    = "A"
  alias {
    name                   = aws_lb.ALBTST.dns_name
    zone_id                = aws_lb.ALBTST.zone_id
    evaluate_target_health = true
  }
}

#################### AWS Certificate Manager #######################
resource "aws_acm_certificate" "certTST" {
  domain_name       = join(".", ["django-tst", data.aws_route53_zone.dns_name.name])
  validation_method = "DNS"

  tags = {
    Environment = "EB-tst-ALB-certTST"
  }
}

resource "aws_acm_certificate_validation" "cert_validationTST" {
  certificate_arn         = aws_acm_certificate.certTST.arn
  validation_record_fqdns = [for record in aws_route53_record.acm_validationTST : record.fqdn]
}
#################### Application Loadbalancer ######################
resource "aws_lb" "ALBTST" {
  name               = "ALB-tst"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.SGALBTST.id]
  subnets            = [aws_subnet.PublicSubnet1TST.id, aws_subnet.PublicSubnet2TST.id,aws_subnet.PublicSubnet3TST.id] 
  enable_deletion_protection = false
  tags = {
    Name = "ALB-tst-"
  }
}
#target Group
resource "aws_lb_target_group" "alb_targetgroupTST" {
  name     = "EB-tst-env-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.VPCTST.id
  health_check {
    enabled  = true
    interval = 15
    path     = "/"
    protocol = "HTTP"
    matcher  = "200"
  }
  tags = {
    Name = "EB-tst-env-target-group"
  }
}

#Listener HTTP
resource "aws_lb_listener" "alb_listener_httpTST" {
  load_balancer_arn = aws_lb.ALBTST.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type             = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

#Listener HTTPS
resource "aws_lb_listener" "alb_listener_httpsTST" {
  load_balancer_arn = aws_lb.ALBTST.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.certTST.arn
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.alb_targetgroupTST.arn
 }
}
resource "aws_lb_listener_rule" "redirectTST"{
    listener_arn = aws_lb_listener.alb_listener_httpsTST.arn
    priority     = 2
    action {
        type = "redirect"
        redirect {
           port = "443"
           protocol = "HTTPS"
           status_code = "HTTP_301"
            host = "${aws_elastic_beanstalk_environment.EBEnvTST.cname}"
        }
    }
    condition {
      path_pattern {
        values = ["/*"]
      }
    }
}

############################# Elastic Beanstalk ######################################

resource "aws_elastic_beanstalk_environment" "EBEnvTST" {
  name                = "django-env-tst"
  application         = aws_elastic_beanstalk_application.EBApp.name
  solution_stack_name = "64bit Amazon Linux 2 v3.3.13 running Python 3.8"

  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "ServiceRole"
    value = "${aws_iam_role.EBserviceRole.arn}"
  }  
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "IamInstanceProfile"
    value     =  "${aws_iam_instance_profile.EC2InstanceProfile.arn}"
  }
  setting {
    namespace = "aws:ec2:vpc"
    name      = "VPCId"
    value     = aws_vpc.VPCTST.id
  }  
  setting {
    namespace = "aws:ec2:vpc"
    name      = "AssociatePublicIpAddress"
    value     =  "false"
  }
 setting {
   namespace = "aws:ec2:vpc"
   name      = "Subnets"
   value     = "${join(",",[aws_subnet.PrivateSubnet1TST.id,aws_subnet.PrivateSubnet2TST.id,aws_subnet.PrivateSubnet3TST.id])}"
 }
 setting {
   namespace = "aws:ec2:vpc"
   name      = "ELBSubnets"
   value     = "${join(",",[aws_subnet.PublicSubnet1TST.id,aws_subnet.PublicSubnet2TST.id,aws_subnet.PublicSubnet3TST.id])}"
 } 
   setting {
    namespace = "aws:ec2:vpc"
    name      = "ELBScheme"
    value     = "public"
  } 
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "InstanceType"
    value     = "t2.micro"
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "EC2KeyName"
    value     = "${aws_key_pair.ec2key.key_name}"
  }  

 setting {
   namespace = "aws:autoscaling:asg"
   name      = "MinSize"
   value     = 2
 }
 setting {
   namespace = "aws:autoscaling:asg"
   name      = "MaxSize"
   value     = 4
 }
 setting {
   namespace = "aws:autoscaling:trigger"
   name      = "MeasureName"
   value     = "NetworkIn"
 }
 setting {
   namespace = "aws:autoscaling:launchconfiguration"
   name      = "SSHSourceRestriction"
   value     = "tcp, 22, 22, ${aws_security_group.SGDMZ.id}"
 }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name      = "SecurityGroups"
    value     = "${aws_security_group.SGEC2TST.id}"
  }
   setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "LoadBalancerIsShared"
    value = "true"
  } 
  setting {
    namespace = "aws:elbv2:loadbalancer"
    name = "SharedLoadBalancer"
    value = "${aws_lb.ALBTST.arn}"
  }
  setting {
    namespace = "aws:elbv2:loadbalancer"
    name = "SecurityGroups"
    value = "${aws_security_group.SGALBTST.id}"
  }
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name      = "LoadBalancerType"
    value     = "application"
  }  
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "StickinessEnabled"
    value     = "true"
  }
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "Port"
    value     = "80"
  }  
  setting {
    namespace = "aws:elasticbeanstalk:environment:process:default"
    name      = "Protocol"
    value     = "HTTP"
  }   
  setting {
    namespace = "aws:elbv2:listener:443"
    name      = "Rules"
    value     = "default"
  }    
  setting {
    namespace = "aws:elbv2:listener:443"
    name      = "Protocol"
    value     = "HTTPS"
  }    
  setting {
    namespace = "aws:elbv2:listener:443"
    name      = "SSLCertificateArns"
    value     = "${aws_acm_certificate.certTST.arn}"
  }
  setting {
    namespace = "aws:elasticbeanstalk:healthreporting:system"
    name = "SystemType"
    value = "enhanced"
  }
  setting {
    namespace = "aws:elbv2:listener:default"
    name = "ListenerEnabled"
    value = "False"
  }
  setting {
    namespace = "aws:elasticbeanstalk:environment"
    name = "EnvironmentType"
    value = "LoadBalanced"
  }
  setting {
    namespace = "aws:autoscaling:launchconfiguration"
    name = "DisableIMDSv1"
    value = "true"
  }
  setting {
    namespace = "aws:elasticbeanstalk:managedactions:platformupdate"
    name = "UpdateLevel"
    value = "minor"
  }                    
}

#create Elastic Beanstalk App Version
resource "aws_elastic_beanstalk_application_version" "EBAppVersionTST" {
  name        = "django-app-tst-v1"
  application = aws_elastic_beanstalk_application.EBApp.name
  bucket      = aws_s3_bucket.S3.id
  key         = aws_s3_object.S3file.id
}

#################   DMZ Environment ##################
variable vpcDMZ {
    default="172.16.0.0/24"
}
variable PublicSubnetDMZ {
    default="172.16.0.0/24"
}    
variable ExternalIP {}

###### VPC  ############
resource "aws_vpc" "VPCDMZ" {
  cidr_block = var.vpcDMZ
  tags = {
    Name = "VPC-dmz"
  }
}
###### Subnets  ############
resource "aws_subnet" "PublicSubnet1" {
  vpc_id     = aws_vpc.VPCDMZ.id
  cidr_block = var.PublicSubnetDMZ
  map_public_ip_on_launch = "true"
  availability_zone = data.aws_availability_zones.AZs.names[1]
  tags = {
    Name = "dmz-Public-Subnet1"
  }  
}

###### IGW  ############
resource "aws_internet_gateway" "IGW" {
  vpc_id = aws_vpc.VPCDMZ.id
  tags = {
    Name = "dmz-VPC-IGW"
  }  
}

###### Route Table  ############
resource "aws_route_table" "RTPublic" {
  vpc_id = aws_vpc.VPCDMZ.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGW.id
  }
  route {
    cidr_block = var.vpcCIDRPRD
    gateway_id = aws_vpc_peering_connection.PeerVPC1.id
  }
  route {
    cidr_block = var.vpcCIDRTST
    gateway_id = aws_vpc_peering_connection.PeerVPC2.id
  }
  tags = {
    Name = "dmz-RT-Public"
  }    
}

resource "aws_route_table_association" "RouteTable1AssociationSubnet1dMZ" {
  subnet_id      = aws_subnet.PublicSubnet1.id
  route_table_id = aws_route_table.RTPublic.id
}

###### ACL  ############
resource "aws_network_acl" "ACLPublicDMZ" {
  vpc_id = aws_vpc.VPCDMZ.id
  subnet_ids = [aws_subnet.PublicSubnet1.id]
  egress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0
    }

  ingress {
      protocol   = "-1"
      rule_no    = 100
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 0
      to_port    = 0     
    }
  tags = {
    Name = "dmz-ACL-Public"    
  }
}

###### Security Group  ############
resource "aws_security_group" "SGDMZ" {
  name        = "dmz-SG-Bastion"
  vpc_id       = aws_vpc.VPCDMZ.id
  description  = "Allow SSH Traffic"
  ingress {
    description = "Allow SSH traffic"
    cidr_blocks = ["${var.ExternalIP}/32"]
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  } 
  egress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
  }
  tags = {
    Name = "dmz-SG-Bastion"
   }
}

######## VPC Peering  ############
resource "aws_vpc_peering_connection" "PeerVPC1" {
  peer_vpc_id   = aws_vpc.VPCPRD.id
  vpc_id        = aws_vpc.VPCDMZ.id
  auto_accept = true
  tags =  {
      Name="VPC-DMZ-VPC-PRD"
  }
}
resource "aws_vpc_peering_connection" "PeerVPC2" {
  peer_vpc_id   = aws_vpc.VPCTST.id
  vpc_id        = aws_vpc.VPCDMZ.id
  auto_accept = true
  tags =  {
      Name="VPC-DMZ-VPC-TST"
  }
}

############ EC2 Key Pair ##########
resource "tls_private_key" "key_pairDMZ" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2keyDMZ" {
  key_name   = "ec2-key-dmz"
  public_key = tls_private_key.key_pairDMZ.public_key_openssh
}

#save the key-pair locally from where terraform had run
resource "local_file" "ssh_keyDMZ" {
  filename = "${aws_key_pair.ec2keyDMZ.key_name}.pem"
  content  = tls_private_key.key_pairDMZ.private_key_pem
}

############ EC2 Instance in DMZ ##########
resource "aws_network_interface" "DMZNIC" {
  subnet_id   = aws_subnet.PublicSubnet1.id
  security_groups = [aws_security_group.SGDMZ.id]
  tags = {
    Name = "dmz-NIC"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = "true"
  owners = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }  
}

resource "aws_instance" "DMZEC2" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.ec2keyDMZ.key_name
  network_interface {
    network_interface_id = aws_network_interface.DMZNIC.id
    device_index         = 0
  }
  tags = {
    Name = "VM-Bastion"
  }
}

#output "app_versionPRD" {
#  value = "${aws_elastic_beanstalk_application_version.EBAppVersionPRD.name}"
#}
#output "env_namePRD" {
#  value = "${aws_elastic_beanstalk_environment.EBEnvPRD.name}"
#}
#output "app_versionTST" {
#  value = "${aws_elastic_beanstalk_application_version.EBAppVersionTST.name}"
#}
#output "env_nameTST" {
#  value = "${aws_elastic_beanstalk_environment.EBEnvTST.name}"
#}

output "Django_PRD_URL" {
  value = aws_elastic_beanstalk_environment.EBEnvPRD.cname
  }
output "Django_TST_URL" {
  value = aws_elastic_beanstalk_environment.EBEnvTST.cname
}


