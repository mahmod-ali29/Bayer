provider "aws" {}

variable vpc {
    default="172.16.0.0/24"
}
variable PublicSubnet {
    default="172.16.0.0/24"
}    

###### VPC  ############
resource "aws_vpc" "VPC" {
  cidr_block = var.vpc
  tags = {
    Name = "VPC-1"
  }
}
###### Subnets  ############
resource "aws_subnet" "PublicSubnet1" {
  vpc_id     = aws_vpc.VPC.id
  cidr_block = var.PublicSubnet
  map_public_ip_on_launch = "true"
  tags = {
    Name = "Public-Subnet1"
  }  
}

###### IGW  ############
resource "aws_internet_gateway" "IGW" {
  vpc_id = aws_vpc.VPC.id
  tags = {
    Name = "VPC-IGW"
  }  
}

###### Route Table  ############
resource "aws_route_table" "RTPublic" {
  vpc_id = aws_vpc.VPC.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.IGW.id
  }
  tags = {
    Name = "RT-Public"
  }    
}

resource "aws_route_table_association" "RouteTable1AssociationSubnet1dMZ" {
  subnet_id      = aws_subnet.PublicSubnet1.id
  route_table_id = aws_route_table.RTPublic.id
}

###### Security Group  ############
resource "aws_security_group" "SG" {
  name        = "SG-Django"
  vpc_id       = aws_vpc.VPC.id
  description  = "Allow SSH Traffic"
  ingress {
    description = "Allow SSH traffic"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }
  ingress {
    description = "Allow HTTPS traffic"
    cidr_blocks = ["0.0.0.0/0"]
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  } 
  ingress {
    description = "Allow HTTP traffic"
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
    Name = "SG-Django"
   }
}


############ EC2 Key Pair ##########
resource "tls_private_key" "key_pair" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2key" {
  key_name   = "ec2key"
  public_key = tls_private_key.key_pair.public_key_openssh
}

#save the key-pair locally from where terraform had run
resource "local_file" "ssh_key" {
  filename = "${aws_key_pair.ec2key.key_name}.pem"
  content  = tls_private_key.key_pair.private_key_pem
}

############ EC2 Instance in  ##########
resource "aws_network_interface" "NIC" {
  subnet_id   = aws_subnet.PublicSubnet1.id
  security_groups = [aws_security_group.SG.id]
  tags = {
    Name = "NIC"
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

resource "aws_instance" "EC2" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.ec2key.key_name
  user_data = <<EOF
	#! /bin/bash
  sudo apt update -y
  sudo apt install -y docker-compose
  git clone https://github.com/mahmod-ali29/Bayer.git
  cd Bayer/option1
  sudo docker-compose up
EOF
  network_interface {
    network_interface_id = aws_network_interface.NIC.id
    device_index         = 0
  }
  tags = {
    Name = "VM-Django"
  }
}
output "Django_IP" {
  value = "${aws_instance.EC2.public_ip}"
}
