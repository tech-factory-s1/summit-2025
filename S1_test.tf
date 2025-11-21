###############################
# Intentional insecure Terraform
# - For scanner testing only
# - Contains hard-coded credentials, secrets, public bucket, open SG, and vulnerable package installs
###############################

# ------------------------
# PROVIDER WITH HARD-CODED KEYS (INSECURE)
# ------------------------
provider "aws" {
  region     = "us-east-1"
  # Intentional insecure hard-coded credentials (fake values)
  access_key = "FAKE_AWS_ACCESS_KEY_ID_EXAMPLE"
  secret_key = "FAKE_AWS_SECRET_ACCESS_KEY_EXAMPLE"
}

# ------------------------
# LOCAL VALUES INCLUDING AN OAUTH TOKEN (HARD-CODED SECRET)
# ------------------------
locals {
  # Fake OAuth/GitHub token intentionally hard-coded for detection
  github_oauth_token = "ghp_FAKE_GITHUB_OAUTH_TOKEN_FOR_TESTING"
  slack_token        = "xoxp-FAKE-SLACK-TOKEN-123456"
}

# ------------------------
# S3 BUCKET: PUBLIC (MISCONFIGURATION)
# ------------------------
resource "aws_s3_bucket" "public_bucket" {
  bucket = "iac-test-public-bucket-12345"
  acl    = "public-read"   # insecure: public-read ACL

  website {
    index_document = "index.html"
  }

  tags = {
    Name = "Public bucket for scanner testing"
    Env  = "test"
  }
}

# Put a file containing a "secret" into the bucket (for scanners that look for PII/secrets in storage)
resource "aws_s3_bucket_object" "secret_file" {
  bucket = aws_s3_bucket.public_bucket.id
  key    = "secrets/credentials.txt"
  content = <<EOT
AWS_ACCESS_KEY_ID=FAKE_AWS_ACCESS_KEY_ID_EXAMPLE
AWS_SECRET_ACCESS_KEY=FAKE_AWS_SECRET_ACCESS_KEY_EXAMPLE
GITHUB_OAUTH=${local.github_oauth_token}
SLACK_TOKEN=${local.slack_token}
EOT
  acl = "public-read"  # insecure: makes this secret file readable by anyone
}

# ------------------------
# SECURITY GROUP: ALL INGRESS OPEN (MISCONFIGURATION)
# ------------------------
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Open SG for testing - INSECURE"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # insecure: full open access
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Env = "test"
  }
}

# ------------------------
# EC2 INSTANCE: user_data installs vulnerable packages and writes an oauth token to disk
# ------------------------
resource "aws_instance" "vulnerable_host" {
  ami           = "ami-0c55b159cbfafe1f0" # example public AMI (change for your region if you apply)
  instance_type = "t2.micro"
  security_groups = [aws_security_group.open_sg.name]

  user_data = <<-EOF
              #!/bin/bash
              # INTENTIONAL: install old/vulnerable packages for testing scanners
              # Python vulnerable package (old Django)
              apt-get update -y
              apt-get install -y python3 python3-pip nodejs npm

              # vulnerable python package (old Django 1.11.x)
              pip3 install "Django==1.11.29"

              # vulnerable npm package (old lodash)
              npm install lodash@4.17.4

              # INTENTIONAL: write hard-coded OAuth token to disk (detectors should find this)
              cat >/etc/oauth_token <<-TOKEN
              ${local.github_oauth_token}
              TOKEN

              # create a local file with AWS creds (simulates accidental commit)
              mkdir -p /home/ubuntu/testcreds
              cat >/home/ubuntu/testcreds/.aws_credentials <<-CRED
              [default]
              aws_access_key_id = FAKE_AWS_ACCESS_KEY_ID_EXAMPLE
              aws_secret_access_key = FAKE_AWS_SECRET_ACCESS_KEY_EXAMPLE
              CRED

              EOF

  tags = {
    Name = "vulnerable-host-for-scanning"
    Env  = "test"
  }

  # Note: avoid allocating public IPs in real testing unless isolated
  associate_public_ip_address = true
}

# ------------------------
# LOCAL FILE (MIMICING A CONFIG FILE WITH SECRET)
# ------------------------
resource "local_file" "app_config" {
  content = <<-CFG
  {
    "db_host": "10.0.0.5",
    "db_user": "appuser",
    "db_password": "P@ssw0rd_FAKE_DB_PASSWORD",   # hard-coded DB password
    "third_party": {
      "client_id": "fake-client-id-123",
      "client_secret": "fake-client-secret-456"
    }
  }
  CFG
  filename = "${path.module}/test_app_config.json"
}

# ------------------------
# OUTPUTS (so scanners can index outputs)
# ------------------------
output "s3_bucket_name" {
  value = aws_s3_bucket.public_bucket.bucket
}

output "vulnerable_instance_id" {
  value = aws_instance.vulnerable_host.id
}
