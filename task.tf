provider "aws" {

   region= "ap-south-1"

}


resource "tls_private_key" "mykey" {

  algorithm = "RSA"
  
  rsa_bits  = 4096

}


resource "aws_key_pair" "generated_key" {

  key_name   = "pvtkey"

  public_key = tls_private_key.mykey.public_key_openssh

}


resource "local_file" "pvtkey" {

    content  = tls_private_key.mykey.private_key_pem

    filename = "task1key.pem"

    file_permission =  0400

}



resource "aws_security_group" "sg_web" {

  name        = "sg_web"

  description = "Allow SSH http ingress"


  
  ingress {

    description =" ssh"

    from_port   = 22

    to_port     = 22

    protocol    = "tcp"

    cidr_blocks =["0.0.0.0/0"]

  }

  ingress {

    description ="http"

    from_port   = 80

    to_port     = 80

    protocol    = "tcp"

    cidr_blocks =["0.0.0.0/0"]

  }

  
  egress {

    from_port   = 0

    to_port     = 0

    protocol    = "-1"

    cidr_blocks = ["0.0.0.0/0"]

  }


  tags = {

    Name = "allow_ssh_http"

  }

}
 
 
resource "aws_instance" "web" {

  ami  = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"

  key_name = aws_key_pair.generated_key.key_name

  security_groups = ["sg_web"]
 
  
  depends_on = [
    
		aws_security_group.sg_web,
  
	]



 connection {
    type     = "ssh"
    user     = "ec2-user"
    port     = 22
    host     = aws_instance.web.public_ip
    private_key = tls_private_key.mykey.private_key_pem
  }

    provisioner "remote-exec" {
      inline = [
        "sudo yum install httpd  php git -y",
        "sudo systemctl restart httpd",
        "sudo systemctl enable httpd",
    ]
  }  

  tags = {

    Name = "mywebinstance"

  }

}

resource "aws_ebs_volume" "webebs" {
  availability_zone = aws_instance.web.availability_zone
  size              = 1

  tags = {
    Name = "Webebs"
  }
}

resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdh"
  volume_id   = aws_ebs_volume.webebs.id
  instance_id = aws_instance.web.id
  force_detach = true
   depends_on = [
    aws_ebs_volume.webebs,
    aws_instance.web
    ]
}

resource "aws_s3_bucket" "bucket" {
  bucket = "bk2444"
  acl    = "private"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_object" "object" {
  bucket = "bk2444"
  key    = "pic.png"
  source = "pic.png"
  acl    = "public-read"
  depends_on = [ 
	aws_s3_bucket.bucket,
	 ]
}


resource "null_resource" "null1"  {
  depends_on = [
    aws_volume_attachment.ebs_att,
  ]

  connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = tls_private_key.mykey.private_key_pem
    host     = aws_instance.web.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/NikitaAgarwal03/hybrid_task1_web.git /var/www/html"
    ]
  }
}



#CLOUD FRONT

locals {
  s3_origin_id = aws_s3_bucket.bucket.id
}

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
  comment = "Some comment"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id

    s3_origin_config {
  origin_access_identity = aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path
}
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "My cloudfront"
  default_root_object = "pic.png"


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }


  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
  depends_on = [aws_s3_bucket.bucket]

connection {
        type    = "ssh"
        user    = "ec2-user"
        host    = aws_instance.web.public_ip
        port    = 22
        private_key = tls_private_key.mykey.private_key_pem
    }
provisioner "remote-exec" {
        inline  = [
            # "sudo su << \"EOF\" \n echo \"<img src='${self.domain_name}'>\" >> /var/www/html/index.php \n \"EOF\""
            "sudo su << EOF",
            "echo \"<img src='http://${self.domain_name}/${aws_s3_bucket_object.object.key}'>\" >> /var/www/html/index.php",
            "EOF"
        ]
}
}