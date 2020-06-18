 #Configure the AWS Provider
provider "aws" {
	region  = "ap-south-1"
	profile = "sshinde"
}
resource "tls_private_key" "t1key" {
  algorithm   = "RSA"

}

resource "aws_key_pair" "gen_key" {
  key_name   = "t1key" 
  public_key = "${tls_private_key.t1key.public_key_openssh}"

  depends_on = [
    		tls_private_key.t1key
  	]
}
resource "local_file" "key-file" {
  	content  = "${tls_private_key.t1key.private_key_pem}" 
  	filename = "t1key.pem"

  depends_on= [
	tls_private_key.t1key,
	aws_key_pair.gen_key
	]

}

resource "aws_security_group" "tasksecgrp" {
  name        = "tasksecgrp"
  description = "sec group for ssh and httpd"

    ingress {
    description = "SSH Port"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP Port"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Secgrp"
  }

}
resource "aws_instance"  "task1instance"  {
 	ami = "ami-0447a12f28fddb066" 
  	instance_type = "t2.micro"
  	key_name = "t1key"
  	security_groups = [ "${aws_security_group.tasksecgrp.name}" ]

	tags = {
    	  Name = "terraos" 
  	}
        
	
}
resource "aws_ebs_volume" "taskvol" {
  	availability_zone = aws_instance.task1instance.availability_zone
	size		  = 1
	tags = {
  	  Name = "awsebs"
  }
}

resource "aws_volume_attachment" "ebs_att" {
  device_name = "/dev/sdh"
  volume_id   = "${aws_ebs_volume.taskvol.id}"
  instance_id = "${aws_instance.task1instance.id}"
  force_detach = true
}
 output "test" {
    value = aws_instance.task1instance.public_ip
}

resource "null_resource" "nullremote" {

depends_on = [
    	aws_volume_attachment.ebs_att,
	aws_security_group.tasksecgrp,
]

	connection {
  	  type     = "ssh"
   	  user     = "ec2-user"
   	  private_key = "${tls_private_key.t1key.private_key_pem}" 
   	  host     = aws_instance.task1instance.public_ip
  }

 	provisioner "remote-exec" {
    inline = [
     "sudo yum install httpd  php git -y",
      "sudo service httpd start",
      "sudo chkconfig httpd on",	
      "sudo mkfs.ext4  /dev/xvdh",
      "sudo mount  /dev/xvdh  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/snehal3099/webserver.git  /var/www/html/"
    ]
  }
}
resource "aws_s3_bucket" "taskbucket3095" {
  bucket = "taskbucket3095"
  acl    = "private"
 tags = {
    Name        = "taskbucket3095"
  }
 
}

resource "aws_s3_bucket_public_access_block" "access_to_bucket" {
  bucket = "${aws_s3_bucket.taskbucket3095.id}"

  block_public_acls   = true
  block_public_policy = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_object" "taskobject" {
  for_each		 = fileset("C:/Users/Snehal/Desktop/terraform_code", "**/*.jpg")
  bucket                 = "${aws_s3_bucket.taskbucket3095.bucket}"
  key                    =  each.value
  source                 = "C:/Users/Snehal/Desktop/terraform_code/${each.value}"
  content_type 		 = "image/jpg"

}

locals {
	s3_origin_id = "tasks3origin"
}


// Creating Origin Access Identity for CloudFront

resource "aws_cloudfront_origin_access_identity" "origin_access_identity" {
	comment = "taskbucket3095"
}

resource "aws_cloudfront_distribution" "s3distribution" {

  origin {
    domain_name = "${aws_s3_bucket.taskbucket3095.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
    s3_origin_config {
      origin_access_identity = "${aws_cloudfront_origin_access_identity.origin_access_identity.cloudfront_access_identity_path}"
    }
}
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "accessforTask1"
  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

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

// Cache behavior with precedence 0
    ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  # Cache behavior with precedence 1
  ordered_cache_behavior {
    path_pattern     = "/content/*"
   allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["IN"]
    }
  }

  tags = {
    Name = "taskdistribution"
    Environment = "production"
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
retain_on_delete = true

depends_on=[
	aws_s3_bucket.taskbucket3095
]
}
/*
// AWS Bucket Policy for CloudFront
data "aws_iam_policy_document" "s3_policy" {
statement {
actions   = ["s3:GetObject"]
resources = ["${aws_s3_bucket.taskbucket3095.arn}/*"]
principals {
type        = "AWS"
identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
}
}
statement {
actions   = ["s3:ListBucket"]
resources = ["${aws_s3_bucket.taskbucket3095.arn}"]
principals {
type        = "AWS"
identifiers = ["${aws_cloudfront_origin_access_identity.origin_access_identity.iam_arn}"]
}
}
}

resource "aws_s3_bucket_policy" "s3BucketPolicy" {
bucket = "${aws_s3_bucket.taskbucket3095.bucket}"
policy = "${data.aws_iam_policy_document.s3_policy.json}"
}
*/
