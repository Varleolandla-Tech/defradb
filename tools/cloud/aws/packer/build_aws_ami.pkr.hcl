// Copyright 2023 Democratized Data Foundation
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

variable "ami_prefix" {
  type    = string
  default = "source-defradb"
}

variable "github_pat" {
  default = env("ONLY_DEFRADB_REPO_CI_PAT")
}

variable "commit" {
  default = env("COMMIT_TO_DEPLOY")
}

locals {
  timestamp = regex_replace(timestamp(), "[- TZ:]", "")
  ami_prefix = "${var.ami_prefix}-${var.commit}"
}

packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.2"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

source "amazon-ebs" "ubuntu-lts" {
  region = "us-east-1"

  source_ami_filter {
    filters = {
      architecture        = "x86_64"
      virtualization-type = "hvm"
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  instance_type  = "t2.micro"
  ssh_username   = "ubuntu"
  ssh_agent_auth = false

  ami_name    = "${local.ami_prefix}-${local.timestamp}"
  ami_regions = ["us-east-1"]
}

build {
  name = "packer-ubuntu"
  sources = [
    "source.amazon-ebs.ubuntu-lts"
  ]
  
  provisioner "shell" {
    environment_vars = ["COMMIT_TO_DEPLOY=${var.commit}", "DEFRADB_GIT_REPO=github.com/sourcenetwork/defradb.git", "ONLY_DEFRADB_REPO_CI_PAT=${var.github_pat}"]
    pause_before = "10s"
    remote_folder = "/home/ubuntu"
    inline = [
      "/usr/bin/cloud-init status --wait",
      "sudo apt-get update && sudo apt-get install make build-essential -y",
      "curl -OL https://golang.org/dl/go1.18.5.linux-amd64.tar.gz",
      "rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.18.5.linux-amd64.tar.gz",
      "export PATH=$PATH:/usr/local/go/bin",
      "git clone \"https://git:$ONLY_DEFRADB_REPO_CI_PAT@$DEFRADB_GIT_REPO\"",
      "cd ./defradb || { printf \"\\\ncd into defradb failed.\\\n\" && exit 2; }",
      "git checkout $COMMIT_TO_DEPLOY || { printf \"\\\nchecking out commit failed.\\\n\" && exit 3; }",
      "make deps:modules",
      "make install",
      "export GOROOT=\"/usr/bin/go\"",
      "export GOPATH=\"$HOME/go\"",
      "export GOBIN=\"$GOPATH/bin\"",
      "export PATH=\"$GOBIN:$GOROOT/bin:$PATH\"",
      "defradb version || { printf \"\\\ndefradb installed but not working properly.\\\n\" && exit 6; }",
      "printf \"\\\ndefradb successfully installed.\\\n\"",
      "sudo /usr/sbin/sshd -o \"PasswordAuthentication no\" -o \"PermitRootLogin without-password\" ",
      "sudo shred -u /etc/ssh/*_key /etc/ssh/*_key.pub",
      "cd ..",
      "sudo rm -rf ./defradb"
      ]
  }

}
