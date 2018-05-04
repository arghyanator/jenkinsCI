#!/bin/bash
####
# Install and run Jenkins master
# Don't forget to put in your S3 URL
# where files are stored
####
wget <s3 URL>/basic_security.groovy -O /root/basic_security.groovy
wget <s3 URL>/nginx_jenkins -O /root/nginx_jenkins
wget <s3 URL>/jenkins_playbook.yml -O /root/jenkins_playbook.yml
apt-add-repository ppa:ansible/ansible
apt-get update
apt-get -y install ansible
ansible-playbook -i "localhost," -c local /root/jenkins_playbook.yml -vv
