# jenkinsCI
Set up a Jenkins Server 

**Don't forget to upload required files and set S3 URL in shell script**<br>
**Don't forget to set S3 URL for files in Ansible playbook**<br>
**Don't forget to set gpg passphrase in s3cmd template in Ansible playbook**<br>
**Add Jenkins server FQDN in Nginx config file**
**Uncomment the Ansible playbook lines to deploy self-signed cert OR if you have cert - then the lines to deploy CA signed CERT**<br> 

This Shell script (can be used as a start-up 'user-data' or 'configuration-script' to set up jenkins on Ubuntu 16.x server

```
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
```

The script downloads the groovy script, Ansible playbook and Nginx proxy configuration files from S3 and runs the ansible script to install jenkins and perform some basic configurations.

**Ansible playbook**
```
---
- hosts: all
  become: true
  vars:
    servernm: "{{ inventory_hostname }}"
    randompass: "{{ lookup('password', '/dev/null length=15 chars=ascii_letters') }}"
  tasks:
    - set_fact:
        jenkins_adminpass: "{{ randompass }}"

    - set_fact:
        server_hostname: "{{ servernm }}"

    - set_fact:
        servername: "{{ servernm }}"

    - name: Create deploy group
      group:
        name: deploy
        state: present

    - name: create deploy user for dunamis team
      user:
        name: deploy
        groups:
          - deploy
          - sudo
        state: present
        shell: /bin/bash
        createhome: yes
        home: /home/deploy

    - name: create ssh directory for deploy user
      file:
        path: /home/deploy/.ssh
        state: directory

    - name: Download ssh pub key for your custom user (other than ec2-user for example)
      get_url:
        url: <<your S3 or Google docs URL with SSH keys>>
        dest: /home/deploy/.ssh/authorized_keys
        mode: 0600
        owner: deploy
        group: deploy

    - name: Test for sudoers permission
      shell: grep "^deploy ALL=(ALL) NOPASSWD:ALL" /etc/sudoers | wc -l
      register: test_sudoers

    - name: add deploy user to SUDOERS
      lineinfile: dest=/etc/sudoers line="deploy ALL=(ALL) NOPASSWD:ALL"
      when: test_sudoers.stdout == "0"

    - name: update apt cache
      apt: update_cache=yes

    - name: Install the package "python-software-properties"
      apt:
        name: python-software-properties
        state: present

    - name: Install zip
      apt:
        name: zip
        state: present

    - name: Install unzip
      apt:
        name: unzip
        state: present

    - name: Install the package "git"
      apt:
        name: git
        state: present

    - name: Install the package "python-setuptools"
      apt:
        name: python-setuptools
        state: present

    - name: install S3CMD utility to interact with IT S3
      shell: |
        wget https://sourceforge.net/projects/s3tools/files/s3cmd/2.0.1/s3cmd-2.0.1.tar.gz -O /root/s3cmd-2.0.1.tar.gz
        tar xzvf /root/s3cmd-2.0.1.tar.gz -C /root
        cd /root/s3cmd-2.0.1
        python setup.py install
      args:
        executable: /bin/bash
      register: install_s3cmd
        
    - apt_repository:
        repo: 'ppa:openjdk-r/ppa'

    - name: Update repositories cache and install "Java OpenJDK8" package
      apt:
        name: openjdk-8-jdk
        update_cache: yes

    - apt_repository:
        repo: deb https://pkg.jenkins.io/debian-stable binary/
        state: present

    - name: Add an Apt signing key, uses whichever key is at the URL
      apt_key:
        url: https://pkg.jenkins.io/debian-stable/jenkins.io.key
        state: present

    - name: Update repositories cache and install "Jenkins" package
      apt:
        name: jenkins
        update_cache: yes
      register: jenkins_installed

    - name: create empty s3cfg file
      copy:
        content: ""
        dest: /.s3cfg
        force: no
        group: jenkins
        owner: jenkins
        mode: 0600


    - name: insert/update S3CMD Config File /.s3cfg 
      blockinfile:
        path: /.s3cfg
        block: |
          [default]
          access_key = 
          access_token = 
          add_encoding_exts = 
          add_headers = 
          bucket_location = US
          ca_certs_file = 
          cache_file = 
          check_ssl_certificate = True
          check_ssl_hostname = True
          cloudfront_host = cloudfront.amazonaws.com
          default_mime_type = binary/octet-stream
          delay_updates = False
          delete_after = False
          delete_after_fetch = False
          delete_removed = False
          dry_run = False
          enable_multipart = True
          encrypt = False
          expiry_date = 
          expiry_days = 
          expiry_prefix = 
          follow_symlinks = False
          force = False
          get_continue = False
          gpg_command = /usr/bin/gpg
          gpg_decrypt = %(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
          gpg_encrypt = %(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
          gpg_passphrase = <xxxxxxxxxxx>
          guess_mime_type = True
          host_base = <aws S3 service URL>
          host_bucket = %(bucket)s.<aws S3 service URL>
          human_readable_sizes = False
          invalidate_default_index_on_cf = False
          invalidate_default_index_root_on_cf = True
          invalidate_on_cf = False
          kms_key = 
          limit = -1
          limitrate = 0
          list_md5 = False
          log_target_prefix = 
          long_listing = False
          max_delete = -1
          mime_type = 
          multipart_chunk_size_mb = 15
          multipart_max_chunks = 10000
          preserve_attrs = True
          progress_meter = True
          proxy_host = 
          proxy_port = 0
          put_continue = False
          recursive = False
          recv_chunk = 65536
          reduced_redundancy = False
          requester_pays = False
          restore_days = 1
          restore_priority = Standard
          secret_key = 
          send_chunk = 65536
          server_side_encryption = False
          signature_v2 = False
          signurl_use_https = False
          simpledb_host = sdb.amazonaws.com
          skip_existing = False
          socket_timeout = 300
          stats = False
          stop_on_error = False
          storage_class = 
          urlencoding_mode = normal
          use_http_expect = False
          use_https = True
          use_mime_magic = True
          verbosity = WARNING
          website_endpoint = http://%(bucket)s.s3-website-%(location)s.amazonaws.com/
          website_error = 
          website_index = index.html

    - debug:
        msg: "Add YOUR \"access_key\" and \"secret_key\" for IT S3 to the Jenkins Credentials"

    - name: Update repositories cache and install "Nginx" package
      apt:
        name: nginx
        state: latest
        update_cache: yes

    - name: Update repositories cache and install python pip
      apt:
        name: python-pip
        update_cache: yes
      register: pip_installed
    
    - name: Ensure python OpenSSL dependencies are installed.
      pip:
        name: pyOpenSSL
        state: present

    - name: Ensure directory exists for local self-signed TLS certs
      file:
        path: /etc/letsencrypt/live/{{ server_hostname }}
        state: directory
    
    ## Create Self-signed SSL CERT and key 
    # - name: Generate an OpenSSL private key
    #   openssl_privatekey:
    #     path: /etc/letsencrypt/live/{{ server_hostname }}/privkey.pem
    # 
    # - name: Generate an OpenSSL CSR
    #   openssl_csr:
    #     path: /etc/ssl/private/{{ server_hostname }}.csr
    #     privatekey_path: /etc/letsencrypt/live/{{ server_hostname }}/privkey.pem
    #     common_name: "{{ server_hostname }}"
    # 
    # - name: Generate a Self Signed OpenSSL certificate
    #   openssl_certificate:
    #     path: /etc/letsencrypt/live/{{ server_hostname }}/fullchain.pem
    #     privatekey_path: /etc/letsencrypt/live/{{ server_hostname }}/privkey.pem
    #     csr_path: /etc/ssl/private/{{ server_hostname }}.csr
    #     provider: selfsigned

    ## OR if you have CA signed CERT and key stored on S3 or google doc
    # - name: Download and install Valid CA signed SSL cert for Nginx
    #  get_url:
    #    url: <s3 URL>.crt
    #    dest: /etc/letsencrypt/live/{{ server_hostname }}/fullchain.pem
    #    mode: 0644
    #    owner: root
    #    group: root

    # - name: Download and install Private Key for Valid CA signed SSL cert for Nginx
    #  get_url:
    #    url: <s3 URL>.key
    #    dest: /etc/letsencrypt/live/{{ server_hostname }}/privkey.pem
    #    mode: 0600
    #    owner: root
    #    group: root

    - debug:
        msg: "{{ jenkins_adminpass }}"

    - name: delete default nginx configs
      file: 
        path: "/etc/nginx/sites-enabled/default"
        state: absent

    - name: Create NGINX config file for Jenkins with SSL
      template: 
        src=/root/nginx_jenkins
        dest=/etc/nginx/sites-available/jenkins

    - name: Create Nginx config symbolic link to Nginx
      file:
        src: /etc/nginx/sites-available/jenkins
        dest: /etc/nginx/sites-enabled/default
        owner: root
        group: root
        state: link
      register: nginx_configured
   
    - name: Ensure directory exists for groovy file
      file:
        path: /var/lib/jenkins/init.groovy.d
        state: directory
 
    - name: Create Jenkins groovy file for auto-unlock during setup
      template: 
        src=/root/basic_security.groovy
        dest=/var/lib/jenkins/init.groovy.d/basic_security.groovy
      register: jenkins_configured

    - name: Dumping Random generated jenkins admin password to file in /root folder
      copy:
        content: "{{ jenkins_adminpass }}"
        dest: /root/.jenkins_adminpass

    - name: restart jenkins service
      systemd:
        state: restarted
        name: jenkins
      when: jenkins_configured.changed

    - name: restart nginx service
      systemd:
        state: restarted
        name: nginx
      when: nginx_configured.changed

    - pause:
        seconds: 10

    - name: generate CRUMB
      command: "curl -k -s -u admin:{{ jenkins_adminpass }} 'https://localhost/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)'" 
      register: generate_crumb
      ignore_errors: yes

    - set_fact:
      jenkins_crumb: "{{ generate_crumb.stdout }}"

    - debug:
        msg: "{{ generate_crumb.stdout }}"

    - name: Install all recommended Jenkins Plugins
      command: "curl -k -u admin:{{ jenkins_adminpass }} -s -X POST -d '<jenkins><install plugin=\"git@2.0\" /></jenkins>' --header 'Content-Type: text/xml' -H \"{{ generate_crumb.stdout }}\" https://localhost/pluginManager/installNecessaryPlugins"
      register: install_alljenkinsplugins

    - name: restart jenkins service
      systemd:
        state: restarted
        name: jenkins
      when: install_alljenkinsplugins.changed

    - name: Remove the groovy script to stop reconfiguring security again and again
      file:
        path: /var/lib/jenkins/init.groovy.d/basic_security.groovy
        state: absent

    - name: change temp folrder for jenkins
      shell: |
        sed -i 's/    \$SU -l \$JENKINS_USER --shell=\/bin\/bash -c "\$DAEMON \$DAEMON_ARGS -- \$JAVA \$JAVA_ARGS -jar \$JENKINS_WAR \$JENKINS_ARGS" || return 2/    JAVA_OPTS="-Djava.io.tmpdir=\/var\/tmp"\n    $SU -l $JENKINS_USER --shell=\/bin\/bash -c "$DAEMON $DAEMON_ARGS -- $JAVA $JAVA_OPTS $JAVA_ARGS -jar $JENKINS_WAR $JENKINS_ARGS" || return 2/g' /etc/init.d/jenkins
        systemctl daemon-reload
        sed -i 's/JENKINS_ARGS="--webroot=\/var\/cache\/\$NAME\/war --httpPort=\$HTTP_PORT"/JENKINS_ARGS="--webroot=\/var\/cache\/$NAME\/war --httpPort=$HTTP_PORT -Djava.io.tmpdir=\/var\/tmp\/"/g' /etc/default/jenkins
      register: change_jenkins_temp
      ignore_errors: yes

    - name: restart jenkins service
      systemd:
        state: restarted
        name: jenkins
      when: change_jenkins_temp.changed
```

**Groovy script**
```
#!groovy

import jenkins.model.*
import hudson.security.*

def instance = Jenkins.getInstance()

println "--> creating local user 'admin'"

def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount('admin','{{ jenkins_adminpass }}')
instance.setSecurityRealm(hudsonRealm)

def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
instance.setAuthorizationStrategy(strategy)
instance.save()
```
**Nginx config file**
```
upstream jenkins {
    server 127.0.0.1:8080 fail_timeout=0;
}

server {
  listen 80 default;
  listen [::]:80 default;
  server_name 127.0.0.1 localhost; ## Other DNS FQDNs for your server
  return 301 https://<your FQDN>$request_uri;
  rewrite ^ https://server_name$request_uri? permanent;
}
 
server {
    listen 443 default ssl;
    listen [::]:443 default ssl;
    server_name localhost ; ## Other DNS FQDNs for your server
    
    ssl_certificate       /etc/letsencrypt/live/localhost/fullchain.pem;
    ssl_certificate_key   /etc/letsencrypt/live/localhost/privkey.pem;

    ssl_session_timeout  5m;
    ssl_protocols  SSLv3 TLSv1;
    ssl_ciphers HIGH:!ADH:!MD5;
    ssl_prefer_server_ciphers on;
 
    location / {
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect http:// https://;
  
        add_header Pragma "no-cache";
 
        if (!-f $request_filename) {
            proxy_pass http://jenkins;
            break;
        }
    }
}
```
