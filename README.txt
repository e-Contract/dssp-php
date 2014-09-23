README for DSSP PHP SDK
=======================

=== 1. Requirements

Tested under Fedora 20, we need:
yum install php.x86_64
yum install php-soap.x86_64
yum install php-mcrypt.x86_64
systemctl restart httpd.service

You can check the available modules via phpinfo.php containing:
<?php
phpinfo();
Or by running:
php -m


=== 2. Debugging via NetBeans

Debug PHP via Xdebug in NetBeans:
yum install php-pecl-xdebug.x86_64
systemctl restart httpd.service

Add to /etc/php.d/xdebug.ini:
xdebug.remote_enable=1
xdebug.remote_handler=dbgp
xdebug.remote_mode=req
xdebug.remote_host=127.0.0.1
xdebug.remote_port=9000


=== 3. syslog

Enable syslog in /etc/php.ini:
error_log = syslog

View syslog via:
journalctl -f
