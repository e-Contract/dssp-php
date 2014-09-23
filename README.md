# DSSP SDK for PHP

## Requirements

Tested under Fedora 20, we need:
```
yum install php.x86_64
yum install php-soap.x86_64
yum install php-mcrypt.x86_64
systemctl restart httpd.service
```

You can check the available modules via phpinfo.php containing:
```
<?php
phpinfo();
```
Or by running:
```
php -m
```


## Example

The PDF upload and initial Browser POST call is demonstrated in `index.php`.
The verification of the DSS Browser POST and subsequent PDF downloading is demonstrated in `landing.php`.


## Debugging via NetBeans

Debug PHP via Xdebug in NetBeans:
```
yum install php-pecl-xdebug.x86_64
systemctl restart httpd.service
```

Add to `/etc/php.d/xdebug.ini`:
```
xdebug.remote_enable=1
xdebug.remote_handler=dbgp
xdebug.remote_mode=req
xdebug.remote_host=127.0.0.1
xdebug.remote_port=9000
```


## syslog

Enable syslog in `/etc/php.ini`:
```
error_log = syslog
```

View syslog via:
```
journalctl -f
```
