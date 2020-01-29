#!/usr/bin/perl -w

### Detach from console after successful start
$cfg{daemonize} = 1;

### Log to syslog using this facility
$cfg{log_facility} = "local7";

### RADIUS-related settings

### You can specify as many as you want RADIUS servers. If server with lower index
### is not answering, server with next index will be tried (0, 1, 2, etc...).
$cfg{radius_auth}{0} = { server => "127.0.0.1:1812", timeout => 5, secret => "apple" };
$cfg{radius_acct}{0} = { server => "127.0.0.1:1813", timeout => 5, secret => "apple" };

#$cfg{nas_identifier} = "lISG"; ## By default equals to NAS IP-address

### CoA-related settings
#$cfg{coa_server} = "127.0.0.1";  ## Accept requests only from this IP (comment to accept from all)
$cfg{coa_secret} = "apple";	 ## Shared secret
$cfg{coa_port} = 3799;		 ## Local UDP port to listen for CoA requests

### Send Interim-Update to RADIUS server every session_alive_interval seconds
$cfg{session_alive_interval} = 60; ## Every minute (0 = don't send)

### Session inactivity default timeout (disconnect session after this time) (in seconds)
$cfg{session_idle_timeout} = 1800;

### Session default maximum duration (end session after this time) (in seconds)
$cfg{session_max_duration} = 86400;

### Unauth session maximum duration (end session after this time) (in seconds)
$cfg{unauth_session_max_duration} = 60;

### This services will be automatically applied if session was rejected by RADIUS
#$cfg{unauth_service_name_list} = [ "ATESTSERV", "AREDIRECT" ];

### Check traffic classification file MD5 sum every N seconds. If sum was changed re-read this file.
$cfg{tc_check_interval} = 300; ## Every 5 minutes

### Don't send RADIUS accounting for main session (even RADIUS Start and Stop)
#$cfg{no_accounting} = 1; ## Default is to send

### Callbacks (ipaddr and nat_ipaddr currenly passed)
#$cfg{cb_on_session_start} = sub { my $pars = shift; print $pars->{"ipaddr"} . " " . $pars->{"nat_ipaddr"} . "\n"; };
#$cfg{cb_on_session_stop} = sub { my $pars = shift; print $pars->{"ipaddr"} . " " . $pars->{"nat_ipaddr"} . "\n"; };

####################### Services description #######################

### Begin ``TESTSERV'' service ###

## Service type:
##
##  * "policer" - for traffic policing (by default)
##  * "tagger"  - can be used to classify services using "lisg" match in Netfiler
##              - (for example to perform L4 redirect)
##
## "tagger" service traffic classes can overlap any "policer" service traffic classes
##
## rate_info, alive_interval, idle_timeout, max_duration and accounting params has no
## meaning for "tagger" type service

#$cfg{srv}{TESTSERV}{type} = "tagger";

## Service download and upload rates in Cisco-Account-Info format (see README file)
## Comment "rate_info" line below or use QD;0;0;U;0;0 as its value for no rate limit
$cfg{srv}{TESTSERV}{rate_info} = "QD;512000;96000;U;512000;96000";

## Traffic classes list for this service (as defined in tc.conf file)
$cfg{srv}{TESTSERV}{traffic_classes} = [ "OUR_LOCAL", "PEERING" ];

## Don't send RADIUS accounting for this service (default is to send)
#$cfg{srv}{TESTSERV}{no_accounting} = 1;

$cfg{srv}{TESTSERV}{alive_interval} = 120;   ## Equals to $cfg{session_alive_interval} if not defined
$cfg{srv}{TESTSERV}{idle_timeout}   = 600;   ## Equals to $cfg{session_idle_timeout} if not defined
$cfg{srv}{TESTSERV}{max_duration}   = 10000; ## Equals to $cfg{session_max_duration} if not defined

### End ``TESTSERV'' service ###

#################### End services description ######################

###
### It's better not to touch anything below this line
###
$cfg{debug} = 1;
$cfg{pid_file} = "/var/run/ISGd.pid";
$cfg{radius_dictionary} = $FindBin::RealBin . "/../etc/raddb/dictionary";
$cfg{tc_file} = $FindBin::RealBin . "/../etc/tc.conf"
