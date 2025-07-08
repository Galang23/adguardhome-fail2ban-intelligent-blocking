# AdGuardHome Fail2Ban Intelligent Blocking
Intelligently block rouge domains and clients querying AdGuardHome DNS Server.

## Why?
The default fail2ban blocking mechanism is not smart enough to detect and ban the ever growing rouge domains and bots querying that rouge domain. 

This python script achieve that goal by checking the AGH log file for one domain which is queried over and over again within the same minute by different client (IPs), 
then block the domain to custom filter rule, add rouge clients to disallowed clients list, and a final blow to stop the bots consuming server's resource, by adding 
rouge IPs to Fail2Ban jail permanently.

## How?
To install, simply create a new Fail2Ban jail and filter, files provided. 
Then, copy the python file to the desired location, preferably accessible only by root user.
Finally, create new service file, either init or systemd, to run and monitor the script.
