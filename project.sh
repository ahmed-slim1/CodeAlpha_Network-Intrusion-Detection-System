# Snort Configuration (/etc/snort/snort.conf)
ipvar HOME_NET 192.168.1.0/24
ipvar EXTERNAL_NET any
include $RULE_PATH/local.rules

# Snort Rules (/etc/snort/rules/local.rules)
# Detect ICMP Ping
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)
# Detect HTTP GET Request
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP GET request detected"; flow:to_server,established; content:"GET "; http_method; sid:1000002; rev:1;)
# Detect Suspicious SSH Activity
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Suspicious SSH activity"; flow:to_server,established; content:"ssh"; sid:1000003; rev:1;)

# Running Snort
# Test Snort configuration
sudo snort -T -c /etc/snort/snort.conf
# Run Snort in packet logging mode
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

# Logstash Configuration (/etc/logstash/conf.d/snort.conf)
input {
  file {
    path => "/var/log/snort/alert"
    start_position => "beginning"
  }
}
filter {
  grok {
    match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{DATA:program}:%{DATA:msg}" }
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "snort-alerts-%{+YYYY.MM.dd}"
  }
}

# Automated Response with Fail2ban (Optional)
# Custom Filter for Snort (/etc/fail2ban/filter.d/snort.conf)
[Definition]
failregex = .*ICMP Ping detected.*
ignoreregex =

# Fail2ban Configuration (/etc/fail2ban/jail.local)
[snort]
enabled = true
filter = snort
logpath = /var/log/snort/alert
bantime = 3600
findtime = 600
maxretry = 3
