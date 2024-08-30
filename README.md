# Network Intrusion Detection System (NIDS) Setup with Snort

This guide provides step-by-step instructions to set up a Network Intrusion Detection System (NIDS) using Snort, with optional visualization using the ELK stack (Elasticsearch, Logstash, Kibana), and automated response using Fail2ban.

## Prerequisites
- A Linux system 
- Root or sudo access
- Basic knowledge of Linux command-line

## Step 1: Install Snort

1. **Update the Package List:**
   ```bash
   sudo apt-get update

2. **Install Snort:**
   ```bash
   sudo apt-get install snort

3. **Configure Snort during installation:**

- Enter your network address when prompted (e.g., ' 192.168.1.0/24 ').


## Step 2: Configure Snort

1. **Edit the Snort Configuration File:**
   ```bash
   sudo nano /etc/snort/snort.conf

- Set the network variables:
     ```bash
   ipvar HOME_NET 192.168.1.0/24
   ipvar EXTERNAL_NET any
- Save and close the file.

2. **Add Snort Rules:**
      ```bash
       sudo nano /etc/snort/rules/local.rules

- Add the following rules:
    ```bash
    alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; sid:1000001; rev:1;)
    alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"HTTP GET request detected"; flow:to_server,established; content:"GET "; http_method; sid:1000002; rev:1;)
   alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"Suspicious SSH activity"; flow:to_server,established; content:"ssh"; sid:1000003; rev:1;)

- Save and close the file.

## Step 3: Test and Run Snort
1. **Test the Snort Configuration:**
   ```bash
   sudo snort -T -c /etc/snort/snort.conf

2. **Run Snort:**
      ```bash
      sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
- Replace ' eth0 ' with your network interface name (use ' ifconfig ' to check).

## Step 4: Install and Configure the ELK Stack for Visualization (Optional)
1. **Install Elasticsearch, Logstash, and Kibana:**
- Follow the official [Elastic documentation](https://www.elastic.co/docs)

2.**Configure Logstash for Snort Logs:**

    sudo nano /etc/logstash/conf.d/snort.conf
- Add the following configuration:
     ```bash
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

- Save and close the file.
3. **Start Logstash:**
      ```bash
       sudo systemctl start logstash
4. **Access Kibana:**
- Open Kibana in your browser:' http://localhost:5601 '.
- Create visualizations and dashboards based on Snort alerts.
  
## Step 5: Optional Fail2ban Integration
1. **Create a Custom Filter for Snort:**
       ```bash 
        sudo nano /etc/fail2ban/filter.d/snort.conf
- Add the following:
     ```bash
       [Definition]
       failregex = .*ICMP Ping detected.*
       ignoreregex =
- Save and close the file.

2. **Configure Fail2ban:**
     ```bash
       sudo nano /etc/fail2ban/jail.local 
- Add the following configuration:
     ```bash
        [snort]
        enabled = true
        filter = snort
        logpath = /var/log/snort/alert
        bantime = 3600
        findtime = 600
        maxretry = 3
- Save and close the file.
3. **Restart Fail2ban:**
      ```bash
        sudo systemctl restart fail2ban

## Step 6: Generate Traffic and Monitor Alerts
- Use tools like ' nmap ' to generate network traffic that triggers the Snort rules:
     ```bash
       nmap -sP 192.168.1.0/24
- Monitor Snort alerts in the console, log files, or Kibana dashboards.
