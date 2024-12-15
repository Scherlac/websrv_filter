
import os
import sys
import time
import re
import numpy as np
import pandas as pd
import plotly.express as px


# SRC: https://sematext.com/blog/nginx-logs/
# Here are some important NGINX access log fields you should be aware of:

# remote_addr: The IP address of the client that requested the resource
# http_user_agent: The user agent in use that sent the request
# time_local: The local time zone of the server
# request: What resource was requested by the client (an API path or any file)
# status: The status code of the response
# body_bytes_sent: The size of the response in bytes
# request_time: The total time spent processing the request
# remote_user: Information about the user making the request
# http_referer: The IP address of the HTTP referer
# gzip_ratio: The compression ratio of gzip, if gzip is enabled

# SRC: https://www.digitalocean.com/community/tutorials/nginx-access-logs-error-logs
# There are many types of log levels that are associated with a log event and with a different priority. All the log levels are listed below. In the following log levels, debug has top priority and includes the rest of the levels too. For example, if you specify error as a log level, then it will also capture log events those are labeled as crit, alert and emergency.

# emerg: Emergency messages when your system may be unstable.
# alert: Alert messages of serious issues.
# crit: Critical issues that need to be taken care of immediately.
# error: An error has occured. Something went wrong while processing a page.
# warn: A warning messages that you should look into it.
# notice: A simple log notice that you can ignore.
# info: Just an information messages that you might want to know.
# debug: Debugging information used to pinpoint the location of error.


# the dictionary that contains the regex patterns for each log type, one to identify the log type and one to parse the log line

# ip address length eg.: ipv4: 192.168.0.1:12, 192.168.000.001:15; ipv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334:39
IP_ADDRESS_LENGTH = 40
# timestamp length eg.: 13/Dec/2024:20:20:08 +0000 --> 26
# max length is 26 
TIMESTAMP_LENGTH = 26
# log levels are eg.: emerg:5, alert:5, crit:4, error:5, warn:4, notice:6, info:4, debug:5
# max length is 6
LOG_LEVEL_LENGTH = 6

# case insensitive regex patterns for ip addresses, timestamps and log levels

regex_dict = {
    "ip_v4": r'(([0-9]{1,3}\.){3}[0-9]{1,3})',
    "ip_v6": r'(([0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4})',
    "timestamp": r'(([0-9]{2}){1,2}[-/]([0-9]{2}|[a-z]{3})[-/]([0-9]{2}){1,2}[ :][0-9]{2}(:[0-9]{2}){2}(\s?[+-][0-9]{4})?)',
                
    "log_level": r'(info)|(error)|(debug)|(warn)|(trace)|(fatal)|(unknown)|(off)|(all)|(critical)|(notice)'
}

regex_dict |= {
    "ip": rf"{regex_dict['ip_v4']}|{regex_dict['ip_v6']}",
}

# the regex pattern '(?:' is used to create a non-capturing group, which is a group that is not captured in the match object)
# the regex pattern '(?P<name>pattern)' is used to create a named group, which is a group that can be referred to by its name 

match_dict = {
    "access_log": {
#  log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
#                       '$status $body_bytes_sent "$http_referer" '
#                       '"$http_user_agent" "$http_x_forwarded_for"';            
        "match_length": IP_ADDRESS_LENGTH + TIMESTAMP_LENGTH + 6,
        "match_pattern": rf"(?P<ip>{regex_dict['ip']}) - " \
            rf"(?P<user>.*?) " \
            rf"\[(?P<timestamp>{regex_dict['timestamp']})\] ",
        "example": """47.237.115.171 - - [13/Dec/2024:20:20:08 +0000] "GET /V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1" 502 157 "-" "Custom-AsyncHttpClient" "-" """,
        "parse_regex": rf"(?P<ip>{regex_dict['ip_v4']}|{regex_dict['ip_v6']}) - " \
            rf"(?P<user>.*?) " \
            rf"\[(?P<timestamp>{regex_dict['timestamp']})\] " \
            rf"(" \
            rf"\"(?P<request>" \
                rf"((?P<method>.*?) (?P<url>.*?) (?P<protocol>.*?))" \
            rf")\" " \
            rf"|\"(?P<bad_request>.*?)\"" \
            rf")" \
            rf"(?P<status>.*?) (?P<body_bytes>.*?) \"(?P<http_referer>.*?)\" \"(?P<http_user_agent>.*?)\" \"(?P<http_x_forwarded_for>.*?)\""
    },
    "error_log": {
        "match_length": TIMESTAMP_LENGTH + LOG_LEVEL_LENGTH + 6,
        "match_pattern": rf"(?P<timestamp>{regex_dict['timestamp']}) \[(?P<level>{regex_dict['log_level']})\] ",
        "example": """2024/12/13 20:20:12 [error] 22#22: *4970 connect() failed (111: Connection refused) while connecting to upstream, client: 47.237.115.171, server: www.sclx.dev, request: "GET /app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php HTTP/1.1", upstream: "http://127.0.0.1:11900/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", host: "87.229.84.82:443""",

        "parse_regex": rf"(?P<timestamp>{regex_dict['timestamp']}) \[(?P<level>{regex_dict['log_level']})\] " \
            rf"(?P<process_id>.*?) (?P<message>.*)"
    }

}


# load the first 1000 lines
def load_lines(file_path, lines=100):
    with open(file_path, 'r') as f:
        return [f.readline() for _ in range(lines)]
    
# parse the log lines
def parse_lines(lines):
    parsed_lines = { log_type: [] for log_type in match_dict.keys() }
    failed_lines = []
    for line in lines:
        parsed = None
        for log_type, log_dict in match_dict.items():
            try:
                initial = line[:log_dict['match_length']]
                match = re.match(log_dict['match_pattern'], initial, re.IGNORECASE)
                if match:
                    result = re.match(log_dict['parse_regex'], line, re.IGNORECASE)
                    parsed = result.groupdict()
                    parsed_type = log_type
                    break
            except Exception as e:
                print(f"Error parsing line: {line}, error: {e}")

        if parsed:
            parsed_lines[parsed_type].append(parsed)
        else:
            failed_lines.append(line)

    return parsed_lines, failed_lines

               




# pattern=rf"(?P<timestamp>{regex_dict['timestamp']}) \[(?P<level>{regex_dict['log_level']})\] "
# string = '2023/10/29 14:42:45 [notice] 1#1: OS: '
# match = re.match(pattern, string, re.IGNORECASE)
# print(match.groupdict())
