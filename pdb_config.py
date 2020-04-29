"""
pdb_config.py
Created by Daniel Piekacz on 2017-01-25.
Updated on 2017-01-30.
https://gixtools.net
"""
#
# Configuration section.
#
config = {}

# If less than the number of days then highlight that peering as recently added / updated
config['days'] = 60

# Web server IP address and port
config['http_ip'] = '0.0.0.0'
config['http_port'] = 5000

config['ssl'] = False
config['ssl_crt'] = '/etc/letsencrypt/live/pdb.gixtools.net/fullchain.pem'
config['ssl_key'] = '/etc/letsencrypt/live/pdb.gixtools.net/privkey.pem'

# Redis
config['redis_host'] = 'localhost'
config['redis_port'] = 6379
config['redis_db'] = 0

# Logging and debugging.
config['debug'] = True

# Timestamp's date and time format
config['timestamp_format'] = '%Y-%m-%d %H:%M:%S %f'

# Number of log entries displayed
config['eventlog_entries'] = 100

# Allow to flush Redis DB
config['redis_flush_allowed'] = False
