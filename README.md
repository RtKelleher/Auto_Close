# Auto_Close

- This script queries The Hive for SentinelOne generated cases older than seven days,
- It then checks if the resolved status is True in the SentinelOne console. 
- Finally it closes the associated case in TheHive

#Define the following
- S1API = ('Your API Token')
- S1WEB = ('https://Your SentinelOne Web Console')
- API = TheHiveApi('http://Your Hive Web Console :9000', 'Your Hive API Token')
