# Uniqid

## Nginx conf
```
	server {
	    ...
		uniqid_pass /data0/uniqid; 
		//full path of unix domain socket
		//off means generate uniqid only, not pass to router, and need not to deploy unqid_agent
		...
	}
```
