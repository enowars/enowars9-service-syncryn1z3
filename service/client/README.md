Client
======

## Install dependencies
Please build the requirements using the following command.
```
pip install -r requirements.txt
python build.py
```

## Run
You may now use the client as follows.

First you want to claim a port on the remote server. 
```
python ptp_client.py 127.0.0.1 0x0200000000000001 1 --secret=password --description="Test port" --claim
```

You can now read your ports description.
```
python ptp_client.py 127.0.0.1 0x0200000000000001 1 --secret=password --description="Test port"
```

To synchronize your systems clock to that of the remote server use the following command.
> Due to the routing in docker not being optimal for this use-case you need to specify the IP of the container running the server (only when on the same system)
```
python ptp_client.py 172.X.0.2 0x0200000000000001 1 --secret=password --description="Test port" --syncs=10 --interval=0.5
```
