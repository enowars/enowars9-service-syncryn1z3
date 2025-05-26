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
python ptp_client.py 127.0.0.1 0x0200000000000001 1 --secret password --description "Test port" --claim
```

You can now read your ports description.
```
python ptp_client.py 127.0.0.1 0x0200000000000001 1 --secret password
```

To synchronize your systems clock to that of the remote server use the following command.
```
python ptp_client.py 127.0.0.1 0x0200000000000001 1 --secret password --syncs 10 --interval 0.5
```
