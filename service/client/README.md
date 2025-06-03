Client
======

## Install dependencies
Please build the requirements using the following command.
```
pip install -r requirements.txt
python build.py
```

## Run
First you need to create a port on the remote server via the web interface. 

To synchronize your systems clock to that of the remote server use the following command.
```
python ptp_client.py [REMOTE] [CLOCK_ID] [PORT] --secret [SECRET] --syncs [NUM_SYNCS] --interval [INTERVAL]
```
