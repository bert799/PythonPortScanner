# PythonPortScanner

This is a network and port scanning python script that runs on a CLI. 
It allows the user to:

* Search a network for active hosts by inserting a subnet address with it's mask. Ex.: 198.168.0.0/24
* Check if a specific host is active based on it's IP address.
* Run a port scan on a given host to check which ports are open and what services are running on it.

## Installing the Scapy library
To run the script the user has to have a python enviroment with the scapy library installed, to do so one can install it from the provided requirements.txt file:
```
pip install -r requirements.txt
```

Alternatively you can install it directly from pip, though the code is only tested to run on version 2.5.0.

## Running the script
To properly run the code the user should be using a linux operating system. To run the script insert the following command on the terminal:

```
sudo -E python3 ./main.py
```
The `-E` modifier preserves the python enviroment when running as root, preventing having problems with the scapy library.
