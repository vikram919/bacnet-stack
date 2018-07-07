### This project is a fork of [bacnet-stack](https://github.com/stargieg/bacnet-stack)

### Dependencies:
#### Get the latest version of [Openssl](https://github.com/openssl/openssl)
	
	$ wget http://www.openssl.org/source/openssl-******.tar.gz
	$ tar -xvzf openssl-******.tar.gz
	$ cd openssl-******
	$ ./config –prefix=/usr/local/openssl –openssldir=/usr/local/openssl
	$ make
	$ sudo make install
	
### Ubuntu Build:
Please refer to the documentation [bacnet-statck wiki install](https://github.com/stargieg/bacnet-stack/wiki/Install)
#### Steps to compile this project:-	
	 
	$ git clone https://github.com/vikram919/bacnet-stack.git
	$ cd bacnet-stack
	$ make clean
	$ make BUILD=debug BACNET_PORT=linux BACDL_DEFINE=-DBACDL_BIP=1 BACNET_DEFINES="-DPRINT_ENABLED=1 -DBACFILE -DBACAPP_ALL -DBACNET_PROPERTY_LISTS"	
	