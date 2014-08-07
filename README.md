### Centinel Client

![ICLab Logo](http://iclab.org/wp-content/themes/svbtle-child/ICLab-f200.png "ICLab Logo")

Centinel is a tool used to detect network interference and internet
censorship.

#### Install and usage

acquire the latest development version
* git clone https://github.com/iclab/centinel-iclab.git
    
prepare and install dependencies
* ./prepare.sh

initialize Centinel and exchange keys with Sirocco server
* ./init_client.py

run Centinel Client
* ./centinel.py [experiment 1] [experiment 2] ...
(running without arguments will run the client daemon and connect to the server)

#### Supported platforms

* Linux/OS X
* BISmark Routers
* Android
