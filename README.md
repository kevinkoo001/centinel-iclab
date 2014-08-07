### Centinel Client

![ICLab Logo](http://iclab.org/wp-content/themes/svbtle-child/ICLab-f200.png "ICLab Logo")

Centinel is a tool used to detect network interference and internet censorship. It can run experiments written in Python (as well as manually) and send the results to Sirocco server. It can also be configured to run a set of standard tests on a given list of URLS using configuration files.
It can be used both as a command-line application and a system service.
Centinel is a project developed by [ICLab](http://iclab.org).

#### Install and usage

acquire the latest development version

    * git clone https://github.com/iclab/centinel-iclab.git
    
prepare and install dependencies

    * ./prepare.sh

##### Running in command-line:

initialize Centinel and exchange keys with Sirocco server

    * ./init_client.py

run Centinel Client

    * ./centinel.py --run path/to/experiment.py --input path/to/input.txt --output path/to/output.json
(running without arguments will run the client daemon and connect to the server)

##### Installing as a service:

    * ./install_centinel.sh
#### Supported platforms

* Linux/OS X
* BISmark Routers
* Android
