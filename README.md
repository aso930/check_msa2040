## Check the status of HP MSA2040 storages

This script is designed to work with nagios. Fell free to modify it for you own personal needs.

Options:

        -h,--help - display this message
        
        -n, --hostname= - IP or hostname of the storage
        
        -u, --username= - Username to connect to the storage
        
        -p --password = - Password to connect to the storage
        
        -c, --check= - What to check. Valid options are: events last <nb>, controllers, power-supplies, sensor-status, system.
        
        -v, --version - print the version

Note about Python version compatibilities:

* For Python 2.7 use check_msa2040.py
* For Python 3+ use check_msa2040.py3
