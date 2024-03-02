# KDC Proxy Docker Container 🐋

* Rename `config/sample-kdcproxy.conf` to `config/kdcproxy.conf`
* Configure Domain Controller IP addresses via `extra_hosts` in `docker-compose.yml` 
* Configure Realm and Domain Controller DNS Names in `config/kdcproxy.conf`
* Run `docker-compose up` and configure to run as service
* Run either behind reverse proxy or as a directly exposed server (bring your own certificates)
