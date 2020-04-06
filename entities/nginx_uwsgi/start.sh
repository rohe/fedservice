#!/usr/bin/env bash
root="/Users/roland/code/fedservice/entities"
cd $root/flask_rp/uwsgi_setup/automatic || exit 1
nohup uwsgi --ini uwsgi_automatic.ini &
cd $root/flask_rp/uwsgi_setup/explicit || exit 1
nohup uwsgi --ini uwsgi_explicit.ini &
cd $root/flask_op/uwsgi_setup || exit 1
nohup uwsgi --ini uwsgi.ini &
cd $root/flask_op/uwsgi_setup || exit 1
nohup uwsgi --ini uwsgi.ini &
cd $root || exit 1
nginx -p /usr/local/etc/nginx -c complete_fedserv.conf
