cd automatic || exit 1
nohup uwsgi --ini uwsgi_automatic.ini &
cd ../explicit || exit 1
nohup uwsgi --ini uwsgi_explicit.ini &
cd ..
nginx -p /usr/local/etc/nginx -c fedserv.conf
