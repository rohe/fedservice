#!/usr/bin/env bash
kill -9 `cat /var/log/uwsgi/flask_rp_automatic.pid`
kill -9 `cat /var/log/uwsgi/flask_rp_explicit.pid`
kill -9 `cat /var/log/uwsgi/flask_sigserv.pid`
kill -9 `cat /var/log/uwsgi/flask_op.pid`
