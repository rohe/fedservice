#!/usr/bin/env bash
kill -9 `cat /var/log/uwsgi/flask_rp_automatic.pid`
kill -9 `cat /var/log/uwsgi/flask_rp_explicit.pid`
kill -9 `cat /var/log/uwsgi/flask_signing_service.pid`
kill -9 `cat /var/log/uwsgi/flask_op.pid`
