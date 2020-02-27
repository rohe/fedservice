# A test setup of a simple federation

The players:

1) The federation (https://127.0.0.1:6000/eid/swamid.se)
2) Intermediate organisation umu.se (https://127.0.0.1:6000/eid/umu.se) 
3) Intermediate organisation lu.se (https://127.0.0.1:6000/eid/lu.se)
4) OIDC Provider at umu.se (https://127.0.0.1:5000)
5) OIDC Relying Party at lu.se (https://127.0.0.1:4000) using explict
 registration.

1,2 and 3 are all handled by a signing service.

To run the different components you run these commands in this order:

```
$ cd entities/flask_op

$ ./server.py -t -k conf_fed.yaml

$ cd ../flask_rp

$ ./wsgi.py conf_fed.yaml

$ cd ../flask_signing_service 

$ ./server.py conf.yaml
```

When all are up and running you should use your web browser of choice 
and access https://127.0.0.1:4000/ .

From the dropdown list at the bottom-left chose **local** and hit start.
Use diana/krall as username/password.
