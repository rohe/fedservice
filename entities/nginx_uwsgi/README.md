# A test setup of a simple federation using uwsgi and nginx

The players:

1) The federation 
2) Intermediate organisation umu.se  
3) Intermediate organisation lu.se 
4) OIDC Provider at umu.se 
5) OIDC Relying Parties at lu.se (one using explicit and the other automatic 
client registration) 

1,2 and 3 are all handled by a signing service.

When everything is running you will have 4 entities running on different
ports (4000, 4001, 5000 and 6000).

To run the different components you have to modify a couple of 
configuration files. Start by making local copies

```
$ cp setup.sh.example setup.sh
```

edit the root specification in setup.sh to where you have the 
software

Then

```
$ ./setup.sh
```

This should produce a set of local configuration file copies.

You have to go through all of them to make them work in your environment.
There are 3 sets of files.

The uwsgi.ini files. Here you have to change the 'base' specification.

The conf*.yaml files:
flask_op/conf_uwsgi.yaml
flask_rp/conf_fed.yaml
flask_rp/conf_fed_auto.yaml
flask_signing_service/conf.yaml 

In all of these you should only have to change the 'domain' specification.

And lastly the nginx config file (nginx.fed.conf).
Here you have to change the values all the uwsgi_pass parameters.
You probably have to change where the SSL certificates reside.
The http/include value might also have to be changed. 

Now for the start script.

```
$ cp start.sh.example start.sh
```

edit the root specification in start.sh to where you have the 
software

Then

```
$ ./start.sh
```

When all are up and running you should use your web browser of choice 
and access https://{domain}:4000/ .

From the dropdown list at the bottom-left chose **local** and hit start.
Use diana/krall as username/password.
