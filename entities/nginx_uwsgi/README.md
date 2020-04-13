# A test setup of a simple federation using uwsgi and nginx

To install it all first create a virtual environment,
then download fedservice from github and install it in the 
virtual environment. You will have to install flask and oidcop from pip.

```
$ git clone https://github.com/rohe/fedservice.git
$ pip install flask
$ pip install oidcop
$ pip install oidcrp
$ cd fedservice
$ python setup.py install 
```

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
$ cd entities/nginx_uwsgi
$ cp setup.sh.example setup.sh
```

edit the root specification in setup.sh to where you have the 
software. Then

```
$ ./setup.sh
```

This should produce a set of local configuration file copies.

You have to go through all of them to make them work in your environment.
There are 3 sets of files.

The uwsgi.ini files. There are 4 of them:

* flask_op/uwsgi_setup/uwsgi.ini 
* flask_rp/uwsgi_setup/automatic/uwsgi.ini 
* flask_rp/uwsgi_setup/explicit/uwsgi.ini 
* flask_signing_service/uwsgi_setup/uwsgi.ini 

In all of them you have to at least change the 'base' specification.

The conf*.yaml files:

* flask_op/conf_uwsgi.yaml
* flask_rp/conf_fed.yaml
* flask_rp/conf_fed_auto.yaml
* flask_signing_service/conf.yaml 

In all of these you should only have to change the 'domain' specification.

And lastly the nginx config file (federation.conf).
Here you have to change the values all the uwsgi_pass parameters.
You probably have to change where the SSL certificates reside.
The http/include value might also have to be changed. 
And finally you have to copy the configuration file to where ever the 
nginx configuration files resides on your machine.

Before going further you make sure that the uid you are going to run the 
whole thing as has write permission to all the log and pid files that will
be used.

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
