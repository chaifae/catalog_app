#Art Supplies Catalog App

This app is a web-based catalog that shows items in a variety of categories. It also has a secure user registration and authentication system. User can read items from a database, while registered users can also create, edit, and delete items.


###How to Use

The app is currently being hosted [here](http://ec2-35-164-186-33.us-west-2.compute.amazonaws.com). You don't have to register to view the catalog, simply click on the category you wish to browse. Create an account by logging in with either facebook or google. Once logged in you can also create a new item by clicking on the create item button, and edit and delete items that you have created by clicking on the edit or delete links under the item description.


###General Info

IP: 35.164.186.33

SSH: 2200

URL: http://ec2-35-164-186-33.us-west-2.compute.amazonaws.com


###Configuration Summary

* Utilized development instance from Udacity
* To ssh into instance
  * chmod 600 ~/.ssh/udacity_key.rsa
  * ssh -i ~/.ssh/udacity_key.rsa root@35.164.186.33 -p 2200
* Create user "grader" and gave sudo permission
  * grader password: 12whatever/
* Update all installed packages
* Changed timezone to UTC
* Changed ssh port from 22 to 2200
  * this was found in the file /ect/ssh/sshd_config
* Configured UFD to only allow incoming for ports 2200, 80, and 123
* Installed apache2, python-setuptools libapache2-mod-wsgi, postgresql, postgresql-contrib
* Installed git and cloned project repository
* Configured apache for project support
  * this was done in the file /etc/apache2/sites-available/000-default.conf
* Installed Flask and sqlalchemy
* Installed oatuh2 and oauth2client
* Updated project code to work on the server


###Resources Used

https://discussions.udacity.com/t/project-5-resources/28343

https://discussions.udacity.com/t/p5-how-i-got-through-it/15342

https://discussions.udacity.com/t/markedly-underwhelming-and-potentially-wrong-resource-list-for-p5/8587

https://help.ubuntu.com/community/PostgreSQL

https://www.digitalocean.com/community/tutorials/how-to-install-and-use-postgresql-on-ubuntu-14-04

https://www.digitalocean.com/community/tutorials/how-to-configure-the-apache-web-server-on-an-ubuntu-or-debian-vps

http://flask.pocoo.org/docs/0.10/config/

http://drumcoder.co.uk/blog/2010/nov/12/apache-environment-variables-and-mod_wsgi/

https://www.digitalocean.com/community/tutorials/how-to-set-up-apache-virtual-hosts-on-ubuntu-14-04-lts

http://flask.pocoo.org/docs/0.12/deploying/mod_wsgi/

http://askubuntu.com/questions/410244/a-command-to-list-all-users-and-how-to-add-delete-modify-users

http://docs.sqlalchemy.org/en/latest/orm/session_basics.html

http://flask.pocoo.org/docs/0.12/config/

http://stackoverflow.com/questions/37001004/facebook-login-message-url-blocked-this-redirect-failed-because-the-redirect

http://flask.pocoo.org/docs/0.12/quickstart/

http://bretthutley.com/2015/02/09/python-oauth2-failing-with-x509-error/

