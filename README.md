# ItemCatalog
Item Catalog python website Final version with Procfile and requirement.txt
Category Web Application :
Introduction:
-------------
The store has items belonging to Sport Categories.
This web application will give ease to choose items available from the intended Category.

The website shows recent items added on Catalog Home screen.

Google+ and facebook login can be used to login this website.
Logged in user can only enter and modify data.

Requeired library and application:
---------------------------------
The website uses Python, Flask and Sqlalchemy
vagrant version 1.9.5
python 3.6
flask 0.9
sqlalchemy 1.0.11
httplib2 0.10.3
requests 2.17.3
oauth2client 4.1.0
flask.ext.httpauth 3.2.3


Project Contents :
-------------------
CATALOG folder contants following files
Python files 
	The main application is : application.py
	The database setup file is :models.py
Database file:
	itemCatalog.db

The Templates subfolder cotains html files
	Home Page : catalog.html
	To add new catalog : newcatalog.html
	
	Items of selected category : items.html
	To view a specific item : viewitem.html
	To add new item : newitem.html
	To edit item : edititem.html
	To delete item :deleteitem.html

	header.html and main.html files are used in all html
	header.html menu bar : Catalog and JSON catalog.
	if user is logged in the name of the user will be displayed in header section

	main.html has login and logout buttons. Login.html has Google+ and Facebook Login buttons.

JSON files :
	Google+ Login api configration file : client_secrets.json
	Facebook login api configration file : fb_client_secrets.json


Installation Guidlines:
----------------------
1. Launch webserver on port 5000
	A. Load Vagrant machine.
		The following documents can help you in setting up Vagrant machine.
		https://www.vagrantup.com/intro/getting-started/project_setup.html
		https://www.sitepoint.com/getting-started-vagrant-windows/
		https://codingnetworker.com/2015/09/use-vagrant-to-run-the-python-examples/
	B. Copy the Catalog.zip and unzip it. Place Catalog folder in vagrant init directory.
	C. Start Vagrant macchine by vagrant up, vagrant ssh and cd /vagrant command
	D. change directory to Catalog
	E. Run python application.py
		Application.py is the main file. The database will be created. The structure of tables are defined in models.py. All related html files are in catalog/template. The css file is in Static folder.

Operating Instructions
-----------------------
1. The database itemCatalog.db will be created automatically.
2. All data entred will be stored here.
Run Application:
-------------------
1. open web browse :like Microsoft Edge and open http:\\localhost:5000\
Please make sure web server is listning on port 5000.

http:\\localhost:5000\ will open the catalog.html
This action will start our website Catalog

3. Home screen has Login button on top.
The left list shows Categories and right list shows the Recent added items in categories.

4. If the user is not logged in he/she can view the different categories and items and also JSON Category.

5. To login in the website press Login button. This action will open another screen with google+ and facebook login buttons. The user can use his/her google+ or facebook account and authenticate it. On successfull login the Catalog page will open again. Now user can add Category and add, edit and delete the items. The website will show the name of logged in user in header and also instead of Login button, now logout button will be displayed.




