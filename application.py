from models import Base, User, Category, Item

from Flask import Flask, render_template, redirect, url_for, jsonify, \
     request, url_for, abort, g, flash

from SQLAlchemy.ext.declarative import declarative_base

from SQLAlchemy.orm import relationship, sessionmaker

from SQLAlchemy import create_engine

from Flask import session as login_session

import json

import random

import string

from Flask.ext.httpauth import HTTPBasicAuth

from oauth2client.client import flow_from_clientsecrets

from oauth2client.client import FlowExchangeError

import httplib2

from Flask import make_response

import requests


auth = HTTPBasicAuth()

engine = create_engine('sqlite:///itemCatalog.db')

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)

session = DBSession()

app = Flask(__name__)

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    #return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

############3  FACEBOOK ############################33
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s' \
    '&client_secret=%s&fb_exchange_token=%s' \
    % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"

    ''' 

        Due to the formatting for the result from the server token exchange we have to 

        split the token first on commas and select the first index which gives us the key : value 

        for the server access token then we split it on colons to pull out the actual token value

        and replace the remaining quotes with nothing so that it can be used directly in the graph

        api calls

    '''

    token = result.split(',')[0].split(':')[1].replace('"', '')
    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]
    # The token must be stored in the login_session in order to properly logout

    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]
    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("Now logged in as %s" % login_session['username'])
    return output

 

app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s'\
     %(facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

###########################3 gogoole connect ##########3
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' \
        %access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match ' \
        'given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not ' \
        ' match app's."), 401)
        #print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    #print login_session['access_token']
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius:' \
        '150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;">'
    flash("you are now logged in as %s" % login_session['username'])
    #print "done!"
    return output

    #######################3 User Helper Function #######################3

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'], \
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None
#######################3  Disconnect #########################3
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# Disconnect based on provider

@app.route('/disconnect')

def disconnect():

    if 'provider' in login_session:

        if login_session['provider'] == 'google':

            gdisconnect()

            del login_session['gplus_id']

        if login_session['provider'] == 'facebook':

            fbdisconnect()

            del login_session['facebook_id']

        del login_session['username']

        del login_session['email']

        del login_session['picture']

        del login_session['user_id']

        del login_session['provider']

        flash("You have successfully been logged out.")

        return redirect(url_for('catalog'))

    else:

        flash("You were not logged in")

        return redirect(url_for('catalog'))


##########################################

#############################################################################
@app.route('/')
@app.route('/catalog')
def catalog():
	category = session.query(Category).all()
	latitems = session.query(Category.name, Category.id, Item.title, Item.id). \
        join(Item,Category.id == Item.cat_id).distinct(Category.name). \
        group_by(Category.name).order_by(Item.id.desc())
	return render_template('catalog.html', category=category, latitems=latitems)

#JSON Endpoint : From top menu catalogJSON method is called.
@app.route('/catalog/JSON')
def catalogJSON():
    categories = session.query(Category).all()
    serializedcategories=[ ]
    for i in categories:
        new_cat = i.serialize
        items = session.query(Item).filter_by(cat_id=i.id).all()
        serializeItems=[ ]
        for j in items:
            serializeItems.append(j.serialize)
        new_cat['items'] = serializeItems
        serializedcategories.append(new_cat)
    return jsonify(categories=[serializedcategories])

####################################################
#########CATALOG CRUD ##############################
#insert
@auth.login_required
@app.route('/catalog/new',methods=['GET','POST'])
def newCategory():
    if request.method=='POST':
        if request.form['name']:
            #Insert the record
            userid=getUserID(login_session['email'])
            newcat = Category(name = request.form['name'],user_id=userid)
            session.add(newcat)
            session.commit()
            #refresh data to show updated catalog
            category = session.query(Category).all()
            latitems = session \
                .query(Category.name,Category.id,Item.title,Item.id) \
                .join(Item,Category.id == Item.cat_id) \
                .distinct(Category.name).group_by(Category.name)\
                .order_by(Item.id.desc())
            return render_template('catalog.html',category = category, \
                latitems = latitems)
        else:
            #If cancel is pressed on InsertForm show catalog
            category = session.query(Category).all()
            latitems = session \
                .query(Category.name,Category.id,Item.title,Item.id). \
                join(Item,Category.id == Item.cat_id) \
                .distinct(Category.name).group_by(Category.name) \
                .order_by(Item.id.desc())
            return render_template('catalog.html',category = category, \
                latitems = latitems)
    else:
        #GET request : create blank form to enter category
        return render_template('newcategory.html')

####################################################################33
######################## Items
#######3 view items of selected category
@app.route('/catalog/<int:catid>/items',methods=['GET'])
def items(catid):
    #selected category
    category = session.query(Category).filter_by(id = catid).one()
    #All categories
    categories = session.query(Category).all()
    #All items of selected Category
    items = session.query(Item).filter_by(cat_id=catid).all()
    #To show number of items
    catItemsCount = session.query(Item).filter_by(cat_id=catid).count()
    return render_template('items.html', \
        categories = categories, category = category, \
        items = items,catItemsCount = catItemsCount)        

########### JSON of all items under selected category
@app.route('/catalog/<int:catid>/JSONitems')
def itemsJSON(catid):
    cat = session.query(Category).filter_by(id=catid).one()
    items = session.query(Item).filter_by(cat_id=catid).all()
    return jsonify(catName = [i.serialize for i in items])

######## view selected item 
@app.route('/catalog/<int:catid>/<int:itemid>',methods =['GET'])
def viewItem(catid,itemid):
	cat = session.query(Category).filter_by(id=catid).one()
	item = session.query(Item).filter_by(id=itemid).one()
	return render_template('viewitem.html', category=cat,item=item)
######## JSON selected item 
@app.route('/catalog/<int:catid>/<int:itemid>/JSONitem')
def itemJSON(catid,itemid):
    cat = session.query(Category).filter_by(id=catid).one()
    item = session.query(Item).filter_by(id=itemid).one()
    return jsonify(item.serialize)


########### ITEM CRUD #########################3
#Delete Item
@auth.login_required
@app.route('/catalog/<int:catid>/<int:itemid>/delete',methods =['GET','POST'])
def deleteItem(catid,itemid):
    #All categories
    categories = session.query(Category).all()
    #selected category
    cat = session.query(Category).filter_by(id=catid).one()
    #selected item
    item = session.query(Item).filter_by(id=itemid).one()
    if item.user_id == login_session['user_id']:
        if request.method =='POST':
            #confirmation received to delete
            session.delete(item)
            session.commit()
            #get refresh data to show items of selected category
            items = session.query(Item).filter_by(cat_id = catid).all()
            catItemsCount = session.query(Item).filter_by(cat_id = catid).count()
            return render_template('items.html', \
                categories=categories, category=cat, \
             items=items, catItemsCount=catItemsCount)
        else:
            #user has cancel the delete confirmation message. Show current data 
            item = session.query(Item).filter_by(id=itemid).one()
            return render_template('deletetem.html', categories=categories, \
                category=cat, item=item)
    else:
        itemname = session.query(Item.title).filter_by(id=itemid).one()
        flash("Sorry !! You can not delete %s ' \
         'as you don't own this item" % itemname) 
        #get refresh data to show items of selected category
        items = session.query(Item).filter_by(cat_id = catid).all()
        catItemsCount = session.query(Item).filter_by(cat_id = catid).count()
        return render_template('items.html', \
             categories=categories, category=cat, \
            items=items, catItemsCount=catItemsCount)


#Update Item
@auth.login_required
@app.route('/catalog/<int:catid>/<int:itemid>/edit',methods =['GET','POST'])
def editItem(catid,itemid):
    #All categories
    categories = session.query(Category).all()
    #Selected category
    cat = session.query(Category).filter_by(id=catid).one()
    #selected item
    item = session.query(Item).filter_by(id=itemid).one()
    if item.user_id == login_session['user_id']:
        if request.method =='POST':
            if request.form['title']:
                item.title = request.form['title']
                item.Description = request.form.get['description']
                session.add(item)
                session.commit()
                #refresh data to show the items screen
                items = session.query(Item).filter_by(cat_id = catid).all()
                catItemsCount = session.query(Item).filter_by(cat_id=catid).count()
                return render_template('items.html', \
                    categories = categories, category=cat, \
                    items=items,catItemsCount=catItemsCount)
            else:
                #user has pressed cancel in edititem screen. Refresh data to show item screen
                items = session.query(Item).filter_by(cat_id=catid).all()
                catItemsCount = session.query(Item).filter_by(cat_id=catid).count()
                return render_template('items.html', \
                    categories=categories, category=cat, \
                    items=items, catItemsCount=catItemsCount)
        else:
            #get Request : Prepare the edit item scrren with item's details
            return render_template('edititem.html', \
                categories=categories, category=cat,item=item)
    else:
        itemname = session.query(Item.title).filter_by(id=itemid).one()
        flash("Sorry !! You can not update %s ' \
         'as you don't own this item" % itemname) 
        #get refresh data to show items of selected category
        items = session.query(Item).filter_by(cat_id = catid).all()
        catItemsCount = session.query(Item).filter_by(cat_id = catid).count()
        return render_template('items.html', \
             categories=categories, category=cat, \
            items=items, catItemsCount=catItemsCount)

#Create
@auth.login_required
@app.route('/catalog/<int:catid>/newItem',methods=['GET','POST'])
def newItem(catid):
    categories = session.query(Category).all()
    cat = session.query(Category).filter_by(id=catid).one()
    userid = getUserID(login_session['email'])
    #print "userid = % s" % userid
    #print "login_session['email' %s " % login_session['email']
    if request.method == 'POST':
        if request.form.get('title'):
            item = Item(title=request.form['title'], \
                Description=request.form['description'], \
                cat_id=cat.id, user_id=userid)
            session.add(item)
            session.commit()
            items = session.query(Item).filter_by(cat_id=catid).all()
            catItemsCount = session.query(Item).filter_by(cat_id=catid).count()
            return render_template('items.html', \
                categories=categories, category=cat, \
                items=items, catItemsCount=catItemsCount)
        else:
            items = session.query(Item).filter_by(cat_id=catid).all()
            catItemsCount = session.query(Item).filter_by(cat_id=catid).count()
            return render_template('items.html', \
                categories=categories, category=cat, \
                items=items, catItemsCount=catItemsCount)
    else:
        return render_template('newItem.html', category=cat)

if __name__ == '__main__':
 	app.secret_key = 'super_secret_key'
 	app.debug = True
 	app.run(host='0.0.0.0', port=5000)
