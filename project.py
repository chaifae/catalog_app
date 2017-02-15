from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash, make_response
from flask import session as login_session
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import random
import string
import httplib2
import json
import requests
from database_setup import Base, Item, User

app = Flask(__name__)
app.secret_key = 'this_is_secret'

CLIENT_ID = json.loads(
    open('/var/www/html/catalog_app/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = 'Catalog Application'

# connect to the database and create database session
engine = create_engine('sqlite:///catalogandusers.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)



@app.route('/')
@app.route('/catalog/')
def catalog():
    # landing page, will show slightly different content depending on if
    # user is logged in
    # start by assuming user not logged in
    loggedin = False
    # if username is in login_session, we can assume a user is logged in
    # and pass that info to the template
    if 'username' in login_session:
        loggedin = True
    return render_template('catalog.html', loggedin=loggedin)


@app.route('/catalog/<string:category>/')
def showCategory(category):
    session = DBSession()
    # landing page for the category selected, displays all items in
    # selected category
    # will show slightly different content depending on if user is
    # logged in
    # start by assuming user not logged in
    loggedin = False
    # grab all the items within the category selected
    items = session.query(Item).filter_by(category=category).all()
    session.close()
    # if username is in login_session, we can assume a user is logged
    # in and pass that info to the template
    if 'username' in login_session:
        loggedin = True
    return render_template('items.html',
                           items=items,
                           category=category,
                           loggedin=loggedin)


@app.route('/catalog/newitem/', methods=['GET', 'POST'])
def newItem():
    session = DBSession()
    try:
        # check if user is logged in, redirect if not
        if 'username' not in login_session:
            return redirect('/login/')
        # user is logged in, continue to new item page
        if request.method == 'POST':
            # grab all the input from the form for the new item
            newItem = Item(name=request.form['name'],
                        description=request.form['description'],
                        price=request.form['price'],
                        category=request.form['category'],
                        user_id=login_session['user_id'])
            session.add(newItem)
            # flash a message to confirm item creation
            flash('New item %s successfully created!' % (newItem.name))
            session.commit()
            # redirect to the category landing page of the newly created item
            return redirect(url_for('showCategory', category=newItem.category))
        else:
            return render_template('newitem.html')
    finally:
        session.close()


@app.route('/catalog/<int:item_id>/edit/', methods=['GET', 'POST'])
def editItem(item_id):
    session = DBSession()
    try:
        # check if user is logged in, redirect if not
        # start by assuming the user is not the authorized creator of the item
        authorized = False
        if 'username' not in login_session:
            return redirect('/login/')
        # user is logged in so we can continue, grab item by id
        editedItem = session.query(Item).filter_by(id=item_id).one()
        # check if user logged in is creator
        # page will display differently if not
        if editedItem.user_id == login_session['user_id']:
            authorized = True
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            if request.form['description']:
                editedItem.description = request.form['description']
            if request.form['price']:
                editedItem.price = request.form['price']
            if request.form['category']:
                editedItem.category = request.form['category']
            session.add(editedItem)
            # flash a message to confirm item edit successful
            flash('%s successfully edited!' % (editedItem.name))
            session.commit()
            session.close()
            # redirect to the category landing page of the edited item
            return redirect(url_for('showCategory', category=editedItem.category))
        else:
            return render_template('edititem.html',
                                item_id=item_id,
                                item=editedItem,
                                authorized=authorized)
    finally:
        session.close()


@app.route('/catalog/<int:item_id>/delete/', methods=['GET', 'POST'])
def deleteItem(item_id):
    session = DBSession()
    try:
        # check if user is logged in, redirect if not
        # start by assuming the user is not the authorized creator
        authorized = False
        if 'username' not in login_session:
            return redirect('/login/')
        # user is logged in, we can continue
        itemToDelete = session.query(Item).filter_by(id=item_id).one()
        # check if user logged in is creator, page will display differently if not
        if itemToDelete.user_id == login_session['user_id']:
            authorized = True
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            # flash a message to confirm item deletion successful
            flash('Item successfully deleted.')
            return redirect(url_for('catalog'))
        else:
            return render_template('deleteitem.html',
                                item=itemToDelete,
                                authorized=authorized)
    finally:
        session.close()


@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # obtain authorization code
    code = request.data
    print "code: " + request.data

    try:
        # upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade to authorization code'), 401)
        response.headers['Conent-Type'] = 'application/json'
        return response

    # check that the access token is valid
    access_token = credentials.access_token
    print access_token
    url = ('''https://www.googleapis.com/oauth2/v1/tokeninfo?
        access_token=%s''' % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # if there was an error in the access token info, abort
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is used for the intended user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            "Token's user id does not match given user id"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify that the access token is valid for this app
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            "Token's client id does not match app's"), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # check to see if user already logged in
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # store the access token in the session for later use
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # get user info
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['username'] = data['name']
    login_session['image'] = data['picture']
    login_session['email'] = data['email']
    login_session['provider'] = 'google'

    # see if user exists, if not then make a new one
    user_id = getUserID(login_session['email'])
    print "user_id: " + str(user_id)
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, %s!</h1>' % login_session['username']
    output += '''<img src="%s" style="width:300px; height: 300px;
    border-radius: 150px; -webkit-border-radius: 150px;
    -moz-border-radius: 150px;">''' % login_session['image']
    flash("you are now logged in as %s" % login_session['username'])
    return output


# revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    if 'access_token' not in login_session:
        response = make_response(json.dumps(
            'Access token is not in session'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = login_session['access_token']
    print 'In gdisconnect, access_token is: %s' % access_token
    print 'Username is: %s' % login_session['username']

    # only disconnect a connected user
    if access_token is None:
        print 'access_token is None'
        response = make_response(json.dumps('Current user not connected'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # execute HTTP GET request to revoke current token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    # for whatever reason, the given token was invalid
    if result['status'] != '200':
        response = make_response(json.dumps(
            'Failed to revoke token for given user'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = request.data
    print 'access token received: %s' % access_token

    # exchange client token for long-lived server-side token
    app_id = json.loads(
        open('/var/www/html/catalog_app/fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(
        open('/var/www/html/catalog_app/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = '''https://graph.facebook.com/oauth/access_token?grant_type=
        fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token
        =%s''' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # use token to get user info from API
    userinfo_url = 'https://graph.facebook.com/v2.4/me'
    # strip expire tag from access token
    token = result.split('&')[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    print data
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']

    # get user picture
    url = '''https://graph.facebook.com/v2.4/me/picture?%s&redirect
        =0&height=200&width=200''' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['image'] = data['data']['url']

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, %s!</h1>' % login_session['username']
    output += '''<img src="%s" style="width:300px; height: 300px;
        border-radius: 150px; -webkit-border-radius: 150px;
        -moz-border-radius: 150px;">''' % login_session['image']
    flash("you are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    if 'access_token' not in login_session:
        response = make_response(json.dumps(
            'Access token not in session'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    facebook_id = login_session['facebook_id']
    # access token must be included to successfully log out
    access_token = login_session['access_token']
    url = '''https://graph.facebook.com/%s/permissions?
        access_token=%s''' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        del login_session['username']
        del login_session['email']
        del login_session['image']
        del login_session['user_id']
        del login_session['provider']
        flash('You have successfully been logged out.')
        return redirect(url_for('catalog'))
    else:
        flash('You were not logged in to begin with!')
        redirect(url_for('catalog'))


# JSON APIs to view item information
@app.route('/catalog/JSON/')
def categoryListJSON():
    session = DBSession()
    # returns list of categories
    categories = session.query(Item.category).distinct()
    session.close()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/catalog/items/JSON/')
def itemsJSON():
    session = DBSession()
    # returns list of all items
    items = session.query(Item).all()
    session.close()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/<string:category>/items/JSON')
def itemsByCategoryJSON(category):
    session = DBSession()
    # returns list of items within the given category
    items = session.query(Item).filter_by(category=category).all()
    session.close()
    return jsonify(items=[i.serialize for i in items])


@app.route('/catalog/items/<int:item_id>/JSON/')
def itemJSON(item_id):
    session = DBSession()
    # returns info for a single item
    item = session.query(Item).filter_by(id=item_id).one()
    session.close()
    return jsonify(item=item.serialize)


def getUserID(email):
    session = DBSession()
    # finds the user's id in the database or returns None
    print "getUserID running..."
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None
    finally:
        session.close()


def getUserInfo(user_id):
    session = DBSession()
    # grabs the rest of the user's info using the user id
    print "getUserInfo running..."
    user = session.query(User).filter_by(id=user_id).one()
    session.close()
    return user


def createUser(login_session):
    session = DBSession()
    # creates a new user using info from login_session
    print "createUser running..."
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   image=login_session['image'])
    # add the new user to the database
    session.add(newUser)
    session.commit()
    # return's the user's id
    user = session.query(User).filter_by(email=login_session['email']).one()
    session.close()
    return user.id


# if __name__ == '__main__':
#     app.debug = True
#     app.run(host='0.0.0.0', port=5000)
