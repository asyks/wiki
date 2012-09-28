
## standard python library imports and app engine library imports
import webapp2
import jinja2
import os 
import logging

## wiki - Mickipebia class/object imports
from utility import *
from datamodel import *
from wikimemcache import *

## app engine library memcache import
from google.appengine.api import memcache

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates)) 
last_page = '/' ## initialize last_page to wiki front


## Main RequestHandler class: parent of all other request handlers

class Handler(webapp2.RequestHandler):

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **b):
    template = jinja_env.get_template(template)
    return template.render(**b)
 
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

  def set_user_cookie(self, val):
    name = 'user_id'
    cookie_val = make_secure_val(val)
    self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
 
  def read_user_cookie(self):
    name = 'user_id'
    cookie_val = self.request.cookies.get(name)
    return cookie_val and check_secure_val(cookie_val) ## return a and b: if a then return b 

  def login(self, user): ## sets the user_id cookie by calling set_user_cookie()
    user_id = str(user.key().id()) 
    self.set_user_cookie(user_id)
    set_user_cache(user.pw_hash, user)

  def logout(self):
    self.response.delete_cookie('user_id')

  def get_wiki_page(self, title, version=None):
    if not version:
      wiki = Wiki.by_title(title)
    elif version:
      wiki = Wiki.by_title_and_version(title, int(version)) 
    logging.error('self.get_wiki_page - wiki: %s' % wiki)
    return wiki
 
  params = {} ## params will contain key value pairs used by jinja2 templates to render html

  def make_logged_out_header(self, page):
    history_link = '/_history' + page 
    self.params['history'] = '<a href ="%s">history</a>' % history_link
    self.params['auth'] = '<a href="/login"> login </a>|<a href="/signup"> signup </a>'

  def make_logged_in_header(self, page, user, version=None):
    history_link = '/_history' + page 
    if version:
      self.params['edit'] = '<a href="/_edit%s?v=%s">edit</a>' % (page, version)
    else:
      self.params['edit'] = '<a href="/_edit%s">edit</a>' % page
    self.params['history'] = '<a href ="%s">history</a>' % history_link
    self.params['auth'] = user.username + '(<a href="/logout"> logout </a>)' 
    
  ## currently I'm hitting the database on every page load becaseu of self.user initialization
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    user_id = self.read_user_cookie() 
    if user_id:
      logging.error('user_id')
      user_id, last_login = get_user_cache(user_id)
      self.user = user_id 
    else:
      logging.error('no user_id')
      self.user = user_id and Users.by_id(int(user_id)) # return a and b: if a then return b  

    if self.request.url.endswith('.json'):
      self.format = 'json'
    else:
      self.format = 'html'


## Class that handles user login requests

class Login(Handler):
  
  def get(self):

    self.render('/login-form.html')
 
  def post(self):

    username = self.request.get('username')
    password = self.request.get('password')

    user = Users.login(username, password)

    if user:
      self.login(user) ## sets user cookie 
      self.redirect(last_page)

    else:
      self.render('/login-form.html', error='invalid username or password')


## Class that handles user login requests

class Logout(Handler):

  def get(self):

    self.logout() ## removes user cookie  
    self.redirect(last_page)


## Handler for all signup requests

class Signup(Handler):

  def get(self):

    self.render('/signup-form.html')

  def post(self): ## user signup process: tests against regex and then if username is in datastore 

    self.username = self.request.get('username')
    self.password = self.request.get('password')
    self.verify = self.request.get('verify')
    self.email = self.request.get('email')
    have_error = False

    params = dict(username = self.username, email = self.email) 
 
    if not user_validate(self.username):
      have_error = True
      params['error_username'] = 'That username is invalid' 
    elif Users.by_name(self.username):
      have_error = True
      params['error_username'] = 'That username is already taken' 

    if not password_validate(self.password):
      have_error=True
      params['error_password'] = 'That password is invalid'
    elif not password_verify(self.password, self.verify):
      have_error = True
      params['error_verify'] = 'Those passwords do not match'

    if not email_validate(self.email):
      have_error = True
      params['error_email'] = 'That is not a valid email'

    if have_error:
      self.render('/signup-form.html', **params) 

    else:
      new_user = Users.register(self.username, self.password, self.email)
      new_user.put()
      self.login(new_user)
      self.redirect(last_page)


## Handler for all view wiki page/article requests 

class WikiPage(Handler):

  def get(self, page):

    global last_page
    user = self.user
    version = self.request.get('v') or None

    wiki, save_time = wiki_cache(page, version) ## gets cached html or hits db if not cached

    if not user and not wiki:
      self.redirect(last_page)
      return
 
    if not wiki:
      wiki = wiki_put_and_cache(page, 0)
      self.redirect('/_edit' + page) 

    elif wiki:
      self.params['title'] = wiki.title
      self.params['content'] = wiki.content
      last_mod = format_datetime(wiki.created)
      last_mod = make_last_edit_str(last_mod)
      self.params['edited'] = last_mod

    if not user: ## page header for logged out visitor
      self.make_logged_out_header(page)
    elif user: ## page header for logged in visitor
      self.make_logged_in_header(page, self.user, wiki.version)
 
    last_page = page
    self.render('wiki-view.html', **self.params)
     

## Handler for wiki page/article edit requests 

class EditPage(Handler):
 
  def get(self, page):
 
    global last_page
    user = self.user
    version = self.request.get('v') or None

    wiki, save_time = wiki_cache(page, version)

    if not user:
      self.redirect(last_page)
      return 

    if not wiki:
      wiki = wiki_put_and_cache(page, 0)

    last_mod = format_datetime(wiki.created)
    self.params['title'] = wiki.title
    self.params['content'] = wiki.content
    self.params['edited'] = last_mod 

    self.make_logged_in_header(page, self.user, wiki.version) ## page header for logged in visitor

    last_page = '/_edit' + page
    self.render('wiki-edit.html', **self.params)

  def post(self, page):

    user = self.user

    if user:
      wiki = Wiki.by_title(page)
      version = wiki.version + 1
      new_content = self.request.get('content')
      new_wiki = wiki_put_and_cache(page, version, new_content)
      self.redirect(page + '?v=%s' % new_wiki.version)

    else:
      redirect(last_page)


## Handler for all history page requests 

class History(Handler):

  def get(self, page):

    global last_page
    user = self.user
    page_history = Wiki.all().filter('title =', page).order('-created')
    page_history = list(page_history)
    self.params['page_history'] = page_history
    self.params['title'] = page

    if not user: ## page header for logged out visitor
      self.make_logged_out_header(page)
    elif user: ## page header for logged out visitor 
      self.make_logged_in_header(page, user)

    last_page = '/_history' + page
    self.render('wiki-history.html', **self.params)


## Mickipebia Routing Table 

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)' # regex for handling wiki page requests

app = webapp2.WSGIApplication([(r'/login/?', Login),
                               (r'/logout/?', Logout),
                               (r'/signup/?', Signup),
                               (r'/_edit/?' + PAGE_RE, EditPage),
                               (r'/_history/?' + PAGE_RE, History),
                               (PAGE_RE, WikiPage)
                               ],
                                debug=True)
