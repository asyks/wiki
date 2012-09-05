import webapp2
import jinja2
import os 
import hashlib
import hmac
import random
import string
import re
import logging

from google.appengine.ext import db
from datetime import datetime

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), 
                               autoescape = True)

# Users entity 

class Users(db.Model):

  username = db.StringProperty(required=True)
  pw_hash = db.StringProperty(required=True)
  email = db.StringProperty()
  created = db.DateTimeProperty(auto_now_add=True)

  @classmethod
  def by_id(cls, user_id):
    return cls.get_by_id(user_id, parent=users_key())

  @classmethod
  def by_name(cls, name):
    u = cls.all()
    u = u.filter('username =', name).get()
    return u

  @classmethod
  def register(cls, un, pw, email=None):
    pw = make_hash(un, pw)
    return cls(parent=users_key(),
               username=un,
               pw_hash=pw,
               email=email)

  @classmethod
  def login(cls, un, pw):
   logging.error('login attempt')
   u = cls.by_name(un)
   if u and check_hash(un, pw, u.pw_hash): 
      logging.error('success login')
      return u 

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
    return cookie_val and check_secure_val(cookie_val) # return a and b: if a then return b 

  def login(self, user): # sets the user_id cookie by calling set_user_cookie()
    self.set_user_cookie(str(user.key().id()))

  def logout(self):
    self.response.delete_cookie('user_id')
    
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    user_id = self.read_user_cookie() 
    self.user = user_id and Users.by_id(int(user_id)) # return a and b: if a then return b  

    if self.request.url.endswith('.json'):
      self.format = 'json'
    else:
      self.format = 'html'

last_page = '/'

class Login(Handler):
  
  def get(self):

    self.render('/login-form.html')
 
  def post(self):

    username = self.request.get('username')
    password = self.request.get('password')

    user = Users.login(username, password)

    if user:
      self.login(user) 
      self.redirect(last_page)

    else:
      self.render('/login-form.html', error='invalid username or password')

class Logout(Handler):

  def get(self):

    self.logout()
    self.redirect(last_page)

class Signup(Handler):

  def get(self):
    self.render('/signup-form.html')

  def post(self):

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

class Wiki(db.Model):

  title = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  last_modified = db.DateTimeProperty(auto_now = True)

  @classmethod
  def by_title(cls, title):
    wiki = cls.all().filter('title =', title).get()
    return wiki

  @classmethod
  def make_entry(cls, title, content=' '):
    entry = cls(title = title,
                content = content)
    return entry

  @classmethod
  def as_dict(cls):
    time_format = '%a %b %y %H:%M:%S %Y' 
    d = {}
    d['wiki_title'] = cls.title
    d['wiki_content'] = cls.content
    d['wiki_created'] = cls.created.strftime(time_format)
    d['wiki_edited'] = cls.last_modified.strftime(time_format)
    
 
class WikiPage(Handler):

  def get(self, page):

    global last_page
    params = {}
    user = self.user
    wiki = Wiki.by_title(page)

    if not wiki:
      if not user:
        self.redirect(last_page)
      elif user:
        new_entry = Wiki.make_entry(page)
        new_entry.put()
        self.redirect('/_edit' + page) 

    elif wiki:
      params['title'] = wiki.title
      params['content'] = wiki.content
      time_format = '%a %b %y %H:%M:%S %Y' 
      last_mod = wiki.last_modified.strftime(time_format)
      last_mod = make_last_edit_str(last_mod)
      params['edited'] = last_mod
      if not user:
        params['history'] = '<a href="%s"> history </a>' % page
        params['auth'] = '<a href="/login"> login </a>|<a href="/signup"> signup </a>'
      elif user:
        params['edit'] = '<a href="/_edit%s">edit</a>' % page
        params ['history'] = '<a href="%s">history</a>' % page
        params['auth'] = user.username + '(<a href="/logout">logout</a>)' 
 
    last_page = page
    self.render('wiki-view.html', **params)
     
class EditPage(Handler):
 
  def get(self, page):
 
    global last_page
    params = {}
    user = self.user
    wiki = Wiki.by_title(str(page))

    if not user:
      self.redirect(last_page)
    elif user:
      params['title'] = wiki.title
      params['content'] = wiki.content
      params['edited'] = wiki.last_modified
      params['edit'] = '<a href="/_edit%s">edit</a>' % page
      params['history'] = '<a href ="%s">history</a>' % page
      params['auth'] = user.username + '(<a href="/logout">logout</a>)' 

    last_page = '/_edit' + page
    self.render('wiki-edit.html', **params)

  def post(self, page):

    user = self.user

    if user:
      new_content = self.request.get('content')
      wiki = Wiki.by_title(page)
      wiki.content = new_content
      wiki.put()
      self.redirect(page)

    else:
      redirect(last_page)

class Front(Handler):
  
  def get(self):

    global last_page

    user = self.user
    params = {}

    if not user:
      params['auth'] = '<a href="/login"> login </a>|<a href="/signup"> signup </a>'
    elif user:
      params['auth'] = user.username + '(<a href="/logout">logout</a>)' 
 
    last_page = '/'
    self.render('wiki-front.html', **params)
 
# Routing Table 

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([(r'/?', Front),
                               (r'/login/?', Login),
                               (r'/logout/?', Logout),
                               (r'/signup/?', Signup),
                               (r'/_edit/?' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               ],
                                debug=True)

# string substitution procedure for wiki pages last edited footer

def make_last_edit_str(time):
  return 'This page was last edited on: %s' % time
 
# sign-up form validation stuff

USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

def user_validate(u):
  if USER_RE.match(u):
    return True

def password_validate(p):
  if PASS_RE.match(p):
    return True

def password_verify(p,v):
  if p == v:
    return True

def email_validate(e): 
  if not e:
    return True
  if e and EMAIL_RE.match(e):
    return True

# cookie setting stuff

secret = 'you will never guess me'

def make_secure_val(val):
  return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
  val = secure_val.split('|')[0]
  if secure_val == make_secure_val(val):
    return val 

# password hashing stuff

def make_salt():
  return ''.join(random.choice(string.letters) for x in range(5))

def make_hash(un, pw, salt=None):
  if not salt:
    salt = make_salt()
  h = hashlib.sha256(un + pw + salt).hexdigest()
  return '%s|%s' % (salt, h)

def check_hash(un, pw, h):
  salt = h.split('|')[0]
  if h == make_hash(un, pw, salt):
    return True

def users_key(group='default'):
  return db.Key.from_path('Users', group)
