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

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), 
                               autoescape = True)

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

# Users entity 

class Users(db.Model):

  username = db.StringProperty(required=True)
  pw_hash = db.StringProperty(required=True)
  email = db.StringProperty()
  created = db.DateTimeProperty(auto_now_add=True)

  @classmethod
  def by_id(cls, user_id):
    return cls.get_by_id(user_id, parent = users_key())

  @classmethod
  def by_name(cls, name):
    user = cls.all().filter('username=', name).get()
    logging.error('Users by_name: %s' % user)
    return user

  @classmethod
  def register(cls, un, pw, email=None):
    pw_hash = make_hash(un, pw)
    return cls(parent = users_key(),
               username = un,
               pw_hash = pw_hash,
               email = email)

  @classmethod
  def login(cls, un, pw):
    user = cls.by_name(un)
    logging.error('login attempt: %s' % user)
    if user and check_hash(un, pw, user.pw_hash): 
      logging.error('success login')
      return user 

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

class Login(Handler):
  
  def get(self):

    self.render('login-form.html')
 
  def post(self):

    username = self.request.get('username')
    password = self.request.get('password')

    user = Users.login(username, password)

    if user:
      self.login(user) 
      self.redirect('/')

    else:
      self.render('login-form.html', error='invalid username or password')

class Logout(Handler):

  def get(self):

    self.logout()
    self.redirect('/')

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
      logging.error('DB put')
      self.login(new_user)
      self.redirect('/example')

class WikiPage(Handler):

  def get(self, page):
    self.write('a wiki page for topic: %s' % page)

class EditPage(Handler):
 
  def get(self, page):
    self.write('a wiki edit page for topic: %s' % page)


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([(r'/login/?', Login),
                               (r'/logout/?', Logout),
                               (r'/signup/?', Signup),
                               (r'/_edit' + PAGE_RE, EditPage),
                               (PAGE_RE, WikiPage)
                               ],
                                debug=True)
