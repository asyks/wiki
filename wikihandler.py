import webapp2
import jinja2
import os 
import hashlib
import hmac
import random
import string
import re

from google.appengine.ext import db

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), 
                               autoescape = True)

# cookie setting stuff

secret = 'you will never guess me'

def make_secure_val(val):
  return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(cookie):
  if cookie:
    val = cookie.split('|')[0]
    if make_secure_val(val) == cookie:
      return val 

# password hashing stuff

def make_salt():
  return ''.join(random.choice(string.letters) for x in range(5))

def make_hash(un, pw, salt=None):
  if salt:
    salt = make_salt
  h = hashlib.sha256(un + pw + salt).hexdigest()
  return '%s|%s' % (h, salt)

def check_hash(un, pw, h):
  salt = h.split('|')[1]
  if make_hash(un, pw, salt) == h:
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
    return cls.get_by_id(user_id, parent=users_key(uid))

  @classmethod
  def by_name(cls, name):
    return cls.all().filter('username=', name).get()

  @classmethod
  def register(cls, un, pw, email=None):
    pw = make_hash(un, pw)
    return cls(parent=users_key(),
               username=un,
               password=pw,
               email=email)

  @classmethod
  def login(cls, un, pw):
    u = cls.by_name(un)
    if u and valid_pw(un, pw, u.pw_hash): 
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
    cookie_val = make_secure_val(val)
    self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_val)
 
  def check_user_cookie(self):
    cookie_val = self.request.cookies.get('user_id')
    return check_secure_val(cookie_val) # originally: cookie_val and... 
    
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    uid = self.check_user_cookie() 
    self.user = Users.by_name(uid) # originally: self.user = uid and...  

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

    self.render('/login-form.html')
    self.set_user_cookie('test') 

class Logout(Handler):

  def get(self):
    self.write('Logout Handler')

class Signup(Handler):

  def get(self):
    self.render('/signup-form.html')

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    verify = self.request.get('verify')
    email = self.request.get('email')
    errors = {}

    if not user_validate(username):
      have_error = True
      errors['error_username'] = 'That username is invalid' 
    else:
      if Users.by_name(username):
        have_error = True
        errors['error_username'] = 'That username is already taken' 

    if not password_validate(password):
      have_error=True
      errors['error_password'] = 'That password is invalid'
    else:
      if not password_verify(password, verify):
        have_error = True
        errors['error_verify'] = 'Those passwords do not match'

    if email:
      if not email_validate(email):
        have_error = True
        errors['error_email'] = 'That is not a valid email'

    if have_error:
      self.render('/signup-form.html', 
                  username=username,
                  email=email
                  )

    else:
      self.render('/signup-form.html')


    # validate form inputs
      # if not valid user --> error_user
    # lookup user in db
      # if invalid or username taken then reload with error
      # if valid and username not taken then: db.put(user), set cookie, and redirect
 
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
