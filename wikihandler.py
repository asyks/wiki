import webapp2
import jinja2
import os 
import hashlib
import hmac
import random
import string

from google.appengine.ext import db

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), 
                               autoescape = True)

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
  password = db.StringProperty(required=True)
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
    # needs to check password and return username on match
    u = cls.by_name(name)
    # if u and valid_pw(...): return u
    pass
    

class Handler(webapp2.RequestHandler):

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **b):
    template = jinja_env.get_template(template)
    return template.render(**b)
  
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
# the following lines are not relevant to this file and have been commented out
#    uid = self.read_secure_cookie('user_id')
#    self.user = uid and User.by_id(int(uid))

    if self.request.url.endswith('.json'):
      self.format = 'json'
    else:
      self.format = 'html'

class Login(Handler):
  
  def get(self):
    self.render('/login-form.html')
    # create get secure cookie procedure and set secure cookie procedure

class Logout(Handler):

  def get(self):
    self.write('Logout Handler')

class Signup(Handler):

  def get(self):
    self.render('/signup-form.html')

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
