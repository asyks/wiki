import webapp2
import jinja2
import os 
import logging

from utility import *
from datamodel import *

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), 
                               autoescape = True)

last_page = '/' # initialize last_page to wiki front

# Main RequestHandler class parent of all other request handlers

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

  params = {}

  def make_logged_out_header(self, page):
    history_link = '/_history' + page 
    self.params['history'] = '<a href ="%s">history</a>' % history_link
    self.params['auth'] = '<a href="/login"> login </a>|<a href="/signup"> signup </a>'

  def make_logged_in_header(self, page, user):
    history_link = '/_history' + page 
    self.params['edit'] = '<a href="/_edit%s">edit</a>' % page
    self.params['history'] = '<a href ="%s">history</a>' % history_link
    self.params['auth'] = user.username + '(<a href="/logout"> logout </a>)' 
    
  def initialize(self, *a, **kw):
    webapp2.RequestHandler.initialize(self, *a, **kw)
    user_id = self.read_user_cookie() 
    self.user = user_id and Users.by_id(int(user_id)) # return a and b: if a then return b  

    if self.request.url.endswith('.json'):
      self.format = 'json'
    else:
      self.format = 'html'

# Login class that handles user login requests

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

# Signup class that handler all signup requests

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

# Wiki articles view handler 

class WikiPage(Handler):

  def get(self, page):

    global last_page
    logging.error(self.params)
    user = self.user
    v = self.request.get('v')
    history_link = '/_history' + page 

    if not v:
      logging.error('render view without version')
      wiki = Wiki.by_title(page)
    elif v:
      logging.error('render view with version')
      wiki = Wiki.by_title_and_version(page, int(v)) 

    if not wiki:
      if not user:
        self.redirect(last_page)
      elif user:
        new_entry = Wiki.make_entry(page,0)
        new_entry.put()
        self.redirect('/_edit' + page) 
    elif wiki:
      self.params['title'] = wiki.title
      self.params['content'] = wiki.content
      last_mod = format_datetime(wiki.created)
      last_mod = make_last_edit_str(last_mod)
      self.params['edited'] = last_mod

    if not user:
      self.make_logged_out_header(page)
    elif user:
      self.make_logged_in_header(page, self.user)
 
    last_page = page
    self.render('wiki-view.html', **self.params)
     
# Wiki articles edit handler

class EditPage(Handler):
 
  def get(self, page):
 
    global last_page
    user = self.user
    v = self.request.get('v')

    if not user:
      self.redirect(last_page)

    if not v:
      wiki = Wiki.by_title(page)
    elif v:
      wiki = Wiki.by_title_and_version(page, int(v))
 
    if not wiki:
      new_entry = Wiki.make_entry(page, 0)
      new_entry.put()
      self.redirect('/_edit' + page) 

    last_mod = format_datetime(wiki.created)
    self.params['title'] = wiki.title
    self.params['content'] = wiki.content
    self.params['edited'] = last_mod 
    self.make_logged_in_header(page, self.user)

    last_page = '/_edit' + page
    self.render('wiki-edit.html', **self.params)

  def post(self, page):

    user = self.user

    if user:
      wiki = Wiki.by_title(page)
      version = wiki.version + 1
      new_content = self.request.get('content')
      new_entry = Wiki.make_entry(page, version, new_content)
      new_entry.put()
      self.redirect(page)

    else:
      redirect(last_page)

# Wiki front page handler 
'''
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
'''

# History page handler 

class History(Handler):

  def get(self, page):

    global last_page
    user = self.user
    page_history = Wiki.all().filter('title =', page).order('-created')
    page_history = list(page_history)
    self.params['page_history'] = page_history
    self.params['title'] = page

    if not user:
      self.make_logged_out_header(page)
    elif user:
      self.make_logged_in_header(page, user)

    last_page = '/history' + page
    self.render('wiki-history.html', **self.params)

# Routing Table 

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)' # regex for handling wiki page requests

app = webapp2.WSGIApplication([#(r'/?', Front),
                               (r'/login/?', Login),
                               (r'/logout/?', Logout),
                               (r'/signup/?', Signup),
                               (r'/_edit/?' + PAGE_RE, EditPage),
                               (r'/_history/?' + PAGE_RE, History),
                               (PAGE_RE, WikiPage)
                               ],
                                debug=True)
