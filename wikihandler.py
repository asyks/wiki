import webapp2
import jinja2
import os 

path = os.path.dirname(__file__)
templates = os.path.join(path, 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates), 
                               autoescape = True)

class Handler(webapp2.RequestHandler):

  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)

  def render_str(self, template, **b):
    template = jinja_env.get_template(template)
    return template.render(**b)
  
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

class Login(Handler):
  
  def get(self):
    self.render('/login-form.html')

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
