from google.appengine.ext import db

# Users object

def users_key(group='default'): # key generator for entities of kind Users
  return db.Key.from_path('Users', group)

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

# Wiki object

def wiki_key(group='default'): # key generator for entities of kind Users 
  return db.Key.from_path('Wiki', group)

class Wiki(db.Model):

  title = db.StringProperty(required = True)
  version = db.IntegerProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)

  @classmethod
  def by_title(cls, title):
    wiki = cls.all().filter('title =', title).order('-created').get()
    return wiki

  @classmethod
  def by_title_and_version(cls, title, version):
    wiki = cls.all().filter('title =', title).filter('version =', version).get()
    return wiki

  @classmethod
  def make_entry(cls, title, version, content=' '):
    entry = cls(parent = wiki_key(),
                title = title,
                version = version,  
                content = content)
    return entry


