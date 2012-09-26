import logging

from utility import *
from datamodel import *
from google.appengine.api import memcache


## All the procedures needed to cache Wiki queries

def get_wiki_page(title, version=None):
  if not version:
    wiki = Wiki.by_title(title)
  elif version:
    wiki = Wiki.by_title_and_version(title, int(version)) 
  return wiki
 
def set_cache(key, wiki):
  save_time = datetime.utcnow() 
  memcache.set(key, (wiki, save_time)) 

def get_cache(key):
  w = memcache.get(key)
  if w:
    wiki, save_time = w
  else:
    wiki, save_time = None, None
  return wiki, save_time 

def wiki_get_and_cache(key, title, version):
  wiki = get_wiki_page(title, version)
  set_cache(key, wiki)
  wiki, save_time = get_cache(key)
  return wiki, save_time

def wiki_put_and_cache(title, version, content):
  key = db.Key.from_path('Wiki', title+str(version)) 
  wiki = Wiki.make_entry(title, version, content)
  wiki.put()
  set_cache(str(key), wiki)
  return wiki

def wiki_cache(title, version, update=False):
  key = db.Key.from_path('Wiki', title+str(version)) 
  logging.error(key)
  wiki, save_time = get_cache(str(key))
  logging.error(wiki)
  if update == True or wiki == None: 
    wiki, save_time = wiki_get_and_cache(str(key), title, version)
  return wiki, save_time 
