import markdown2

from google.appengine.ext import db
import utils
import logging

class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.EmailProperty()
    is_admin = db.BooleanProperty(default=False)

def create_user(username, email, password):
    '''Register user and return user object'''
    password_hash = utils.make_hash(password)
    new_user = User(username=username, 
                    password=password_hash,
                    email=email)
    new_user.is_admin = False
    try:
        new_user.put()
    except:
        return None
    new_user.user_id = new_user.key().id()
    return new_user
    

def get_user(username, password):
    '''If user exists and return user object, otherwise return None'''
    query = db.GqlQuery("SELECT * FROM User "
                        "WHERE username = '%s'" % username)
    results = list(query)
    if len(results):
        user = results[0]
        if utils.valid_password(password, user.password):
            user.user_id = user.key().id()
            return user
    return None
        
def get_user_by_id(user_id):
    user = User.get_by_id(user_id)
    if user:
        user.user_id = user_id
    return user

class Entry(db.Model):
    title = db.StringProperty(required=True)
    slug = db.StringProperty()
    body = db.TextProperty(required=True)
    body_html = db.TextProperty()
    date = db.DateTimeProperty(auto_now_add=True)
    author = db.IntegerProperty(required=True)
    tags = db.StringListProperty()
    category = db.StringListProperty()

    def put(self, *args, **kwargs):
        self.body_html = markdown2.markdown(self.body)
        super(Entry, self).put(*args, **kwargs)

class Tag(db.Model):
    name = db.StringProperty()

def save_entry(title, body, slug, author, tags=[], entry_id=0):
    if not entry_id:
        new_entry = Entry(title=title,
                          body=body,
                          slug=slug,
                          author=author)
    else:
        new_entry = get_entry_by_id(entry_id) #retrieve entry to edit
        new_entry.title, new_entry.body, new_entry.slug = title, body, slug
    tags_available = set([tag.name for tag in list(db.GqlQuery("SELECT * from Tag"))])
    for tag in tags:
        if tag not in tags_available:
            Tag(name=tag).put()
    new_entry.tags = tags
    new_entry.put()
    entry_id = new_entry.key().id()
    new_entry.entry_id = entry_id
    return new_entry

def get_entry_by_id(entry_id):
    entry = Entry.get_by_id(entry_id)
    entry.entry_id = entry_id
    return entry


def get_entries(latest=True, conditions=[]):
    query_strings = ["SELECT * FROM Entry"]
    if conditions:
        query_strings.append("WHERE %s" % " AND ".join("%s = '%s'" % (k, v) for k, v in conditions))
    if latest:
        query_strings.append("ORDER BY date DESC")
    query_string = " ".join(query_strings);logging.error(query_string)
    db_entries = list(db.GqlQuery(query_string))
    entries = []
    for entry in db_entries:
        entry.entry_id = entry.key().id()
        entries.append(entry)
    return entries

def get_tags():
    db_tags = list(db.GqlQuery("SELECT * FROM Tag"))
    tags = []
    for tag in db_tags:
        tag.tag_id = tag.key().id()
        tags.append(tag)
    return tags
    
