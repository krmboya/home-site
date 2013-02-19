import os
import logging

import webapp2
import jinja2

import models
import utils

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=False)

class BaseHandler(webapp2.RequestHandler):
    def render_template(self, template_name, ctx={}, include_tags=True):
        if include_tags:
            ctx['tags'] = models.get_tags()
        template = jinja_env.get_template(template_name)
        self.response.out.write(template.render(ctx))

    def set_cookie(self, name='', value='', path='/'):
        try:
            self.response.headers.add_header('Set-Cookie', '%s=%s; Path=%s' % (name, value, path))
        except TypeError:
            raise TypeError('Non-string cookie parameter.')
    
    def set_user(self, user):
        user_id = str(user.user_id)
        session_hash = utils.make_cookie_hash(user_id)
        self.set_cookie('user_id', session_hash, path='/blog')

    def get_user(self):
        session_string = self.request.cookies.get('user_id')
        if session_string:
            if utils.valid_cookie_hash(session_string):
                session_hash, user_id = session_string.split("|")
                user = models.get_user_by_id(int(user_id))
                return user
        return None
        
class MainHandler(BaseHandler):
    def get(self):
        self.render_template('root.html', include_tags=False)

class BlogHandler(BaseHandler):
    def get(self):
        ctx = {}
        user = self.get_user()
        if user:
            ctx['user'] = user
        entries = models.get_entries()
        ctx['entries'] = entries
        self.render_template('posts.html', ctx)

class RegistrationHandler(BaseHandler):
    def get(self):
        self.render_template('register.html')

    def post(self):
        errors = []
        username = self.request.get('username'); logging.error(username)
        email = self.request.get('email'); logging.error(email)
        password = self.request.get('password'); logging.error(password)
        confirm_password = self.request.get('confirm_password'); logging.error(confirm_password)
        if (username and email and password and (password == confirm_password)):
            username = utils.clean_input(username)
            email = utils.clean_input(email)
            user = models.create_user(username, email, password)
            if user:
                self.set_user(user)
                self.redirect('/blog/posts')
            else:
                errors.append('An error occured, please try again.')
        if not username: errors.append('Username is required.')
        if not password: 
            errors.append('Password is required.')
        elif not password == confirm_password:
            errors.append('Passwords do not match.')
        self.render_template('register.html', {'errors': errors})
            
        
class LoginHandler(BaseHandler):
    def get(self):
        redirect = self.request.get('redirect', '')
        self.render_template('login.html', {'redirect' : redirect})

    def post(self):
        errors = []
        username = self.request.get('username');logging.error(username)
        password = self.request.get('password');logging.error(password)
        redirect = self.request.get('redirect');logging.error(redirect)
        if (username and password):
            username = utils.clean_input(username)
            user = models.get_user(username, password)
            if user:
                self.set_user(user)
                self.redirect((str(redirect) or '/blog/posts'))
            errors.append('Login Error: incorrect username or password.')
        if not username: errors.append('Username is required.')
        if not password: errors.append('Password is required.')
        self.render_template('login.html', {'errors': errors, 'redirect': redirect})

class LogoutHandler(BaseHandler):
    def get(self):
        self.set_cookie('user_id', '', path='/blog')
        self.redirect('/blog/posts')

class BlogPostHandler(BaseHandler):
    def get(self):
        if not self.get_user():
            self.redirect('/blog/login?redirect=%s' % self.request.url)
        self.render_template('post_entry.html')
            
    def post(self):
        user = self.get_user()
        if not user:
            self.redirect('/blog/login?redirect=%s' % self.request.url)
        errors = []
        title = self.request.get('title')
        body = self.request.get('body')
        tags = self.request.get('entry_tags')
        slug = self.request.get('slug')
        entry_id = self.request.get('entry_id')
        entry_type = self.request.get('entry_type')
        if (title and body):
            title = utils.clean_input(title)
            # line below commented out to prevent escaping of raw html within markdown
            # body = utils.clean_input(body)
            slug = utils.clean_input(slug)
            if entry_id:
                try: entry_id = int(utils.clean_input(entry_id))
                except TypeError: entry_id = 0
            if tags:
                tags = tags.split(",")
                tags = [utils.clean_input(tag.strip()) for tag in tags]
            entry_type = (entry_type in ['article', 'note', 'log'] and entry_type or '')
            entry = models.save_entry(title=title,
                                      body=body,
                                      slug=slug, 
                                      author=user.user_id, 
                                      tags=tags, 
                                      entry_id=(entry_id or 0),
                                      entry_type=entry_type)
            self.redirect('/blog/entry/view/%d' % entry.entry_id)
        if not title: errors.append('Title is required')
        if not body: errors.append('Body is required.')
        self.render_template('post_entry.html', {'errors': errors,
                                                 'title': title,
                                                 'body': body,
                                                 'entry_tags': tags,
                                                 'slug': slug})

class PermalinkHandler(BaseHandler):
    def get(self, action, entry_id):
        entry = models.get_entry_by_id(int(entry_id))
        if not entry:
            self.error(404)
        else:
            if action == 'view':
                self.render_template('entry.html', {'entry': entry}); 
            elif action == 'edit':
                if not self.get_user():
                    self.redirect("/blog/login?redirect=%s" % self.request.url)
                self.render_template('post_entry.html', 
                                     { 'title': entry.title,
                                       'slug': entry.slug,
                                       'body': entry.body,
                                       'entry_tags': ', '.join(tag for tag in entry.tags),
                                       'entry_id': entry.entry_id })

class TagHandler(BaseHandler):
    def get(self, tag_name):
        tag_name = utils.clean_input(tag_name)
        entries = models.get_entries(equal_conditions=[('tags', tag_name)])
                                     
        ctx = {}
        ctx['entries'] = entries
        self.render_template('posts.html', ctx)
        

app = webapp2.WSGIApplication([(r'/?', MainHandler),
                               (r'/blog/?', BlogHandler),
                               (r'/blog/posts/?', BlogHandler),
                               (r'/blog/register/?', RegistrationHandler),
                               (r'/blog/login/?', LoginHandler),
                               (r'/blog/logout/?', LogoutHandler),
                               (r'/blog/post_entry/?', BlogPostHandler),
                               (r'/blog/tag/([.\-\s\w]+)/?', TagHandler),
                               (r'/blog/entry/(view|edit)/(\d+)/?', PermalinkHandler)],
                              debug=True)
