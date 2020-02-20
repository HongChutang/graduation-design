#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os, re, time, base64, hashlib, logging


from transwarp.web import get, post, ctx, view, interceptor, seeother, notfound

from apis import api, Page, APIError, APIValueError, APIPermissionError, APIResourceNotFoundError
from models import User, Record, Payload, Normal
from config import configs
import sys

sys.path.append('../')
import system.core as DS

_COOKIE_NAME = 'sqlinjectiondssession'
_COOKIE_KEY = configs.session.secret


def _get_page_index():
    page_index = 1
    try:
        page_index = int(ctx.request.get('page', '1'))
    except ValueError:
        pass
    return page_index


def make_signed_cookie(id, password, max_age):
    # build cookie string by: id-expires-md5
    expires = str(int(time.time() + (max_age or 86400)))
    L = [id, expires, hashlib.md5('%s-%s-%s-%s' % (id, password, expires, _COOKIE_KEY)).hexdigest()]
    return '-'.join(L)


def parse_signed_cookie(cookie_str):
    try:
        L = cookie_str.split('-')
        if len(L) != 3:
            return None
        id, expires, md5 = L
        if int(expires) < time.time():
            return None
        user = User.get(id)
        if user is None:
            return None
        if md5 != hashlib.md5('%s-%s-%s-%s' % (id, user.password, expires, _COOKIE_KEY)).hexdigest():
            return None
        return user
    except:
        return None


def check_user():
    user = ctx.request.user
    if user:
        return
    raise APIPermissionError('No permission.')


@interceptor('/')
def user_interceptor(next):
    logging.info('try to bind user from session cookie...')
    user = None
    cookie = ctx.request.cookies.get(_COOKIE_NAME)
    if cookie:
        logging.info('parse session cookie...')
        user = parse_signed_cookie(cookie)
        if user:
            logging.info('bind user <%s> to session...' % user.email)
    ctx.request.user = user
    return next()


@interceptor('/manage/')
def manage_interceptor(next):
    user = ctx.request.user
    if user and user.admin:
        return next()
    raise seeother('/signin')


@get('/')
def index():
    user = ctx.request.user
    if user:
        raise seeother('/index')
    raise seeother('/signin')


@view('signin.html')
@get('/signin')
def signin():
    return dict()


@get('/signout')
def signout():
    ctx.response.delete_cookie(_COOKIE_NAME)
    raise seeother('/')


@api
@post('/api/authenticate')
def authenticate():
    i = ctx.request.input(remember='')
    email = i.email.strip().lower()
    password = i.password
    remember = i.remember
    user = User.find_first('where email=?', email)
    if user is None:
        raise APIError('auth:failed', 'email', 'Invalid email.')
    elif user.password != password:
        raise APIError('auth:failed', 'password', 'Invalid password.')
    # make session cookie:
    max_age = 604800 if remember == 'true' else None
    cookie = make_signed_cookie(user.id, user.password, max_age)
    ctx.response.set_cookie(_COOKIE_NAME, cookie, max_age=max_age)
    user.password = '******'
    return user


_RE_EMAIL = re.compile(r'^[a-z0-9\.\-\_]+\@[a-z0-9\-\_]+(\.[a-z0-9\-\_]+){1,4}$')
_RE_MD5 = re.compile(r'^[0-9a-f]{32}$')


@get('/manage/')
def manage_index():
    raise seeother('/manage/comments')


@view('manage_comment_list.html')
@get('/index')
def manage_comments():
    return dict(page_index=_get_page_index(), user=ctx.request.user)


@api
@post('/api/confirm_attack/:record_id')
def api_confirm_attack(record_id):
    check_user()
    record = Record.get(record_id)
    if record is None:
        raise APIResourceNotFoundError('Record')

    payload = Payload(content=record.content)
    payload.insert()
    record.delete()
    return dict(id=record_id)


@api
@post('/api/ignore/:record_id')
def api_ignore(record_id):
    check_user()
    record = Record.get(record_id)
    if record is None:
        raise APIResourceNotFoundError('Record')

    normal = Normal(content=record.content)
    normal.insert()
    record.delete()
    return dict(id=record_id)


@api
@get('/api/records')
def api_get_comments():
    total = Record.count_all()
    page = Page(total, _get_page_index())
    records = Record.find_by('order by level desc limit ?,?', page.offset, page.limit)
    return dict(records=records, page=page)


@api
@get('/api/train')
def api_train():
    DS.run()


