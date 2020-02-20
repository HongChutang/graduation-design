#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Models for user, blog, comment.
'''

import time, uuid

from transwarp.db import next_id
from transwarp.orm import Model, StringField, BooleanField, FloatField, TextField


def next_id():
    return '%015d%s000' % (int(time.time() * 1000), uuid.uuid4().hex)


class User(Model):
    __table__ = 'console_users'

    id = FloatField(primary_key=True, default=next_id, ddl='varchar(50)')
    email = StringField(updatable=False, ddl='varchar(50)')
    password = StringField(ddl='varchar(50)')


class Record(Model):
    __table__ = 'before_confirm_params'

    id = FloatField(primary_key=True, default=next_id, ddl='int(11)')
    content = TextField()


class Payload(Model):
    __table__ = 'payload_params'

    id = FloatField(primary_key=True, default=next_id, ddl='int(11)')
    content = TextField()


class Normal(Model):
    __table__ = 'normal_params_final'

    id = StringField(primary_key=True, default=next_id, ddl='int(11)')
    content = TextField()

# class Blog(Model):
#     __table__ = 'blogs'
#
#     id = StringField(primary_key=True, default=next_id, ddl='varchar(50)')
#     user_id = StringField(updatable=False, ddl='varchar(50)')
#     user_name = StringField(ddl='varchar(50)')
#     user_image = StringField(ddl='varchar(500)')
#     name = StringField(ddl='varchar(50)')
#     summary = StringField(ddl='varchar(200)')
#     content = TextField()
#     created_at = FloatField(updatable=False, default=time.time)
#
# class Comment(Model):
#     __table__ = 'comments'
#
#     id = StringField(primary_key=True, default=next_id, ddl='varchar(50)')
#     blog_id = StringField(updatable=False, ddl='varchar(50)')
#     user_id = StringField(updatable=False, ddl='varchar(50)')
#     user_name = StringField(ddl='varchar(50)')
#     user_image = StringField(ddl='varchar(500)')
#     content = TextField()
#     created_at = FloatField(updatable=False, default=time.time)