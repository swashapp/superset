import math
import random
from flask_appbuilder.security.sqla.models import User
from sqlalchemy import Column, Integer, ForeignKey, String, Sequence, Table
from sqlalchemy.orm import relationship, backref
from flask_appbuilder import Model

class BIUser(User):
    __tablename__ = 'ab_user'
    nonce = Column(Integer, default=math.floor(random.random() * 1000000))