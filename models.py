from sqlalchemy import Column,ForeignKey,Integer,String

from sqlalchemy.ext.declarative import declarative_base

from sqlalchemy.orm import relationship, sessionmaker

from sqlalchemy import create_engine

from passlib.apps import custom_app_context as pwd_context

import random, string

from itsdangerous import(TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)



Base = declarative_base()

secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))


class Category(Base):
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(40),index=True)
    user_id=Column(Integer,ForeignKey('user.id'))
    user = relationship('User')
    @property
    def serialize(self):
        return {
        'id' : self.id,
        'name' : self.name
        }

class Item(Base):
    __tablename__ = 'item'    
    id = Column(Integer,primary_key=True)
    title = Column(String(50),index = True)
    Description = Column(String(2500), index = True)
    cat_id = Column(Integer,ForeignKey('category.id'))
    category = relationship('Category')
    user_id=Column(Integer,ForeignKey('user.id'))
    user = relationship('User')
    @property
    def serialize(self):
        return {
        'id' : self.id,
        'title' : self.title,
        'Description' : self.Description,
        'cat_id' : self.cat_id
        }

class User(Base):

    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)

    name = Column(String(30), index = True)

    password_hash = Column(String(64))

    email = Column(String, index=True)

    picture = Column(String)

    @property
    def serialize(self):
        return {
        'id': self.id,
        'name' : self.name,
        'email' : self.email,
        'picture' : self.picture,
        }

    def hash_password(self, password):

        self.password_hash = pwd_context.encrypt(password)



    def verify_password(self, password):

        return pwd_context.verify(password, self.password_hash)



    def generate_auth_token(self, expiration=600):

    	s = Serializer(secret_key, expires_in = expiration)

    	return s.dumps({'id': self.id })



    @staticmethod

    def verify_auth_token(token):

    	s = Serializer(secret_key)

    	try:

    		data = s.loads(token)

    	except SignatureExpired:

    		#Valid Token, but expired

    		return None

    	except BadSignature:

    		#Invalid Token

    		return None

    	user_id = data['id']

    	return user_id





engine = create_engine('sqlite:///itemCatalog.db')

 



Base.metadata.create_all(engine)