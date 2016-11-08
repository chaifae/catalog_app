from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key = True)
	name = Column(String(250), nullable = False)
	email = Column(String(250), nullable = False)
	image = Column(String(250))


class Item(Base):
	__tablename__ = 'store_item'

	id = Column(Integer, primary_key = True)
	name = Column(String(250), nullable = False)
	description = Column(String(250))
	price = Column(String(10))
	category = Column(String(50), nullable = False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialize(self):
		"""Returns object in serialize format."""
		return {
			'id': self.id,
			'name': self.name,
			'description': self.description,
			'price': self.price,
			'category': self.category
		}


engine = create_engine('sqlite:///catalogandusers.db')

Base.metadata.create_all(engine)