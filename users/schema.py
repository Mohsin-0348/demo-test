# at w3gym/backend/users/schema.py
import graphene

from users.mutation import Mutation as userMutation
from users.query import Query as userQuery


class Mutation(userMutation, graphene.ObjectType):
    pass


class Query(userQuery, graphene.ObjectType):
    pass
