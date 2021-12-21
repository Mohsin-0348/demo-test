import graphene

from notifications.mutation import Mutation as notificationMutation
from notifications.query import Query as notificationQuery


class Query(notificationQuery, graphene.ObjectType):
    pass


class Mutation(notificationMutation, graphene.ObjectType):
    pass
