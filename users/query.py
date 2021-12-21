# at w3gym/backend/users/schema.py

import graphene
from django.contrib.auth import get_user_model
from graphene_django.filter import DjangoFilterConnectionField
from graphql import GraphQLError

from backend.permissions import is_admin_user, is_authenticated
from users.models import UnitOfHistory
from users.object_types import LogType, UserType

User = get_user_model()


class Query(graphene.ObjectType):
    me = graphene.Field(UserType)
    user = graphene.Field(UserType, object_id=graphene.ID())
    users = DjangoFilterConnectionField(UserType)
    logs = DjangoFilterConnectionField(LogType)
    log = graphene.Field(LogType, object_id=graphene.ID())

    @is_authenticated
    def resolve_me(self, info) -> object:
        user = info.context.user
        if user.is_anonymous:
            raise GraphQLError(
                message='Your are not logged in',
                extensions={
                    "message": "Your are not logged in",
                    "code": "unauthorised"
                })
        return user

    @is_admin_user
    def resolve_users(self, info, **kwargs) -> object:
        return User.objects.all()

    @is_admin_user
    def resolve_user(self, info, object_id, **kwargs) -> object:
        return User.objects.get(id=object_id)

    @is_admin_user
    def resolve_logs(self, info, **kwargs) -> object:
        return UnitOfHistory.objects.all()

    @is_admin_user
    def resolve_log(self, info, object_id, **kwargs) -> object:
        return UnitOfHistory.objects.get(id=object_id)
