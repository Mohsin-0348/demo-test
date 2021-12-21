# at w3universal/backend/users/schema.py

import graphene
from django.contrib.auth import get_user_model
from graphene_django import DjangoObjectType

from backend.count_connection import CountConnection
from users.filters import AddressFilters, LogsFilters, UserFilters
from users.models import Address, UnitOfHistory

User = get_user_model()


class UserType(DjangoObjectType):
    """
        User type is defined here with default filtering,
        pagination, edge-node serialization and total-count.
    """
    object_id = graphene.ID()

    class Meta:
        model = User
        filterset_class = UserFilters
        interfaces = (graphene.relay.Node, )
        convert_choices_to_enum = False
        connection_class = CountConnection

    @staticmethod
    def resolve_object_id(self, info, **kwargs):
        return self.id


class LogType(DjangoObjectType):
    """
        Log/ user-action history type is defined here with default filtering,
        pagination, edge-node serialization and total-count.
    """

    class Meta:
        model = UnitOfHistory
        filterset_class = LogsFilters
        interfaces = (graphene.relay.Node, )
        connection_class = CountConnection


class AddressType(DjangoObjectType):
    """
        Address type is defined here with default filtering,
        pagination, edge-node serialization and total-count.
    """
    object_id = graphene.ID()

    class Meta:
        model = Address
        filterset_class = AddressFilters
        interfaces = (graphene.relay.Node, )
        connection_class = CountConnection

    @staticmethod
    def resolve_object_id(self, info, **kwargs):
        return self.id
