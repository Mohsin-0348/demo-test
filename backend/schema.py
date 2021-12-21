import graphene

import notifications.schema as notification_schema
import users.schema as user_schema


class Query(
    user_schema.Query,
    notification_schema.Query,
    graphene.ObjectType
):
    """
        All queries from all the modules are defined here with specific names.
    """
    pass


class Mutation(
    user_schema.Mutation,
    notification_schema.Mutation,
    graphene.ObjectType
):
    """
        All mutations from all the modules are defined here with specific names.
    """
    pass


schema = graphene.Schema(query=Query, mutation=Mutation)
