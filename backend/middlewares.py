
from backend.authentication import Authentication


class W3AuthMiddleware(object):

    def resolve(self, next, root, info, **kwargs):
        """
            initialise user to info-context.
        """
        info.context.user = self.authorize_user(info)
        return next(root, info, **kwargs)

    @staticmethod
    def authorize_user(info):
        """
            Authorize user by info-context and return.
        """
        auth = Authentication(info.context)
        return auth.authenticate()
