from oauth2_provider.decorators import protected_resource

from .validators import PartnerApiOAuth2Validator


def partner_api_protected_resource(scopes=None):
    """
    Decorator to protect views by providing OAuth2 authentication out of the box, optionally with
    scope handling.

        @partner_api_protected_resource()
        def my_view(request):
            # An access token is required to get here...
            # ...
            pass
    """
    _scopes = scopes or []

    def decorator(view_func):
        @wraps(view_func)
        def _validate(request, *args, **kwargs):
            return protected_resource(validator_cls=PartnerApiOAuth2Validator)(request, *args, **kwargs)
        return _validate
    return decorator
