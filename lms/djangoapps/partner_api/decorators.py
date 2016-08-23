from functools import wraps
from oauth2_provider.decorators import protected_resource
from oauth2_provider.oauth2_backends import OAuthLibCore
from oauthlib.oauth2 import Server
from django.http import HttpResponseForbidden

from .validators import PartnerApiOAuth2Validator


def partner_api_protected_resource(scopes=None, validator_cls=PartnerApiOAuth2Validator, server_cls=Server):
    _scopes = scopes or []

    def decorator(view_func):
        @wraps(view_func)
        def _validate(request, *args, **kwargs):
            validator = validator_cls()
            core = OAuthLibCore(server_cls(validator))
            valid, oauthlib_req = core.verify_request(request, scopes=_scopes)
            if valid:
                request.user = oauthlib_req.user
                return view_func(request, *args, **kwargs)
            return HttpResponseForbidden()
        return _validate
    return decorator
