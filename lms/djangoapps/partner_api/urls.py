"""
OAuth2 wrapper urls and Partner API support
"""

from django.conf import settings
from django.conf.urls import patterns, url
from django.views.decorators.csrf import csrf_exempt

from . import views


urlpatterns = patterns(
    '',
    # OAuth flows
    url(r'^oauth2/authorize/?$', csrf_exempt(views.PartnerApiAuthorizationView.as_view()), name='authorize'),
    url(r'^oauth2/access_token/?$', csrf_exempt(views.PartnerApiAccessTokenView.as_view()), name='access_token'),
    url(r'^oauth2/revoke_token/?$', csrf_exempt(views.PartnerApiRevokeTokenView.as_view()), name='revoke_token'),

    # Protected APIs
    url(r'^v1/my_info/?$', views.get_my_info)
)

