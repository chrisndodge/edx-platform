from __future__ import unicode_literals

import six
import base64
import binascii
import logging
from datetime import timedelta

from django.utils import timezone
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist

from .models import (
    PartnerApiGrant, PartnerApiAccessToken, PartnerApiRefreshToken,
    PartnerApiApplication
)

from oauth2_provider.settings import oauth2_settings
from oauth2_provider.oauth2_validators import OAuth2Validator

log = logging.getLogger('partner_api_validator')


class PartnerApiOAuth2Validator(OAuth2Validator):

    def _load_application(self, client_id, request):
        """
        If request.client was not set, load application instance for given client_id and store it
        in request.client
        """

        # we want to be sure that request has the client attribute!
        assert hasattr(request, "client"), "'request' instance has no 'client' attribute"

        Application = PartnerApiApplication()
        try:
            request.client = request.client or PartnerApiApplication.objects.get(client_id=client_id)
            return request.client
        except PartnerApiApplication.DoesNotExist:
            log.debug("Failed body authentication: Application %s does not exist" % client_id)
            return None

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        """
        Ensure the redirect_uri is listed in the Application instance redirect_uris field
        """
        grant = PartnerApiGrant.objects.get(code=code, application=client)
        return grant.redirect_uri_allowed(redirect_uri)

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        Remove the temporary grant used to swap the authorization token
        """
        grant = PartnerApiGrant.objects.get(code=code, application=request.client)
        grant.delete()

    def validate_bearer_token(self, token, scopes, request):
        """
        When users try to access resources, check that provided token is valid
        """
        if not token:
            return False

        try:
            access_token = PartnerApiAccessToken.objects.select_related("application", "user").get(
                token=token)
            if access_token.is_valid(scopes):
                request.client = access_token.application
                request.user = access_token.user
                request.scopes = scopes

                # this is needed by django rest framework
                request.access_token = access_token
                return True
            return False
        except PartnerApiAccessToken.DoesNotExist:
            return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        try:
            grant = PartnerApiGrant.objects.get(code=code, application=client)
            if not grant.is_expired():
                request.scopes = grant.scope.split(' ')
                request.user = grant.user
                return True
            return False

        except PartnerApiGrant.DoesNotExist:
            return False

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        expires = timezone.now() + timedelta(
            seconds=oauth2_settings.AUTHORIZATION_CODE_EXPIRE_SECONDS)
        g = PartnerApiGrant(application=request.client, user=request.user, code=code['code'],
                  expires=expires, redirect_uri=request.redirect_uri,
                  scope=' '.join(request.scopes))
        g.save()

    def save_bearer_token(self, token, request, *args, **kwargs):
        """
        Save access and refresh token, If refresh token is issued, remove old refresh tokens as
        in rfc:`6`
        """
        if request.refresh_token:
            # remove used refresh token
            try:
                PartnerApiRefreshToken.objects.get(token=request.refresh_token).revoke()
            except RefreshToken.DoesNotExist:
                assert()  # TODO though being here would be very strange, at least log the error

        expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        if request.grant_type == 'client_credentials':
            request.user = None

        access_token = PartnerApiAccessToken(
            user=request.user,
            scope=token['scope'],
            expires=expires,
            token=token['access_token'],
            application=request.client)
        access_token.save()

        if 'refresh_token' in token:
            refresh_token = PartnerApiRefreshToken(
                user=request.user,
                token=token['refresh_token'],
                application=request.client,
                access_token=access_token
            )
            refresh_token.save()

        # TODO check out a more reliable way to communicate expire time to oauthlib
        token['expires_in'] = oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS

    def revoke_token(self, token, token_type_hint, request, *args, **kwargs):
        """
        Revoke an access or refresh token.

        :param token: The token string.
        :param token_type_hint: access_token or refresh_token.
        :param request: The HTTP Request (oauthlib.common.Request)
        """
        if token_type_hint not in ['access_token', 'refresh_token']:
            token_type_hint = None

        token_types = {
            'access_token': PartnerApiAccessToken,
            'refresh_token': PartnerApiRefreshToken,
        }

        token_type = token_types.get(token_type_hint, AccessToken)
        try:
            token_type.objects.get(token=token).revoke()
        except ObjectDoesNotExist:
            for other_type in [_t for _t in token_types.values() if _t != token_type]:
                # slightly inefficient on Python2, but the queryset contains only one instance
                list(map(lambda t: t.revoke(), other_type.objects.filter(token=token)))

    def validate_user(self, username, password, client, request, *args, **kwargs):
        """
        Authenticate users, but allow inactive users (with u.is_active == False)
        to authenticate. See oauth_dispatch/dot_overrides.py
        """
        u = authenticate(username=username, password=password)
        if u is not None:
            request.user = u
            return True
        return False

    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """
        Check refresh_token exists and refers to the right client.
        Also attach User instance to the request object
        """
        try:
            rt = PartnerApiRefreshToken.objects.get(token=refresh_token)
            request.user = rt.user
            request.refresh_token = rt.token
            # Temporary store RefreshToken instance to be reused by get_original_scopes.
            request.refresh_token_instance = rt
            return rt.application == client

        except PartnerApiRefreshToken.DoesNotExist:
            return False
