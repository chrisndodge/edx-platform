from __future__ import unicode_literals

from datetime import timedelta
from django.utils.translation import ugettext_lazy as _
from django.db import models, transaction
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth.models import User

from oauth2_provider.generators import generate_client_secret, generate_client_id
from oauth2_provider import models as dot_models
from oauth2_provider.settings import oauth2_settings
from oauth2_provider.validators import validate_uris
from oauth2_provider.compat import urlparse, parse_qsl

class PartnerApiApplication(models.Model):
    """
    Subclass the Django OAuth Tookit Application class.
    We just want to give it a unique name to avoid
    naming confusion between DOT and these models
    """
    class Meta:
        db_table='partner_api_application'

    CLIENT_CONFIDENTIAL = 'confidential'
    CLIENT_PUBLIC = 'public'
    CLIENT_TYPES = (
        (CLIENT_CONFIDENTIAL, _('Confidential')),
        (CLIENT_PUBLIC, _('Public')),
    )

    GRANT_AUTHORIZATION_CODE = 'authorization-code'
    GRANT_IMPLICIT = 'implicit'
    GRANT_PASSWORD = 'password'
    GRANT_CLIENT_CREDENTIALS = 'client-credentials'
    GRANT_TYPES = (
        (GRANT_AUTHORIZATION_CODE, _('Authorization code')),
        (GRANT_IMPLICIT, _('Implicit')),
        (GRANT_PASSWORD, _('Resource owner password-based')),
        (GRANT_CLIENT_CREDENTIALS, _('Client credentials')),
    )

    client_id = models.CharField(max_length=100, unique=True,
                                 default=generate_client_id, db_index=True)
    user = models.ForeignKey(User, related_name="%(app_label)s_%(class)s",
                             null=True, blank=True)

    help_text = _("Allowed URIs list, space separated")
    redirect_uris = models.TextField(help_text=help_text,
                                     validators=[validate_uris], blank=True)
    client_type = models.CharField(max_length=32, choices=CLIENT_TYPES)
    authorization_grant_type = models.CharField(max_length=32,
                                                choices=GRANT_TYPES)
    client_secret = models.CharField(max_length=255, blank=True,
                                     default=generate_client_secret, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    skip_authorization = models.BooleanField(default=False)

    @property
    def default_redirect_uri(self):
        """
        Returns the default redirect_uri extracting the first item from
        the :attr:`redirect_uris` string
        """
        if self.redirect_uris:
            return self.redirect_uris.split().pop(0)

        assert False, "If you are using implicit, authorization_code" \
                      "or all-in-one grant_type, you must define " \
                      "redirect_uris field in your Application model"

    def redirect_uri_allowed(self, uri):
        """
        Checks if given url is one of the items in :attr:`redirect_uris` string
        :param uri: Url to check
        """
        for allowed_uri in self.redirect_uris.split():
            parsed_allowed_uri = urlparse(allowed_uri)
            parsed_uri = urlparse(uri)

            if (parsed_allowed_uri.scheme == parsed_uri.scheme and
                    parsed_allowed_uri.netloc == parsed_uri.netloc and
                    parsed_allowed_uri.path == parsed_uri.path):

                aqs_set = set(parse_qsl(parsed_allowed_uri.query))
                uqs_set = set(parse_qsl(parsed_uri.query))

                if aqs_set.issubset(uqs_set):
                    return True

        return False

    def clean(self):
        from django.core.exceptions import ValidationError
        if not self.redirect_uris \
            and self.authorization_grant_type \
            in (PartnerApiApplication.GRANT_AUTHORIZATION_CODE,
                PartnerApiApplication.GRANT_IMPLICIT):
            error = _('Redirect_uris could not be empty with {0} grant_type')
            raise ValidationError(error.format(self.authorization_grant_type))

    def __str__(self):
        return self.name or self.client_id


@python_2_unicode_compatible
class PartnerApiGrant(models.Model):
    class Meta:
        db_table='partner_api_grant'

    user = models.ForeignKey(User)
    code = models.CharField(max_length=255, db_index=True)  # code comes from oauthlib
    application = models.ForeignKey(PartnerApiApplication)
    expires = models.DateTimeField()
    redirect_uri = models.CharField(max_length=255)
    scope = models.TextField(blank=True)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def redirect_uri_allowed(self, uri):
        return uri == self.redirect_uri

    def __str__(self):
        return self.code


@python_2_unicode_compatible
class PartnerApiAccessToken(models.Model):
    class Meta:
        db_table='partner_api_accesstoken'

    user = models.ForeignKey(User, blank=True, null=True)
    token = models.CharField(max_length=255, db_index=True)
    application = models.ForeignKey(PartnerApiApplication)
    expires = models.DateTimeField()
    scope = models.TextField(blank=True)

    def is_valid(self, scopes=None):
        """
        Checks if the access token is valid.
        :param scopes: An iterable containing the scopes to check or None
        """
        return not self.is_expired() and self.allow_scopes(scopes)

    def is_expired(self):
        """
        Check token expiration with timezone awareness
        """
        if not self.expires:
            return True

        return timezone.now() >= self.expires

    def allow_scopes(self, scopes):
        """
        Check if the token allows the provided scopes
        :param scopes: An iterable containing the scopes to check
        """
        if not scopes:
            return True

        provided_scopes = set(self.scope.split())
        resource_scopes = set(scopes)

        return resource_scopes.issubset(provided_scopes)

    def revoke(self):
        """
        Convenience method to uniform tokens' interface, for now
        simply remove this token from the database in order to revoke it.
        """
        self.delete()

    @property
    def scopes(self):
        """
        Returns a dictionary of allowed scope names (as keys) with their descriptions (as values)
        """
        return {name: desc for name, desc in oauth2_settings.SCOPES.items() if name in self.scope.split()}

    def __str__(self):
        return self.token


@python_2_unicode_compatible
class PartnerApiRefreshToken(models.Model):
    class Meta:
        db_table='partner_api_refreshtoken'

    user = models.ForeignKey(User)
    token = models.CharField(max_length=255, db_index=True)
    application = models.ForeignKey(PartnerApiApplication)
    access_token = models.OneToOneField(PartnerApiAccessToken,
                                        related_name='refresh_token')

    def revoke(self):
        """
        Delete this refresh token along with related access token
        """
        PartnerApiAccessToken.objects.get(id=self.access_token.id).revoke()
        self.delete()

    def __str__(self):
        return self.token


def clear_expired():
    now = timezone.now()
    refresh_expire_at = None

    REFRESH_TOKEN_EXPIRE_SECONDS = oauth2_settings.REFRESH_TOKEN_EXPIRE_SECONDS
    if REFRESH_TOKEN_EXPIRE_SECONDS:
        if not isinstance(REFRESH_TOKEN_EXPIRE_SECONDS, timedelta):
            try:
                REFRESH_TOKEN_EXPIRE_SECONDS = timedelta(seconds=REFRESH_TOKEN_EXPIRE_SECONDS)
            except TypeError:
                e = "REFRESH_TOKEN_EXPIRE_SECONDS must be either a timedelta or seconds"
                raise ImproperlyConfigured(e)
        refresh_expire_at = now - REFRESH_TOKEN_EXPIRE_SECONDS

    with transaction.atomic():
        if refresh_expire_at:
            PartnerApiRefreshToken.objects.filter(access_token__expires__lt=refresh_expire_at).delete()
        PartnerApiAccessToken.objects.filter(refresh_token__isnull=True, expires__lt=now).delete()
        PartnerApiGrant.objects.filter(expires__lt=now).delete()
