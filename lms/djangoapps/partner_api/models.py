from __future__ import unicode_literals

from datetime import timedelta

from django.db import transaction
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible
from django.core.exceptions import ImproperlyConfigured

from oauth2_provider import models as dot_models
from oauth2_provider.settings import oauth2_settings


class PartnerApiApplication(dot_models.Application):
    """
    Subclass the Django OAuth Tookit Application class.
    We just want to give it a unique name to avoid
    naming confusion between DOT and these models
    """
    class Meta:
        table_name='partner_api_application'


@python_2_unicode_compatible
class PartnerApiGrant(dot_models.Grant):
    class Meta:
        table_name='partner_api_grant'

    application = models.ForeignKey(PartnerApiApplication)


@python_2_unicode_compatible
class PartnerApiAccessToken(dot_models.AccessToken):
    class Meta:
        table_name='partner_api_accesstoken'

    application = models.ForeignKey(PartnerApiApplication)


@python_2_unicode_compatible
class PartnerApiRefreshToken(dot_models.RefreshToken):
    class Meta:
        table_name='partner_api_refreshtoken'

    application = models.ForeignKey(PartnerApiApplication)


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
