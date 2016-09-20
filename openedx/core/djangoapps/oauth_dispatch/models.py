"""
Specialized models for oauth_dispatch djangoapp
"""

from django.db import models

from oauth2_provider.settings import oauth2_settings


class RestrictedApplication(models.Model):
    """
    This model lists which django-oauth-toolkit Applications are considered 'restricted'
    and thus have a limited ability to use various APIs.

    A restricted Application will only get expired token/JWT payloads
    so that they cannot be used to call into APIs.
    """

    application = models.ForeignKey(oauth2_settings.APPLICATION_MODEL, null=False)

    def __unicode__(self):
        return u"<RestrictedApplication '{name}'>".format(
            name=self.application.name
        )
