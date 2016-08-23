from oauth2_provider.views import base as dot_base_views
from oauth2_provider.exceptions import OAuthToolkitError
from oauth2_provider.settings import oauth2_settings

from django.views.generic import View
from django.http import JsonResponse

from .validators import PartnerApiOAuth2Validator
from .models import PartnerApiApplication
from .decorators import partner_api_protected_resource


class PartnerApiAuthorizationView(dot_base_views.AuthorizationView):
    validator_class = PartnerApiOAuth2Validator

    def get(self, request, *args, **kwargs):
        """
        Unfortunately, we have to define this whole method as an override
        to django-oauth-toolkit's view JUST BECAUSE we need to
        change one line (which looks up the Application). Otherwise this
        is an exact cut/paste from DOT library
        """
        try:
            scopes, credentials = self.validate_authorization_request(request)
            kwargs['scopes_descriptions'] = [oauth2_settings.SCOPES[scope] for scope in scopes]
            kwargs['scopes'] = scopes
            # at this point we know an Application instance with such client_id exists in the database
            # NOTE: THIS IS THE LINE WE NEEDED TO CHANGE FROM DOT IMPLEMENTATION
            application = PartnerApiApplication.objects.get(client_id=credentials['client_id'])  # TODO: cache it!
            kwargs['application'] = application
            kwargs.update(credentials)
            self.oauth2_data = kwargs
            # following two loc are here only because of https://code.djangoproject.com/ticket/17795
            form = self.get_form(self.get_form_class())
            kwargs['form'] = form

            # Check to see if the user has already granted access and return
            # a successful response depending on 'approval_prompt' url parameter
            require_approval = request.GET.get('approval_prompt', oauth2_settings.REQUEST_APPROVAL_PROMPT)

            # If skip_authorization field is True, skip the authorization screen even
            # if this is the first use of the application and there was no previous authorization.
            # This is useful for in-house applications-> assume an in-house applications
            # are already approved.
            if application.skip_authorization:
                uri, headers, body, status = self.create_authorization_response(
                    request=self.request, scopes=" ".join(scopes),
                    credentials=credentials, allow=True)
                return HttpResponseUriRedirect(uri)

            elif require_approval == 'auto':
                tokens = request.user.accesstoken_set.filter(application=kwargs['application'],
                                                             expires__gt=timezone.now()).all()
                # check past authorizations regarded the same scopes as the current one
                for token in tokens:
                    if token.allow_scopes(scopes):
                        uri, headers, body, status = self.create_authorization_response(
                            request=self.request, scopes=" ".join(scopes),
                            credentials=credentials, allow=True)
                        return HttpResponseUriRedirect(uri)

            return self.render_to_response(self.get_context_data(**kwargs))

        except OAuthToolkitError as error:
            return self.error_response(error)


class PartnerApiAccessTokenView(dot_base_views.TokenView):
    validator_class = PartnerApiOAuth2Validator


class PartnerApiRevokeTokenView(dot_base_views.RevokeTokenView):
    validator_class = PartnerApiOAuth2Validator


@partner_api_protected_resource(scopes=['read'])
def get_my_info(request):
    return JsonResponse({
        'user_id': request.user.id,
        'username': request.user.username
    })
