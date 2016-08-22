from django.contrib import admin

from .models import PartnerApiGrant, PartnerApiAccessToken, PartnerApiRefreshToken, PartnerApiApplication


class RawIDAdmin(admin.ModelAdmin):
    raw_id_fields = ('user',)

admin.site.register(PartnerApiApplication, RawIDAdmin)
admin.site.register(PartnerApiGrant, RawIDAdmin)
admin.site.register(PartnerApiAccessToken, RawIDAdmin)
admin.site.register(PartnerApiRefreshToken, RawIDAdmin)
